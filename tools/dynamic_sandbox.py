"""Dynamic Analysis Sandbox — tự động dump runtime data từ Android app.

Kết hợp ADB + Frida + logcat để:
  - Dump SQLite databases
  - Dump SharedPreferences XML
  - Capture logcat logs theo package
  - Liệt kê filesystem của app
  - Chụp screenshot
  - Ghi kết quả vào workspace storage
"""

import json
import logging
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.android_tools import run_adb
from tools.workflow import tool_meta

logger = logging.getLogger(__name__)


@dataclass
class SandboxResult:
    package: str
    databases: list[dict] = field(default_factory=list)
    preferences: list[dict] = field(default_factory=list)
    files: list[dict] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    screenshot: str = ""
    findings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "databases": self.databases,
            "preferences": self.preferences,
            "files": self.files[:50],
            "logs": self.logs[:50],
            "screenshot": self.screenshot,
            "findings": self.findings,
            "summary": {
                "db_count": len(self.databases),
                "pref_count": len(self.preferences),
                "file_count": len(self.files),
                "log_lines": len(self.logs),
                "finding_count": len(self.findings),
            },
        }


# ------------------------------------------------------------------
# Core dump functions
# ------------------------------------------------------------------

def _adb_shell(cmd: str, timeout: int = 15) -> str:
    """Run adb shell command and return stdout."""
    try:
        result = run_adb(["shell", cmd], timeout=timeout)
        return result.stdout
    except Exception as e:
        logger.warning("ADB shell error: %s", e)
        return ""


def _adb_pull(remote: str, local: str, timeout: int = 15) -> bool:
    """Pull file from device, return True on success."""
    try:
        result = run_adb(["pull", remote, local], timeout=timeout)
        return result.returncode == 0
    except Exception:
        return False


def _find_package_base(package: str) -> str | None:
    """Find the /data/data/<package> or /data/app/<package> base dir."""
    # Try /data/data/<package>
    out = _adb_shell(f"ls /data/data/{package} 2>/dev/null && echo OK")
    if "OK" in out:
        return f"/data/data/{package}"

    # Fallback: search for package base path
    out = _adb_shell(f"pm path {package} 2>/dev/null")
    for line in out.split("\n"):
        if line.startswith("package:"):
            return Path(line[8:]).parent.as_posix()
    return None


# ------------------------------------------------------------------
# M7: Dynamic Analysis Sandbox
# ------------------------------------------------------------------

@tool_meta(
    name="sandbox_dump_databases",
    description="Dump and analyze SQLite databases from app private directory",
    params={
        "package": "Android package name",
        "output_dir": "Local output directory (default: workspace/sandbox)",
    },
    outputs=["databases", "findings", "result"],
)
def sandbox_dump_databases(package: str = "", output_dir: str = "", **kwargs) -> dict:
    """Pull and analyze all SQLite databases from the app's data directory.

    Args:
        package: Android package name
        output_dir: Local directory to save pulled files

    Returns:
        Dict with databases list and security findings.
    """
    pkg = package or kwargs.get("package", "")
    out_dir = output_dir or kwargs.get("output_dir", "workspace/sandbox")

    if not pkg:
        return {"error": "package required", "databases": [], "findings": [], "result": {}}

    output_path = Path(out_dir) / pkg / "databases"
    output_path.mkdir(parents=True, exist_ok=True)

    # Step 1: List database files
    db_dir = f"/data/data/{pkg}/databases"
    list_out = _adb_shell(f"run-as {pkg} ls {db_dir} 2>/dev/null || ls {db_dir} 2>/dev/null || echo EMPTY")

    databases: list[dict] = []
    findings: list[dict] = []

    if "EMPTY" in list_out or "No such file" in list_out:
        return {"databases": [], "findings": [], "info": "No databases directory found",
                "result": {}}

    for line in list_out.split("\n"):
        line = line.strip()
        if not line or line.startswith("ls:") or "Permission" in line:
            continue

        # Try to pull the database
        remote_path = f"{db_dir}/{line}"
        local_path = output_path / line
        pulled = _adb_pull(remote_path, str(local_path), timeout=30)

        if pulled and local_path.exists():
            size = local_path.stat().st_size
            db_info: dict = {"file": line, "size": size, "path": str(local_path)}

            # Try to read tables if sqlite3 available on device
            tables_out = _adb_shell(f"run-as {pkg} sqlite3 {remote_path} \\\".tables\\\" 2>/dev/null || echo NOSQLITE")
            if "NOSQLITE" not in tables_out:
                tables = tables_out.strip().split()
                db_info["tables"] = tables

                # Check for sensitive data in table names
                sensitive_tables = [t for t in tables if any(kw in t.lower()
                    for kw in ["password", "token", "secret", "key", "credential",
                                "session", "auth", "user", "account", "payment",
                                "credit", "wallet", "transaction", "log", "sync"])]
                if sensitive_tables:
                    findings.append({
                        "type": "sensitive_db_tables",
                        "severity": "medium",
                        "title": f"Sensitive table names in {line}",
                        "description": f"Tables found: {', '.join(sensitive_tables)}",
                        "evidence": f"DB: {line}",
                        "source": "sandbox",
                    })

                # Check table row counts
                for tbl in tables[:20]:
                    count_out = _adb_shell(
                        f"run-as {pkg} sqlite3 {remote_path} \\\"SELECT COUNT(*) FROM \\\"{tbl}\\\";\\\" 2>/dev/null || echo ERR"
                    )
                    if "ERR" not in count_out and count_out.strip().isdigit():
                        if int(count_out.strip()) > 0:
                            db_info.setdefault("row_counts", {})[tbl] = int(count_out.strip())

            databases.append(db_info)

    return {
        "databases": databases,
        "findings": findings,
        "count": len(databases),
        "finding_count": len(findings),
        "result": {"databases": databases, "findings": findings},
    }


@tool_meta(
    name="sandbox_dump_preferences",
    description="Dump SharedPreferences XML files from app private directory",
    params={
        "package": "Android package name",
        "output_dir": "Local output directory",
    },
    outputs=["preferences", "findings", "result"],
)
def sandbox_dump_preferences(package: str = "", output_dir: str = "", **kwargs) -> dict:
    """Pull SharedPreferences XML files and scan for sensitive data.

    Args:
        package: Android package name
        output_dir: Local directory to save files

    Returns:
        Dict with preferences list and findings.
    """
    pkg = package or kwargs.get("package", "")
    out_dir = output_dir or kwargs.get("output_dir", "workspace/sandbox")

    if not pkg:
        return {"error": "package required", "preferences": [], "findings": [], "result": {}}

    output_path = Path(out_dir) / pkg / "shared_prefs"
    output_path.mkdir(parents=True, exist_ok=True)

    prefs_dir = f"/data/data/{pkg}/shared_prefs"
    list_out = _adb_shell(f"run-as {pkg} ls {prefs_dir} 2>/dev/null || echo EMPTY")

    preferences: list[dict] = []
    findings: list[dict] = []

    if "EMPTY" in list_out:
        return {"preferences": [], "findings": [], "info": "No shared_prefs directory",
                "result": {}}

    for line in list_out.split("\n"):
        line = line.strip()
        if not line or not line.endswith(".xml") or "Permission" in line:
            continue

        remote_path = f"{prefs_dir}/{line}"
        local_path = output_path / line
        pulled = _adb_pull(remote_path, str(local_path), timeout=15)

        if pulled and local_path.exists():
            try:
                content = local_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                content = ""

            pref_info: dict = {
                "file": line,
                "size": local_path.stat().st_size,
                "path": str(local_path),
                "content_preview": content[:500],
            }
            preferences.append(pref_info)

            # Check for sensitive keys in XML
            sensitive_keys = re.findall(
                r'<string\s+name="([^"]*)"',
                content,
                re.IGNORECASE,
            )
            sensitive_found = [k for k in sensitive_keys if any(
                kw in k.lower() for kw in ["password", "token", "secret", "auth",
                                            "key", "session", "cookie", "credential",
                                            "pin", "otp", "phone", "email"])]
            if sensitive_found:
                findings.append({
                    "type": "sensitive_shared_prefs",
                    "severity": "medium",
                    "title": f"Sensitive keys in SharedPreferences: {line}",
                    "description": f"Keys: {', '.join(sensitive_found[:10])}",
                    "evidence": f"File: {line}",
                    "source": "sandbox",
                })

            # Check for plaintext passwords
            for pw_pattern in [r"(?i)password[^>]*>([^<]+)", r"(?i)token[^>]*>([^<]{8,})"]:
                for m in re.finditer(pw_pattern, content):
                    findings.append({
                        "type": "plaintext_credential",
                        "severity": "high",
                        "title": f"Plaintext credential in SharedPreferences: {line}",
                        "description": f"Value found matching pattern: {pw_pattern}",
                        "evidence": m.group(0)[:100],
                        "source": "sandbox",
                    })

    return {
        "preferences": preferences,
        "findings": findings,
        "count": len(preferences),
        "finding_count": len(findings),
        "result": {"preferences": preferences, "findings": findings},
    }


@tool_meta(
    name="sandbox_dump_logs",
    description="Capture logcat logs filtered by app package",
    params={
        "package": "Android package name",
        "duration": "Capture duration in seconds (default: 30)",
        "max_lines": "Maximum lines to return (default: 200)",
    },
    outputs=["logs", "result"],
)
def sandbox_dump_logs(package: str = "", duration: int = 30,
                      max_lines: int = 200, **kwargs) -> dict:
    """Capture Android logcat output filtered by app package.

    Captures both verbose logs and error-level logs for security analysis.

    Args:
        package: Android package name
        duration: Capture duration in seconds
        max_lines: Maximum lines to return

    Returns:
        Dict with log lines and extracted findings.
    """
    pkg = package or kwargs.get("package", "")
    dur = duration or kwargs.get("duration", 30)
    ml = max_lines or kwargs.get("max_lines", 200)

    if not pkg:
        return {"error": "package required", "logs": [], "result": {}}

    logs: list[str] = []
    findings: list[dict] = []

    try:
        # Clear logcat buffer first
        run_adb(["logcat", "-c"], timeout=5)

        # Wait for new logs
        time.sleep(1)

        # Capture logs
        result = subprocess.run(
            ["adb", "logcat", "-d", "-v", "brief", f"-s", pkg],
            capture_output=True, text=True, timeout=dur + 5,
        )
        lines = result.stdout.strip().split("\n")

        # Also capture error level
        result_e = subprocess.run(
            ["adb", "logcat", "-d", "-v", "brief", "*:E"],
            capture_output=True, text=True, timeout=dur + 5,
        )
        lines_e = result_e.stdout.strip().split("\n")

        combined = lines + lines_e

        for line in combined:
            if pkg.lower() in line.lower() or (not line):
                continue
            logs.append(line[:300])

        logs = logs[:ml]

        # Extract security-relevant patterns
        security_patterns = [
            (r"(?i)(password|passwd|pwd)=?\S+", "Password leak in logcat"),
            (r"(?i)(token|secret|key|auth)=?\w{8,}", "Secret/token leak in logcat"),
            (r"(?i)(error|exception|crash|fatal|ANR)", "App crash/error"),
            (r"(?i)(sqlite|sql|query|select|insert|delete)", "SQL query in logs"),
            (r"(?i)(https?://\S+)", "URL in logs"),
            (r"(?i)(stacktrace|stack trace|at\s+\w+\.\w+)", "Stack trace leak"),
        ]

        for line in logs:
            for pattern, desc in security_patterns:
                if re.search(pattern, line):
                    findings.append({
                        "type": "logcat_leak",
                        "severity": "medium" if "password" in pattern or "token" in pattern else "low",
                        "title": desc,
                        "description": f"Sensitive data in logcat output",
                        "evidence": line[:200],
                        "source": "sandbox",
                    })
                    break

    except subprocess.TimeoutExpired:
        logs.append("[TIMEOUT] logcat capture exceeded duration")
    except FileNotFoundError:
        return {"error": "adb not found", "logs": [], "result": {}}
    except Exception as e:
        logs.append(f"[ERROR] {e}")

    return {
        "logs": logs,
        "findings": findings,
        "count": len(logs),
        "finding_count": len(findings),
        "result": {"logs": logs, "findings": findings},
    }


@tool_meta(
    name="sandbox_dump_filesystem",
    description="List app filesystem recursively for sensitive data exposure",
    params={
        "package": "Android package name",
        "depth": "Recursion depth (default: 3)",
    },
    outputs=["files", "findings", "result"],
)
def sandbox_dump_filesystem(package: str = "", depth: int = 3, **kwargs) -> dict:
    """Recursively list the app's private filesystem.

    Identifies world-readable files, cache data, and sensitive file names.

    Args:
        package: Android package name
        depth: Recursion depth

    Returns:
        Dict with files list and findings.
    """
    pkg = package or kwargs.get("package", "")
    dep = depth or kwargs.get("depth", 3)

    if not pkg:
        return {"error": "package required", "files": [], "findings": [], "result": {}}

    base = f"/data/data/{pkg}"
    files: list[dict] = []
    findings: list[dict] = []
    seen = set()

    dirs_to_check = [""]
    for d in dirs_to_check:
        target = f"{base}/{d}" if d else base
        out = _adb_shell(f"run-as {pkg} ls -la {target} 2>/dev/null || echo PERM_DENIED")

        if "PERM_DENIED" in out or "No such file" in out:
            continue

        for line in out.split("\n"):
            line = line.strip()
            if not line or line.startswith("total") or "Permission" in line:
                continue

            parts = line.split()
            if len(parts) < 8:
                continue

            permissions = parts[0]
            name = parts[-1]
            full_path = f"{target}/{name}" if d else f"{base}/{name}"

            if name in (".", "..") or full_path in seen:
                continue
            seen.add(full_path)

            is_dir = permissions.startswith("d")
            world_readable = "r--" in permissions[-3:] if len(permissions) >= 9 else False

            entry = {
                "path": full_path[len(base):] or "/",
                "permissions": permissions,
                "is_dir": is_dir,
                "world_readable": world_readable,
            }
            files.append(entry)

            if world_readable and not is_dir:
                findings.append({
                    "type": "world_readable_file",
                    "severity": "medium",
                    "title": f"World-readable file: {entry['path']}",
                    "description": f"File permissions {permissions} allow any app to read",
                    "evidence": full_path,
                    "source": "sandbox",
                })

            # Add subdirectories to check (within depth limit)
            if is_dir and name not in ("cache", "code_cache", "lib") and len(dirs_to_check) < dep:
                sub = f"{d}/{name}" if d else name
                dirs_to_check.append(sub)

    return {
        "files": files,
        "findings": findings,
        "count": len(files),
        "finding_count": len(findings),
        "result": {"files": files, "findings": findings},
    }


@tool_meta(
    name="sandbox_full_dump",
    description="Full dynamic sandbox: dump databases + prefs + logs + filesystem in one shot",
    params={
        "package": "Android package name",
        "output_dir": "Local output directory",
        "log_duration": "Log capture duration in seconds (default: 15)",
    },
    outputs=["databases", "preferences", "logs", "files", "findings", "result"],
)
def sandbox_full_dump(package: str = "", output_dir: str = "",
                      log_duration: int = 15, **kwargs) -> dict:
    """Complete dynamic sandbox: one-shot dump of all app runtime data.

    Runs sequentially:
    1. Dump databases
    2. Dump SharedPreferences
    3. Capture logcat logs
    4. List filesystem
    5. Take screenshot

    All results saved to output_dir/<package>/.

    Args:
        package: Android package name
        output_dir: Local output directory
        log_duration: Seconds to capture logs

    Returns:
        Dict with all results and aggregated findings.
    """
    pkg = package or kwargs.get("package", "")
    out_dir = output_dir or kwargs.get("output_dir", "workspace/sandbox")
    log_dur = log_duration or kwargs.get("log_duration", 15)

    if not pkg:
        return {"error": "package required", "result": {}}

    all_findings: list[dict] = []

    # 1. Databases
    db_result = sandbox_dump_databases(package=pkg, output_dir=out_dir)
    dbs = db_result.get("databases", [])
    all_findings.extend(db_result.get("findings", []))

    # 2. Preferences
    pref_result = sandbox_dump_preferences(package=pkg, output_dir=out_dir)
    prefs = pref_result.get("preferences", [])
    all_findings.extend(pref_result.get("findings", []))

    # 3. Logs
    log_result = sandbox_dump_logs(package=pkg, duration=log_dur, max_lines=300)
    logs = log_result.get("logs", [])
    all_findings.extend(log_result.get("findings", []))

    # 4. Filesystem
    fs_result = sandbox_dump_filesystem(package=pkg, depth=3)
    files = fs_result.get("files", [])
    all_findings.extend(fs_result.get("findings", []))

    # 5. Screenshot
    screenshot_path = f"{out_dir}/{pkg}/screenshot.png"
    Path(screenshot_path).parent.mkdir(parents=True, exist_ok=True)
    try:
        from tools.android_tools import capture_screenshot
        capture_screenshot(output_path=screenshot_path)
        screenshot = screenshot_path
    except Exception:
        screenshot = ""

    # Deduplicate findings
    seen_keys = set()
    unique_findings = []
    for f in all_findings:
        key = json.dumps(f, sort_keys=True)
        if key not in seen_keys:
            seen_keys.add(key)
            unique_findings.append(f)

    return {
        "package": pkg,
        "databases": dbs,
        "preferences": prefs,
        "logs": logs,
        "files_count": len(files),
        "files": files[:30],
        "screenshot": screenshot,
        "findings": unique_findings,
        "finding_count": len(unique_findings),
        "summary": {
            "db_count": len(dbs),
            "pref_count": len(prefs),
            "log_lines": len(logs),
            "files_count": len(files),
            "findings": len(unique_findings),
        },
        "result": {
            "findings": unique_findings,
            "databases": dbs,
            "preferences": prefs,
        },
    }


# ------------------------------------------------------------------
# Injected analysis
# ------------------------------------------------------------------

@tool_meta(
    name="sandbox_analyze_sqlite",
    description="Run SQL queries on a pulled SQLite database to find sensitive data",
    params={
        "db_path": "Local path to pulled .db file",
    },
    outputs=["tables", "sensitive_data", "result"],
)
def sandbox_analyze_sqlite(db_path: str = "", **kwargs) -> dict:
    """Analyze a local SQLite database for sensitive content.

    Reads all tables and searches for credentials, tokens, PII.

    Args:
        db_path: Local path to .db file

    Returns:
        Dict with table analysis and sensitive data findings.
    """
    path = db_path or kwargs.get("db_path", "")
    if not path or not Path(path).exists():
        return {"error": "db_path not found", "tables": [], "sensitive_data": [],
                "result": {}}

    try:
        import sqlite3
        conn = sqlite3.connect(path)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        tables_info: list[dict] = []
        sensitive_data: list[dict] = []

        for table in tables:
            cursor.execute(f"PRAGMA table_info('{table}')")
            columns = [row[1] for row in cursor.fetchall()]
            cursor.execute(f"SELECT COUNT(*) FROM '{table}'")
            row_count = cursor.fetchone()[0]

            tbl_info = {"name": table, "columns": columns, "row_count": row_count}
            tables_info.append(tbl_info)

            # Sample rows and check for sensitive column content
            sensitive_cols = [c for c in columns if any(kw in c.lower() for kw in
                ["password", "token", "secret", "key", "auth", "credential",
                 "ssn", "pin", "cvv", "phone", "email", "address",
                 "session", "cookie", "refresh"])]

            if sensitive_cols and row_count > 0:
                cursor.execute(f"SELECT * FROM '{table}' LIMIT 5")
                rows = cursor.fetchall()
                for row in rows:
                    for idx, col in enumerate(columns):
                        if col in sensitive_cols and idx < len(row) and row[idx]:
                            val = str(row[idx])[:100]
                            if val and val not in ("null", "None", "") and len(val) > 3:
                                sensitive_data.append({
                                    "table": table,
                                    "column": col,
                                    "sample": val,
                                })

        conn.close()
        return {
            "tables": tables_info,
            "sensitive_data": sensitive_data[:50],
            "sensitive_count": len(sensitive_data),
            "result": {"tables": tables_info, "sensitive_data": sensitive_data[:50]},
        }

    except Exception as e:
        return {"error": str(e), "tables": [], "sensitive_data": [], "result": {}}
