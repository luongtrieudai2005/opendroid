"""MobSF (Mobile Security Framework) integration for automated APK analysis.

Calls MobSF REST API (Docker) for comprehensive static analysis:
  - OWASP MASVS compliance
  - Malware SDK detection
  - Manifest/Native/Network analysis
  - Code analysis rules
"""

import json
import logging
import subprocess
import time
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.workflow import tool_meta

logger = logging.getLogger(__name__)

_MobSF_URL = "http://127.0.0.1:8000"
_MobSF_API_KEY: str | None = None


def _api_request(method: str, path: str, data: dict | None = None,
                 files: dict | None = None, timeout: int = 300) -> dict | None:
    """Make a request to MobSF REST API using curl.exe subprocess."""
    url = f"{_MobSF_URL}{path}"
    headers = ["-H", "Content-Type: application/json"]

    if method == "GET":
        cmd = ["curl.exe", "-s", "--max-time", str(timeout), url] + headers
    elif method == "POST" and data:
        tmp = Path(Path(__file__).parent.parent / "workspace" / "_mobsf_payload.json")
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(data), encoding="utf-8")
        cmd = ["curl.exe", "-s", "--max-time", str(timeout), "-X", "POST", url,
               "-H", "Content-Type: application/json", "-d", f"@{tmp}"]
    elif method == "POST" and files:
        cmd = ["curl.exe", "-s", "--max-time", str(timeout), "-X", "POST", url]
        for k, v in files.items():
            cmd.extend(["-F", f"{k}=@{v}"])
    else:
        return None

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
        if result.stdout.strip():
            return json.loads(result.stdout)
        logger.warning("MobSF empty response from %s", url)
        return None
    except json.JSONDecodeError as e:
        logger.warning("MobSF JSON error from %s: %s", url, e)
        return None
    except subprocess.TimeoutExpired:
        logger.warning("MobSF timeout from %s (%ds)", url, timeout)
        return None
    except FileNotFoundError:
        logger.warning("curl.exe not found — MobSF unavailable")
        return None


def check_mobsf_available() -> dict:
    """Check if MobSF server is running and responsive."""
    try:
        result = subprocess.run(
            ["curl.exe", "-s", "--max-time", "3", f"{_MobSF_URL}/api/v1/version"],
            capture_output=True, text=True, timeout=5,
        )
        if result.stdout.strip():
            data = json.loads(result.stdout)
            return {"available": True, "version": data.get("version", "?"),
                    "api": data.get("api", "?"), "url": _MobSF_URL}
        return {"available": False, "version": "?", "error": "no response"}
    except Exception as e:
        return {"available": False, "version": "?", "error": str(e)}


def _ensure_mobsf() -> bool:
    """Verify MobSF is reachable, log warning if not."""
    status = check_mobsf_available()
    if not status["available"]:
        logger.warning("MobSF not available at %s — start with: docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest", _MobSF_URL)
    return status["available"]


# ------------------------------------------------------------------
# M1: Static Analysis via MobSF
# ------------------------------------------------------------------

@tool_meta(
    name="mobsf_upload",
    description="Upload APK to MobSF for static analysis, return scan hash",
    params={
        "apk_path": "Path to APK file on Windows",
    },
    outputs=["scan_hash", "file_name", "result"],
)
def mobsf_upload(apk_path: str = "", **kwargs) -> dict:
    """Upload APK to MobSF and trigger static analysis.

    Returns the scan hash needed to retrieve results.

    Args:
        apk_path: Path to APK file

    Returns:
        Dict with scan_hash, file_name, result.
    """
    apk = apk_path or kwargs.get("apk_path", "")
    if not _ensure_mobsf():
        return {"error": "MobSF not available", "result": {}}

    if not Path(apk).exists():
        return {"error": f"APK not found: {apk}", "result": {}}

    try:
        result = subprocess.run(
            ["curl.exe", "-s", "--max-time", "300", "-X", "POST",
             f"{_MobSF_URL}/api/v1/upload",
             "-F", f"file=@{apk}"],
            capture_output=True, text=True, timeout=310,
        )
        if not result.stdout.strip():
            return {"error": "empty response", "result": {}}
        data = json.loads(result.stdout)
        scan_hash = data.get("hash", "")
        file_name = data.get("file_name", "")
        logger.info("MobSF upload OK: %s (hash=%s)", file_name, scan_hash)
        return {"scan_hash": scan_hash, "file_name": file_name,
                "result": data}
    except Exception as e:
        logger.warning("MobSF upload failed: %s", e)
        return {"error": str(e), "result": {}}


@tool_meta(
    name="mobsf_scan",
    description="Trigger MobSF static analysis on uploaded APK",
    params={
        "scan_hash": "Hash returned by mobsf_upload",
        "wait": "Wait for scan to complete (default: true)",
    },
    outputs=["scan_results", "result"],
)
def mobsf_scan(scan_hash: str = "", wait: bool = True, **kwargs) -> dict:
    """Trigger and wait for MobSF static analysis results.

    Args:
        scan_hash: Hash from mobsf_upload
        wait: If True, poll until scan completes

    Returns:
        Dict with full MobSF scan results.
    """
    h = scan_hash or kwargs.get("scan_hash", "")
    if not h or not _ensure_mobsf():
        return {"error": "invalid hash or MobSF unavailable", "result": {}}

    # Trigger scan
    try:
        result = subprocess.run(
            ["curl.exe", "-s", "--max-time", "60", "-X", "POST",
             f"{_MobSF_URL}/api/v1/scan",
             "-H", "Content-Type: application/json",
             "-d", json.dumps({"hash": h, "scan_type": "apk", "re_scan": 1})],
            capture_output=True, text=True, timeout=70,
        )
        if not result.stdout.strip():
            return {"error": "scan trigger empty response", "result": {}}
        data = json.loads(result.stdout)
    except Exception as e:
        logger.warning("MobSF scan trigger failed: %s", e)
        return {"error": str(e), "result": {}}

    if not wait:
        return {"scan_results": data, "result": data}

    # Poll for completion
    max_wait = 300
    polled = 0
    while polled < max_wait:
        try:
            r = subprocess.run(
                ["curl.exe", "-s", "--max-time", "15",
                 f"{_MobSF_URL}/api/v1/scorecard?hash={h}"],
                capture_output=True, text=True, timeout=20,
            )
            if r.stdout.strip():
                score = json.loads(r.stdout)
                if score.get("scan_status", "") == "completed":
                    logger.info("MobSF scan completed for hash=%s", h)
                    break
        except Exception:
            pass
        time.sleep(5)
        polled += 5

    # Fetch full report
    try:
        r = subprocess.run(
            ["curl.exe", "-s", "--max-time", "30",
             f"{_MobSF_URL}/api/v1/report_json?hash={h}"],
            capture_output=True, text=True, timeout=40,
        )
        if r.stdout.strip():
            report = json.loads(r.stdout)
        else:
            report = data
    except Exception:
        report = data

    return {"scan_results": report, "result": report}


@tool_meta(
    name="mobsf_analyze",
    description="Full MobSF pipeline: upload + scan + return structured findings",
    params={
        "apk_path": "Path to APK file",
        "target_id": "Storage target ID for saving findings",
    },
    outputs=["findings", "severity_counts", "result"],
)
def mobsf_analyze(apk_path: str = "", target_id: int = 0, **kwargs) -> dict:
    """Full MobSF analysis pipeline: upload → scan → parse findings.

    Args:
        apk_path: Path to APK file
        target_id: Target ID in storage (for saving findings)

    Returns:
        Dict with findings, severity_counts, result.
    """
    apk = apk_path or kwargs.get("apk_path", "")
    tid = target_id or kwargs.get("target_id", 0)

    if not _ensure_mobsf():
        return {"error": "MobSF not available", "findings": [],
                "severity_counts": {}, "result": {}}

    # Step 1: Upload
    upload = mobsf_upload(apk_path=apk)
    if "error" in upload:
        return {"error": upload["error"], "findings": [],
                "severity_counts": {}, "result": upload}
    scan_hash = upload.get("scan_hash", "")

    # Step 2: Scan
    scan = mobsf_scan(scan_hash=scan_hash, wait=True)
    report = scan.get("scan_results", {})

    # Step 3: Parse findings
    findings = _parse_mobsf_findings(report)

    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = f.get("severity", "info").lower()
        if s in sev:
            sev[s] += 1

    # Save to storage if target_id provided
    storage = kwargs.get("_storage")
    if storage and tid:
        run_id = kwargs.get("_run_id")
        storage.add_findings_bulk(tid, findings, run_id=run_id)

    return {
        "findings": findings,
        "severity_counts": sev,
        "total": len(findings),
        "result": report,
    }


def _parse_mobsf_findings(report: dict) -> list[dict]:
    """Convert MobSF report dict into uniform findings list."""
    findings: list[dict] = []

    # Permission analysis
    for perm in report.get("permissions", []):
        if perm.get("status", "") == "dangerous":
            findings.append({
                "type": "dangerous_permission",
                "severity": "medium" if perm.get("name") != "INTERNET" else "info",
                "title": f"Dangerous Permission: {perm.get('name', '')}",
                "description": perm.get("description", ""),
                "evidence": perm.get("name", ""),
                "source": "mobsf",
            })

    # Manifest analysis
    manifest = report.get("manifest_analysis", {}) if isinstance(report.get("manifest_analysis"), dict) else {}
    if manifest.get("debuggable"):
        findings.append({
            "type": "debuggable_app",
            "severity": "high",
            "title": "App is debuggable",
            "description": "android:debuggable=true in production build",
            "evidence": "AndroidManifest.xml",
            "source": "mobsf",
        })
    if manifest.get("allow_backup"):
        findings.append({
            "type": "allow_backup",
            "severity": "medium",
            "title": "App allows ADB backup",
            "description": "android:allowBackup=true",
            "evidence": "AndroidManifest.xml",
            "source": "mobsf",
        })

    # Code analysis
    code_analysis = report.get("code_analysis", {})
    if isinstance(code_analysis, dict):
        for rule_id, rule_data in code_analysis.items():
            if isinstance(rule_data, list):
                for item in rule_data:
                    if isinstance(item, dict):
                        files = item.get("files", [])
                        if files:
                            sev_map = {"high": "high", "warning": "medium", "info": "low"}
                            findings.append({
                                "type": f"code_{rule_id}",
                                "severity": sev_map.get(item.get("level", "").lower(), "medium"),
                                "title": item.get("title", rule_id),
                                "description": item.get("description", ""),
                                "evidence": "; ".join(str(f) for f in files[:5]),
                                "source": "mobsf",
                            })

    # Malware analysis
    malware = report.get("malware_analysis", {})
    if isinstance(malware, dict):
        for key in ("network", "dynamic", "static"):
            items = malware.get(f"{key}_analysis", [])
            for item in items if isinstance(items, list) else []:
                if isinstance(item, dict):
                    findings.append({
                        "type": f"malware_{key}",
                        "severity": "high",
                        "title": item.get("title", f"Malware: {key}"),
                        "description": item.get("detail", ""),
                        "evidence": item.get("file", ""),
                        "source": "mobsf",
                    })

    # Trackers
    for tracker in report.get("trackers", []):
        if isinstance(tracker, dict):
            findings.append({
                "type": "tracker_detected",
                "severity": "info",
                "title": f"Tracker: {tracker.get('name', '')}",
                "description": f"Category: {tracker.get('category', '')}",
                "evidence": tracker.get("url", ""),
                "source": "mobsf",
            })

    # CVEs
    for cve_item in report.get("cves", []):
        if isinstance(cve_item, dict):
            findings.append({
                "type": "cve_dependency",
                "severity": cve_item.get("severity", "high"),
                "title": f"CVE: {cve_item.get('id', '')} - {cve_item.get('library', '')}",
                "description": cve_item.get("description", ""),
                "evidence": f"Version: {cve_item.get('version', '')}",
                "source": "mobsf",
            })

    return findings


# ------------------------------------------------------------------
# M5 (helper): APK Diff via MobSF
# ------------------------------------------------------------------

@tool_meta(
    name="mobsf_apk_diff",
    description="Compare two APK versions via MobSF for new endpoints, removed security checks",
    params={
        "apk_old": "Path to older APK",
        "apk_new": "Path to newer APK",
    },
    outputs=["diff", "new_endpoints", "removed_security", "result"],
)
def mobsf_apk_diff(apk_old: str = "", apk_new: str = "", **kwargs) -> dict:
    """Compare two APK versions using MobSF analysis outputs.

    Args:
        apk_old: Path to older version APK
        apk_new: Path to newer version APK

    Returns:
        Dict with diff details.
    """
    old = apk_old or kwargs.get("apk_old", "")
    new = apk_new or kwargs.get("apk_new", "")

    if not _ensure_mobsf():
        return {"error": "MobSF not available", "diff": {},
                "new_endpoints": [], "removed_security": [], "result": {}}

    old_result = mobsf_analyze(apk_path=old)
    new_result = mobsf_analyze(apk_path=new)

    old_findings = {f.get("type", "") + ":" + f.get("title", "") for f in old_result.get("findings", [])}
    new_findings_set = {f.get("type", "") + ":" + f.get("title", "") for f in new_result.get("findings", [])}

    added = new_findings_set - old_findings
    removed = old_findings - new_findings_set

    new_endpoints = []
    removed_security = []

    for f in new_result.get("findings", []):
        key = f.get("type", "") + ":" + f.get("title", "")
        if key in added and "endpoint" in f.get("type", "").lower():
            new_endpoints.append(f)

    for f in old_result.get("findings", []):
        key = f.get("type", "") + ":" + f.get("title", "")
        if key in removed and any(k in f.get("type", "").lower() for k in ("security", "pinning", "cert")):
            removed_security.append(f)

    return {
        "diff": {"added": len(added), "removed": len(removed)},
        "new_findings": [f for f in new_result.get("findings", [])
                         if f.get("type", "") + ":" + f.get("title", "") in added],
        "removed_findings": [f for f in old_result.get("findings", [])
                             if f.get("type", "") + ":" + f.get("title", "") in removed],
        "new_endpoints": new_endpoints,
        "removed_security": removed_security,
        "result": {"old_scan": old_result, "new_scan": new_result},
    }
