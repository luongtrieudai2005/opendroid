"""Flutter app pentest tools: detection, reFlutter automation, Blutter bridge, TLS bypass.

Flutter apps differ from native Android:
  - Business logic in libapp.so (ARM64 native), NOT in DEX → jadx useless for Dart code
  - BoringSSL bundled → system CA store ignored, standard SSL unpinning won't work
  - No system proxy → Flutter manages sockets directly

Tools integrated:
  - reFlutter: APK patching + class/function dump (user đã có)
  - Blutter (WSL2): libapp.so analysis → pp.txt, objs.txt, blutter_frida.js
  - NVISO disable-flutter-tls.js: BoringSSL TLS bypass via Frida
"""

import json
import logging
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from tools.http_tools import send_http
from tools.workflow import tool_meta

logger = logging.getLogger(__name__)

_FLUTTER_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "config" / "frida-scripts" / "flutter"


# ------------------------------------------------------------------
# F1: Flutter APK Detection
# ------------------------------------------------------------------

@tool_meta(
    name="flutter_detect_apk",
    description="Detect if APK is a Flutter app and extract engine metadata",
    params={
        "apk_path": "Path to APK file",
    },
    outputs=["is_flutter", "engine_hash", "archs", "obfuscated", "result"],
)
def flutter_detect_apk(apk_path: str = "", **kwargs) -> dict:
    """Check if an APK is built with Flutter and extract metadata.

    Detection signals:
      - lib/ contains libflutter.so
      - lib/ contains libapp.so (Dart AOT compiled code)
      - assets/flutter_assets/ exists

    Args:
        apk_path: Path to APK file

    Returns:
        Dict with is_flutter, engine info, result.
    """
    apk = apk_path or kwargs.get("apk_path", "")

    if not apk or not Path(apk).exists():
        return {"error": "APK not found", "is_flutter": False, "result": {}}

    # Use unzip -l to list APK contents (faster than extracting)
    try:
        result = subprocess.run(
            ["unzip", "-l", apk],
            capture_output=True, text=True, timeout=15,
        )
        listing = result.stdout
    except FileNotFoundError:
        # Fallback: try 7z
        try:
            result = subprocess.run(
                ["7z", "l", apk],
                capture_output=True, text=True, timeout=15,
            )
            listing = result.stdout
        except FileNotFoundError:
            return {"error": "neither unzip nor 7z found", "is_flutter": False, "result": {}}
    except Exception as e:
        return {"error": str(e), "is_flutter": False, "result": {}}

    has_flutter_so = "libflutter.so" in listing
    has_app_so = "libapp.so" in listing
    has_flutter_assets = "flutter_assets" in listing

    is_flutter = has_flutter_so or (has_app_so and has_flutter_assets)

    # Extract architectures
    archs = set()
    for line in listing.split("\n"):
        m = re.search(r"lib/(\w+)/libflutter\.so", line)
        if m:
            archs.add(m.group(1))
        m = re.search(r"lib/(\w+)/libapp\.so", line)
        if m:
            archs.add(m.group(1))

    # Check for obfuscation signal
    obfuscated = False
    libapp_lines = [l for l in listing.split("\n") if "libapp.so" in l]
    if not libapp_lines:
        # No separate libapp.so means code may be in libflutter.so (obfuscated/small apps)
        obfuscated = True

    # Try to get engine version from flutter_assets/version.json
    engine_version = ""
    try:
        if "version.json" in listing or "flutter_assets/version.json" in listing:
            ver_out = subprocess.run(
                ["unzip", "-p", apk, "flutter_assets/version.json"],
                capture_output=True, text=True, timeout=10,
            )
            if ver_out.stdout.strip():
                ver_data = json.loads(ver_out.stdout)
                engine_version = ver_data.get("engine_version", "")
    except Exception:
        pass

    return {
        "is_flutter": is_flutter,
        "engine_version": engine_version,
        "archs": sorted(archs),
        "obfuscated": obfuscated,
        "signals": {
            "has_libflutter_so": has_flutter_so,
            "has_libapp_so": has_app_so,
            "has_flutter_assets": has_flutter_assets,
        },
        "result": {
            "is_flutter": is_flutter,
            "engine_version": engine_version,
            "archs": sorted(archs),
            "obfuscated": obfuscated,
        },
    }


# ------------------------------------------------------------------
# F2: reFlutter Automation
# ------------------------------------------------------------------

@tool_meta(
    name="flutter_extract_lib",
    description="Extract libflutter.so and libapp.so from Flutter APK",
    params={
        "apk_path": "Path to APK file",
        "output_dir": "Output directory",
        "arch": "Target architecture (arm64-v8a, armeabi-v7a, x86_64)",
    },
    outputs=["libflutter_path", "libapp_path", "result"],
)
def flutter_extract_lib(apk_path: str = "", output_dir: str = "",
                        arch: str = "arm64-v8a", **kwargs) -> dict:
    """Extract Flutter native libraries from APK for analysis.

    Args:
        apk_path: Path to APK
        output_dir: Output directory for extracted files
        arch: Target architecture

    Returns:
        Dict with paths to extracted libraries.
    """
    apk = apk_path or kwargs.get("apk_path", "")
    out = output_dir or kwargs.get("output_dir", "workspace/flutter_libs")
    a = arch or kwargs.get("arch", "arm64-v8a")

    if not apk or not Path(apk).exists():
        return {"error": "APK not found", "result": {}}

    output_path = Path(out)
    output_path.mkdir(parents=True, exist_ok=True)

    libs_to_extract = [
        f"lib/{a}/libflutter.so",
        f"lib/{a}/libapp.so",
    ]

    extracted = {}
    for lib in libs_to_extract:
        try:
            result = subprocess.run(
                ["unzip", "-o", apk, lib, "-d", str(output_path)],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                full_path = output_path / lib
                if full_path.exists():
                    key = Path(lib).stem
                    extracted[key] = str(full_path)
                    logger.info("Extracted %s (%d bytes)", lib, full_path.stat().st_size)
        except Exception as e:
            logger.warning("Failed to extract %s: %s", lib, e)

    return {
        "libflutter_path": extracted.get("libflutter", ""),
        "libapp_path": extracted.get("libapp", ""),
        "output_dir": str(output_path),
        "extracted_count": len(extracted),
        "result": extracted,
    }


@tool_meta(
    name="flutter_reflutter_patch",
    description="Patch Flutter APK with reFlutter for traffic interception and class dump",
    params={
        "apk_path": "Path to original APK",
        "proxy_ip": "IP address of Burp Suite proxy",
        "output_path": "Output path for patched APK (default: release.RE.apk)",
    },
    outputs=["patched_apk", "snapshot_hash", "result"],
)
def flutter_reflutter_patch(apk_path: str = "", proxy_ip: str = "192.168.1.100",
                            output_path: str = "", **kwargs) -> dict:
    """Patch a Flutter APK using reFlutter for traffic interception and class dumping.

    reFlutter patches libflutter.so to:
      - Bypass TLS verification (socket.cc patched)
      - Dump Dart classes, functions, fields at runtime (dart.cc modified)

    Args:
        apk_path: Path to original APK
        proxy_ip: Burp Suite proxy IP
        output_path: Output path for patched APK

    Returns:
        Dict with patched APK path, snapshot hash, result.
    """
    apk = apk_path or kwargs.get("apk_path", "")
    ip = proxy_ip or kwargs.get("proxy_ip", "192.168.1.100")
    out = output_path or kwargs.get("output_path", "release.RE.apk")

    if not apk or not Path(apk).exists():
        return {"error": "APK not found", "result": {}}

    # Check if reflutter is installed
    try:
        subprocess.run(["reflutter", "--version"], capture_output=True, text=True, timeout=5)
    except FileNotFoundError:
        return {"error": "reFlutter not found. Install: pip install reflutter",
                "result": {}}

    # Run reFlutter (takes stdin input for proxy IP)
    logger.info("Patching %s with reFlutter (proxy: %s) ...", apk, ip)
    try:
        result = subprocess.run(
            ["reflutter", apk],
            input=f"{ip}\n",
            text=True,
            capture_output=True,
            timeout=120,
        )
        output = result.stdout + result.stderr

        # Extract snapshot hash from output
        snapshot_hash = ""
        m = re.search(r"SnapshotHash:\s*([a-f0-9]+)", output)
        if m:
            snapshot_hash = m.group(1)

        # Find the patched APK
        patched = Path("release.RE.apk")
        if patched.exists():
            patched_path = str(patched.resolve())
        else:
            patched_path = ""

        if "The resulting apk file" in output or patched_path:
            logger.info("reFlutter patched APK: %s (hash: %s)", patched_path, snapshot_hash)
            return {
                "patched_apk": patched_path,
                "snapshot_hash": snapshot_hash,
                "reflutter_output": output[:500],
                "result": {"patched_apk": patched_path, "hash": snapshot_hash},
            }
        else:
            return {"error": "reFlutter did not produce patched APK", "output": output[:500],
                    "result": {}}

    except subprocess.TimeoutExpired:
        return {"error": "reFlutter timed out after 120s", "result": {}}
    except Exception as e:
        return {"error": str(e), "result": {}}


@tool_meta(
    name="flutter_sign_apk",
    description="Sign a patched APK with uber-apk-signer or apksigner",
    params={
        "apk_path": "Path to APK to sign",
    },
    outputs=["signed_path", "result"],
)
def flutter_sign_apk(apk_path: str = "", **kwargs) -> dict:
    """Sign an APK for installation. Tries uber-apk-signer then apksigner.

    Args:
        apk_path: Path to unsigned APK

    Returns:
        Dict with signed path, result.
    """
    apk = apk_path or kwargs.get("apk_path", "")
    if not apk or not Path(apk).exists():
        return {"error": "APK not found", "result": {}}

    # Try uber-apk-signer first
    signers = [
        (["java", "-jar", "uber-apk-signer.jar", "--allowResign", "-a", apk], "uber-apk-signer"),
        (["apksigner", "sign", "--ks", "debug.keystore", "--ks-pass", "pass:android",
          "--ks-key-alias", "androiddebugkey", apk], "apksigner"),
    ]

    for cmd, name in signers:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                logger.info("APK signed with %s: %s", name, apk)
                return {"signed_path": apk, "signer": name, "result": {"path": apk}}
        except FileNotFoundError:
            continue
        except Exception as e:
            logger.warning("%s failed: %s", name, e)

    return {"error": "No signer available. Install uber-apk-signer or Android SDK apksigner",
            "signed_path": apk, "result": {}}


@tool_meta(
    name="flutter_deploy_patched",
    description="Install patched Flutter APK on device and set proxy",
    params={
        "apk_path": "Path to signed patched APK",
        "package": "Android package name",
        "proxy_host": "Proxy host (default 10.0.2.2)",
        "proxy_port": "Proxy port (default 8080)",
    },
    outputs=["installed", "result"],
)
def flutter_deploy_patched(apk_path: str = "", package: str = "",
                           proxy_host: str = "10.0.2.2",
                           proxy_port: int = 8080, **kwargs) -> dict:
    """Deploy patched Flutter APK to device and configure proxy.

    Args:
        apk_path: Path to signed APK
        package: Package name
        proxy_host: Proxy hostname
        proxy_port: Proxy port

    Returns:
        Dict with deployment status.
    """
    apk = apk_path or kwargs.get("apk_path", "")
    pkg = package or kwargs.get("package", "")
    ph = proxy_host or kwargs.get("proxy_host", "10.0.2.2")
    pp = proxy_port or kwargs.get("proxy_port", 8080)

    if not apk or not pkg:
        return {"error": "apk_path and package required", "installed": False, "result": {}}

    from tools.android_tools import run_adb

    steps = {}

    # Step 1: Uninstall existing
    try:
        run_adb(["uninstall", pkg], timeout=15)
        steps["uninstall"] = "ok"
    except Exception as e:
        steps["uninstall"] = str(e)

    # Step 2: Install
    try:
        result = run_adb(["install", "-r", "-d", apk], timeout=120)
        steps["install"] = "ok" if result.returncode == 0 else result.stderr[:200]
    except Exception as e:
        steps["install"] = str(e)

    # Step 3: Set proxy
    try:
        run_adb(["shell", "settings", "put", "global", "http_proxy", f"{ph}:{pp}"])
        steps["proxy"] = f"{ph}:{pp}"
    except Exception as e:
        steps["proxy"] = str(e)

    installed = "ok" in str(steps.get("install", ""))
    return {
        "installed": installed,
        "package": pkg,
        "proxy": f"{ph}:{pp}",
        "steps": steps,
        "result": steps,
    }


@tool_meta(
    name="flutter_pull_dump",
    description="Pull reFlutter dump.dart from device for class/function analysis",
    params={
        "package": "Android package name",
        "output_dir": "Local output directory",
    },
    outputs=["dump_path", "dump_preview", "result"],
)
def flutter_pull_dump(package: str = "", output_dir: str = "", **kwargs) -> dict:
    """Pull the reFlutter dump.dart file from a running device.

    After running the reFlutter-patched app, reFlutter writes dump.dart
    to the app's root directory with classes, functions, and code offsets.

    Args:
        package: Android package name
        output_dir: Local output directory

    Returns:
        Dict with dump file path and preview.
    """
    pkg = package or kwargs.get("package", "")
    out = output_dir or kwargs.get("output_dir", "workspace/flutter_dump")

    if not pkg:
        return {"error": "package required", "result": {}}

    output_path = Path(out)
    output_path.mkdir(parents=True, exist_ok=True)

    from tools.android_tools import run_adb

    # Try multiple possible dump locations
    dump_locations = [
        f"/data/data/{pkg}/dump.dart",
        f"/data/data/{pkg}/app_flutter/dump.dart",
        "/sdcard/dump.dart",
        f"/sdcard/Android/data/{pkg}/dump.dart",
    ]

    for remote in dump_locations:
        try:
            result = run_adb(["shell", f"cat {remote} 2>/dev/null || echo NOT_FOUND"], timeout=15)
            if "NOT_FOUND" not in result.stdout and result.stdout.strip():
                local = output_path / "dump.dart"
                local.write_text(result.stdout, encoding="utf-8")
                preview_lines = result.stdout.strip().split("\n")[:20]
                logger.info("Pulled dump.dart from %s (%d bytes)", remote, local.stat().st_size)
                return {
                    "dump_path": str(local),
                    "source": remote,
                    "size": local.stat().st_size,
                    "dump_preview": "\n".join(preview_lines),
                    "result": {"path": str(local), "preview": "\n".join(preview_lines)},
                }
        except Exception:
            continue

    return {"error": "dump.dart not found on device. Run the patched app first.",
            "result": {}}


@tool_meta(
    name="flutter_parse_dump",
    description="Parse reFlutter dump.dart into structured classes, functions, libraries",
    params={
        "dump_path": "Path to dump.dart file",
    },
    outputs=["libraries", "classes", "functions", "offsets", "result"],
)
def flutter_parse_dump(dump_path: str = "", **kwargs) -> dict:
    """Parse reFlutter dump.dart output into structured data.

    reFlutter dump format:
      Library:'package:app/file.dart' Class: Name extends Object {
        Function 'methodName': (args) => ReturnType {
          Code Offset: _kDartIsolateSnapshotInstructions + 0xHEX
        }
      }

    Args:
        dump_path: Path to dump.dart from reFlutter

    Returns:
        Dict with parsed libraries, classes, functions, offsets.
    """
    path = dump_path or kwargs.get("dump_path", "")
    if not path or not Path(path).exists():
        return {"error": "dump.dart not found", "result": {}}

    text = Path(path).read_text(encoding="utf-8", errors="ignore")

    libraries: list[dict] = []
    current_lib: dict | None = None
    current_class: dict | None = None

    lib_pat = re.compile(r"Library:'([^']*)'")
    class_pat = re.compile(r"Class:\s*(\w+)\s*extends\s*(\w+)")
    func_pat = re.compile(
        r"Function\s+'([^']*)':\s*(?:static\s+)?(factory\.|getter\.|setter\.|)?\s*\(([^)]*)\)\s*(?:=>\s*(\w+))?"
    )
    offset_pat = re.compile(r"Code Offset:\s*_kDartIsolateSnapshotInstructions\s*\+\s*(0x[0-9a-fA-F]+)")

    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue

        # Library
        lm = lib_pat.search(line)
        if lm:
            current_lib = {
                "name": lm.group(1),
                "classes": [],
            }
            libraries.append(current_lib)
            current_class = None
            continue

        # Class
        cm = class_pat.search(line)
        if cm and current_lib is not None:
            current_class = {
                "name": cm.group(1),
                "extends": cm.group(2),
                "functions": [],
            }
            current_lib["classes"].append(current_class)
            continue

        # Function
        fm = func_pat.search(line)
        if fm and current_class is not None:
            func_name = fm.group(1)
            func_type = (fm.group(2) or "").strip()
            func_args = fm.group(3)
            func_return = fm.group(4)
            offset = ""

            # Look ahead for offset on same or next line
            om = offset_pat.search(line)
            if not om:
                om = offset_pat.search(text[text.index(line) + len(line):text.index(line) + len(line) + 100])
            if om:
                offset = om.group(1)

            current_class["functions"].append({
                "name": func_name,
                "type": func_type,
                "args": func_args,
                "return_type": func_return or "void",
                "offset": offset,
            })

    # Aggregate statistics
    all_classes = []
    all_functions = []
    all_offsets = {}
    for lib in libraries:
        for cls in lib.get("classes", []):
            all_classes.append(cls["name"])
            for fn in cls.get("functions", []):
                key = f"{cls['name']}.{fn['name']}"
                all_functions.append(key)
                if fn.get("offset"):
                    all_offsets[key] = fn["offset"]

    # Save to workspace if storage available
    storage = kwargs.get("_storage")
    target_id = kwargs.get("_target_id")
    if storage and target_id:
        findings = []
        # Identify interesting classes
        interesting_keywords = ["api", "http", "client", "service", "repository",
                                "auth", "token", "session", "payment", "wallet",
                                "crypto", "cipher", "key", "secret", "webview",
                                "deep", "link", "intent", "provider", "database"]
        for cls_name in all_classes:
            if any(kw in cls_name.lower() for kw in interesting_keywords):
                findings.append({
                    "type": "flutter_interesting_class",
                    "severity": "info",
                    "title": f"Flutter class: {cls_name}",
                    "description": f"Interesting class from reFlutter dump",
                    "source": "flutter_parse_dump",
                })
        storage.add_findings_bulk(target_id, findings, run_id=kwargs.get("_run_id"))

    return {
        "libraries": libraries,
        "library_count": len(libraries),
        "class_count": len(all_classes),
        "function_count": len(all_functions),
        "classes": all_classes,
        "functions": all_functions,
        "offsets": all_offsets,
        "result": {
            "libraries": libraries[:10],
            "class_count": len(all_classes),
            "function_count": len(all_functions),
        },
    }


# ------------------------------------------------------------------
# F3: Blutter WSL2 Bridge
# ------------------------------------------------------------------

@tool_meta(
    name="flutter_blutter_analyze",
    description="Run Blutter on libapp.so via WSL2 to extract Dart objects and Frida hooks",
    params={
        "lib_dir": "Path to directory containing libflutter.so + libapp.so",
        "output_dir": "Output directory for Blutter results",
    },
    outputs=["pp_path", "frida_js_path", "asm_dir", "result"],
)
def flutter_blutter_analyze(lib_dir: str = "", output_dir: str = "", **kwargs) -> dict:
    """Analyze Flutter app using Blutter via WSL2.

    Blutter parses libapp.so to extract:
      - pp.txt: all Dart objects in object pool (strings, class names, URLs)
      - objs.txt: nested object dump
      - blutter_frida.js: Frida hook template
      - asm/: disassembled functions with symbols

    Args:
        lib_dir: Directory containing libflutter.so + libapp.so (extracted from APK)
        output_dir: Output directory for Blutter results

    Returns:
        Dict with paths to generated files.
    """
    lib = lib_dir or kwargs.get("lib_dir", "")
    out = output_dir or kwargs.get("output_dir", "workspace/blutter_out")

    if not lib or not Path(lib).exists():
        return {"error": "lib directory not found", "result": {}}

    output_path = Path(out).resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    # Convert Windows path to WSL2 path
    def _to_wsl(path: str) -> str:
        p = Path(path).resolve()
        drive = p.drive.lower().rstrip(":")
        rest = str(p.relative_to(p.anchor)).replace("\\", "/")
        return f"/mnt/{drive}/{rest}"

    wsl_lib = _to_wsl(lib)
    wsl_out = _to_wsl(str(output_path))

    # Check if blutter.py exists in WSL2
    check_cmd = "test -f /home/trieudai/go/bin/blutter.py && echo OK || test -f blutter.py && echo OK || echo NOT_FOUND"
    try:
        check = subprocess.run(
            ["wsl.exe", "bash", "-c", check_cmd],
            capture_output=True, text=True, timeout=5,
        )
        if "NOT_FOUND" in check.stdout:
            return {"error": "Blutter not found in WSL2. Clone: git clone https://github.com/worawit/blutter",
                    "result": {}}
    except FileNotFoundError:
        return {"error": "WSL2 not available", "result": {}}

    # Run Blutter via WSL2
    # blutter.py takes lib/ directory and output directory
    cmd = f"cd /home/trieudai/go/bin && python3 blutter.py {wsl_lib} {wsl_out} --rebuild"
    logger.info("Running Blutter via WSL2 (this may take a while to compile Dart VM)...")
    try:
        result = subprocess.run(
            ["wsl.exe", "bash", "-c", cmd],
            capture_output=True, text=True, timeout=600,
        )
        logger.info("Blutter output: %s", result.stdout[-300:])
    except subprocess.TimeoutExpired:
        return {"error": "Blutter timed out after 600s — Dart VM compilation may take long",
                "result": {}}
    except Exception as e:
        return {"error": str(e), "result": {}}

    # Check outputs
    outputs = {}
    for fname in ["pp.txt", "objs.txt", "blutter_frida.js"]:
        fpath = output_path / fname
        if fpath.exists():
            outputs[fname] = str(fpath)
            logger.info("Blutter output: %s (%d bytes)", fname, fpath.stat().st_size)

    asm_dir = output_path / "asm"
    if asm_dir.exists():
        outputs["asm_dir"] = str(asm_dir)
        outputs["asm_count"] = len(list(asm_dir.glob("*.S")))

    return {
        "pp_path": outputs.get("pp.txt", ""),
        "objs_path": outputs.get("objs.txt", ""),
        "frida_js_path": outputs.get("blutter_frida.js", ""),
        "asm_dir": outputs.get("asm_dir", ""),
        "asm_count": outputs.get("asm_count", 0),
        "blutter_output": result.stdout[-500:] if 'result' in dir() else "",
        "result": outputs,
    }


@tool_meta(
    name="flutter_blutter_parse_pp",
    description="Parse Blutter pp.txt to extract endpoints, secrets, class names",
    params={
        "pp_path": "Path to pp.txt from Blutter",
    },
    outputs=["urls", "secrets", "classes", "counts", "result"],
)
def flutter_blutter_parse_pp(pp_path: str = "", **kwargs) -> dict:
    """Parse Blutter's pp.txt (object pool dump) for useful intelligence.

    The Object Pool contains all string constants, class names, and metadata
    used by the Dart app — including API URLs, keys, and other hardcoded strings.

    Args:
        pp_path: Path to pp.txt from Blutter

    Returns:
        Dict with URLs, secrets, classes extracted from the pool.
    """
    path = pp_path or kwargs.get("pp_path", "")
    if not path or not Path(path).exists():
        return {"error": "pp.txt not found", "result": {}}

    text = Path(path).read_text(encoding="utf-8", errors="ignore")

    urls: list[str] = []
    secrets: list[dict] = []
    classes: list[str] = []
    domains: set[str] = set()

    # URL pattern
    url_pat = re.compile(r'https?://[^\s"\'<>\[\]{}]+')
    # Secret patterns
    secret_pats = {
        "api_key": re.compile(r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([^"\' \n]{8,})'),
        "aws_key": re.compile(r'AKIA[0-9A-Z]{16}'),
        "firebase_url": re.compile(r'https://[a-z0-9-]+\.firebaseio\.com'),
        "jwt": re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'),
    }
    # Class pattern
    class_pat = re.compile(r"Class:\s*(\w+)|class\s+(\w+)", re.IGNORECASE)

    # Process each line
    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue

        # URLs
        for m in url_pat.finditer(line):
            url = m.group(0)
            urls.append(url)
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                if parsed.hostname:
                    domains.add(parsed.hostname)
            except Exception:
                pass

        # Secrets
        for stype, spat in secret_pats.items():
            for m in spat.finditer(line):
                val = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(1)
                secrets.append({"type": stype, "value": val[:80]})

        # Classes
        for cm in class_pat.finditer(line):
            cls_name = cm.group(1) or cm.group(2)
            if cls_name:
                classes.append(cls_name)

    # Deduplicate
    urls = list(set(urls))
    classes = list(set(classes))
    secrets = list({(s["type"], s["value"]): s for s in secrets}.values())

    # Save findings to storage
    storage = kwargs.get("_storage")
    target_id = kwargs.get("_target_id")
    if storage and target_id:
        run_id = kwargs.get("_run_id")
        # Endpoints
        for url in urls:
            storage.add_endpoint(target_id, url, source="blutter",
                                 category=storage.auto_categorize_endpoint(url),
                                 run_id=run_id)
        # Secrets
        for sec in secrets:
            storage.add_secret(target_id, type=sec["type"], value=sec["value"],
                               confidence="medium", run_id=run_id)

    return {
        "urls": urls,
        "secrets": secrets,
        "classes": classes,
        "domains": sorted(domains),
        "counts": {
            "urls": len(urls),
            "secrets": len(secrets),
            "classes": len(classes),
            "domains": len(domains),
        },
        "result": {
            "urls": urls[:30],
            "secrets": secrets[:10],
            "domains": sorted(domains),
        },
    }


@tool_meta(
    name="flutter_blutter_parse_frida",
    description="Parse blutter_frida.js from Blutter and add hooks to Frida catalog",
    params={
        "frida_js_path": "Path to blutter_frida.js",
    },
    outputs=["hooks_added", "hook_count", "result"],
)
def flutter_blutter_parse_frida(frida_js_path: str = "", **kwargs) -> dict:
    """Parse the Frida script generated by Blutter and import hooks into the Frida catalog.

    blutter_frida.js contains auto-generated hook stubs for the target app's
    Dart functions, including decompressPointer, getDartString, and class-specific hooks.

    Args:
        frida_js_path: Path to blutter_frida.js

    Returns:
        Dict with imported hook count.
    """
    path = frida_js_path or kwargs.get("frida_js_path", "")
    if not path or not Path(path).exists():
        return {"error": "blutter_frida.js not found", "result": {}}

    # Save as a proper Frida script in the catalog
    from tools.frida_manager import frida_save_script
    content = Path(path).read_text(encoding="utf-8", errors="ignore")

    # First line as description
    desc_line = content.split("\n")[0].strip() if content else "Blutter-generated Frida hooks"

    result = frida_save_script(
        name="blutter_hooks",
        category="flutter",
        content=content,
    )

    return {
        "hooks_added": result.get("path", ""),
        "hook_count": len([l for l in content.split("\n") if "Interceptor" in l or "hook" in l.lower()]),
        "file_size": len(content),
        "result": result,
    }


# ------------------------------------------------------------------
# F4: Flutter TLS Bypass
# ------------------------------------------------------------------

def _ensure_nviso_script() -> str:
    """Download NVISO disable-flutter-tls.js if not present."""
    _FLUTTER_SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    script_path = _FLUTTER_SCRIPTS_DIR / "disable_flutter_tls.js"

    if script_path.exists():
        return str(script_path)

    # Download from GitHub
    url = ("https://raw.githubusercontent.com/"
           "NVISOsecurity/disable-flutter-tls-verification/main/"
           "disable-flutter-tls.js")
    try:
        import urllib.request
        logger.info("Downloading disable-flutter-tls.js from NVISO ...")
        urllib.request.urlretrieve(url, script_path)
        logger.info("Saved to %s", script_path)
    except Exception as e:
        logger.warning("Failed to download NVISO script: %s", e)
        return ""
    return str(script_path)


@tool_meta(
    name="flutter_tls_bypass_frida",
    description="Bypass Flutter TLS verification using NVISO Frida script",
    params={
        "package": "Android package name",
        "mode": "spawn or attach",
        "timeout": "Timeout in seconds (default: 120)",
    },
    outputs=["output", "result"],
)
def flutter_tls_bypass_frida(package: str = "", mode: str = "spawn",
                             timeout: int = 120, **kwargs) -> dict:
    """Run NVISO disable-flutter-tls.js to bypass Flutter's BoringSSL TLS.

    Flutter bundles BoringSSL directly in libflutter.so, bypassing the system
    CA store. Standard SSL unpinning (TrustManager, OkHttp hooks) does NOT work.

    NVISO script uses pattern matching to find ssl_verify_peer_cert in
    handshake.cc and hooks it to always return success.

    Args:
        package: Android package name
        mode: spawn or attach
        timeout: Execution timeout

    Returns:
        Dict with Frida output.
    """
    pkg = package or kwargs.get("package", "")
    mod = mode or kwargs.get("mode", "spawn")
    to = timeout or kwargs.get("timeout", 120)

    if not pkg:
        return {"error": "package required", "output": "", "result": {}}

    script = _ensure_nviso_script()
    if not script:
        return {"error": "NVISO script not available", "output": "", "result": {}}

    # Use Frida to run the script
    cmd = ["frida", "-U"]
    if mod == "spawn":
        cmd.extend(["-f", pkg, "--no-pause"])
    else:
        cmd.extend(["-n", pkg])
    cmd.extend(["-l", script])
    cmd.extend(["-o", str(_FLUTTER_SCRIPTS_DIR / f"tls_bypass_{pkg}.log")])

    logger.info("Running NVISO TLS bypass on %s ...", pkg)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=to)
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "TIMEOUT — TLS bypass likely active (Frida keeps running)"
    except FileNotFoundError:
        return {"error": "frida CLI not found", "output": "", "result": {}}
    except Exception as e:
        output = f"ERROR: {e}"

    success = any(kw in output.lower() for kw in
                  ["ssl_verify_peer_cert", "tls disabled", "hooking ssl",
                   "replacing ssl", "flutter tls"])

    return {
        "output": output[:2000],
        "bypass_active": success,
        "log_path": str(_FLUTTER_SCRIPTS_DIR / f"tls_bypass_{pkg}.log"),
        "result": {"success": success, "output_preview": output[:500]},
    }


@tool_meta(
    name="flutter_tls_bypass_reflutter",
    description="Bypass Flutter TLS by patching APK with reFlutter and deploying",
    params={
        "apk_path": "Path to original APK",
        "package": "Package name",
        "proxy_ip": "Burp Suite IP address",
        "proxy_port": "Burp proxy port",
    },
    outputs=["patched_apk", "deployed", "result"],
)
def flutter_tls_bypass_reflutter(apk_path: str = "", package: str = "",
                                 proxy_ip: str = "192.168.1.100",
                                 proxy_port: int = 8083, **kwargs) -> dict:
    """Full reFlutter TLS bypass pipeline: patch → sign → deploy → proxy.

    reFlutter patches libflutter.so to disable TLS verification at the binary
    level, then routes traffic to a Burp invisible proxy (port 8083).

    Args:
        apk_path: Path to original APK
        package: Package name
        proxy_ip: Burp Suite IP
        proxy_port: Burp invisible proxy port (default 8083)

    Returns:
        Dict with deployment status and instructions.
    """
    apk = apk_path or kwargs.get("apk_path", "")
    pkg = package or kwargs.get("package", "")
    ip = proxy_ip or kwargs.get("proxy_ip", "192.168.1.100")
    port = proxy_port or kwargs.get("proxy_port", 8083)

    if not apk or not pkg:
        return {"error": "apk_path and package required", "result": {}}

    steps: dict[str, Any] = {}

    # Step 1: Patch
    patch = flutter_reflutter_patch(apk_path=apk, proxy_ip=ip)
    steps["reflutter_patch"] = patch
    if "error" in patch:
        return {"error": patch["error"], "result": steps}
    patched = patch.get("patched_apk", "release.RE.apk")

    # Step 2: Sign
    sign = flutter_sign_apk(apk_path=patched)
    steps["sign"] = sign

    # Step 3: Deploy
    deploy = flutter_deploy_patched(apk_path=patched, package=pkg)
    steps["deploy"] = deploy

    success = deploy.get("installed", False)
    return {
        "patched_apk": patched,
        "deployed": success,
        "package": pkg,
        "proxy_instructions": {
            "burp_listener_port": port,
            "burp_listener_bind": "All interfaces",
            "invisible_proxying": True,
            "note": "Add Burp listener on port 8083, bind to all interfaces, enable invisible proxying",
        },
        "steps": steps,
        "result": {"success": success, "patched_apk": patched},
    }


# ------------------------------------------------------------------
# Full Flutter Analysis Pipeline
# ------------------------------------------------------------------

@tool_meta(
    name="flutter_full_analyze",
    description="Complete Flutter analysis pipeline: detect → reflutter → blutter → tls bypass → parse",
    params={
        "apk_path": "Path to Flutter APK",
        "package": "Android package name",
        "proxy_ip": "Proxy IP for reFlutter",
        "run_blutter": "Run Blutter analysis via WSL2 (default: true)",
        "run_reflutter": "Patch with reFlutter (default: true)",
    },
    outputs=["detection", "blutter", "reflutter", "tls_bypass", "summary", "result"],
)
def flutter_full_analyze(apk_path: str = "", package: str = "",
                         proxy_ip: str = "192.168.1.100",
                         run_blutter: bool = True,
                         run_reflutter: bool = True, **kwargs) -> dict:
    """Run the complete Flutter analysis pipeline.

    Pipeline:
    1. Detect → check if APK is Flutter
    2. Extract libs → extract libflutter.so + libapp.so
    3. Blutter (WSL2) → analyze libapp.so, parse pp.txt
    4. reFlutter → patch APK, sign, deploy
    5. TLS bypass → instructions for NVISO Frida script

    Args:
        apk_path: Path to APK
        package: Package name
        proxy_ip: Proxy IP
        run_blutter: Enable Blutter analysis
        run_reflutter: Enable reFlutter patching

    Returns:
        Dict with all pipeline results.
    """
    apk = apk_path or kwargs.get("apk_path", "")
    pkg = package or kwargs.get("package", "")

    if not apk:
        return {"error": "apk_path required", "result": {}}

    results: dict[str, Any] = {}

    # Step 1: Detect
    detect = flutter_detect_apk(apk_path=apk)
    results["detection"] = detect

    if not detect.get("is_flutter", False):
        return {"error": "Not a Flutter app", "is_flutter": False, "result": results}

    if not pkg:
        # Try to get package name from APK
        try:
            from tools.android_tools import extract_manifest
            pkg_result = subprocess.run(
                ["unzip", "-p", apk, "AndroidManifest.xml"],
                capture_output=True, text=True, timeout=10,
            )
            # Can't easily parse binary XML here, just return note
        except Exception:
            pass

    storage = kwargs.get("_storage")
    target_id = kwargs.get("_target_id")

    # Step 2: Blutter analysis
    if run_blutter:
        extract = flutter_extract_lib(apk_path=apk, arch="arm64-v8a")
        results["lib_extract"] = extract
        lib_dir = str(Path(extract.get("output_dir", "")) / "lib" / "arm64-v8a")
        if Path(lib_dir).exists():
            blutter = flutter_blutter_analyze(lib_dir=lib_dir)
            results["blutter"] = blutter

            if blutter.get("pp_path"):
                pp_parsed = flutter_blutter_parse_pp(
                    pp_path=blutter["pp_path"],
                    _storage=storage,
                    _target_id=target_id,
                    _run_id=kwargs.get("_run_id"),
                )
                results["blutter_pp_parsed"] = {
                    "urls": len(pp_parsed.get("urls", [])),
                    "secrets": len(pp_parsed.get("secrets", [])),
                    "classes": len(pp_parsed.get("classes", [])),
                }

            if blutter.get("frida_js_path"):
                frida_result = flutter_blutter_parse_frida(
                    frida_js_path=blutter["frida_js_path"]
                )
                results["blutter_frida"] = frida_result

    # Step 3: reFlutter
    if run_reflutter:
        refl = flutter_tls_bypass_reflutter(
            apk_path=apk, package=pkg, proxy_ip=proxy_ip,
        )
        results["reflutter"] = refl

    # Summary
    summary = {
        "is_flutter": True,
        "engine_version": detect.get("engine_version", ""),
        "blutter_completed": "blutter" in results and "error" not in results["blutter"],
        "reflutter_completed": "reflutter" in results and results["reflutter"].get("deployed", False),
    }

    return {
        "detection": detect,
        "blutter": results.get("blutter", {}),
        "reflutter": results.get("reflutter", {}),
        "summary": summary,
        "result": summary,
    }
