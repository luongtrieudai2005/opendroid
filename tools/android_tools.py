"""Android pentest tools: adb, jadx, Frida wrappers.

Mỗi function gọi tool bên ngoài qua subprocess và parse output.
"""

import json
import logging
import os
import re
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ADB
# ---------------------------------------------------------------------------

def run_adb(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    """Run an adb command and return the result."""
    cmd = ["adb"] + args
    logger.debug("$ %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def set_proxy(host: str = "10.0.2.2", port: int = 8080) -> str:
    """Set HTTP proxy on Android emulator/device via adb."""
    result = run_adb([
        "shell", "settings", "put", "global", "http_proxy",
        f"{host}:{port}"
    ])
    if result.returncode == 0:
        logger.info("Proxy set to %s:%s", host, port)
    else:
        logger.warning("Failed to set proxy: %s", result.stderr)
    return result.stdout


def remove_proxy() -> str:
    """Remove HTTP proxy from Android emulator/device."""
    result = run_adb(["shell", "settings", "put", "global", "http_proxy", ":0"])
    if result.returncode == 0:
        logger.info("Proxy removed")
    return result.stdout


def list_packages(filter_str: str | None = None) -> list[str]:
    """List installed packages, optionally filtered."""
    args = ["shell", "pm", "list", "packages"]
    if filter_str:
        args.extend(["-f", filter_str])
    result = run_adb(args, timeout=60)
    packages = []
    for line in result.stdout.strip().split("\n"):
        if line.startswith("package:"):
            packages.append(line[8:].strip())
    return packages


def capture_screenshot(output_path: str = "screenshot.png") -> str:
    """Capture device screen via adb."""
    result = run_adb(["shell", "screencap", "-p", "/sdcard/screenshot.png"])
    if result.returncode == 0:
        run_adb(["pull", "/sdcard/screenshot.png", output_path])
        run_adb(["shell", "rm", "/sdcard/screenshot.png"])
        logger.info("Screenshot saved to %s", output_path)
    return output_path


def dump_app_data(package: str, output_dir: str = "app_data") -> list[str]:
    """Dump local storage files for a given package."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    base = f"/data/data/{package}"
    result = run_adb(["shell", f"run-as {package} ls -R {base}"], timeout=15)

    files = []
    for line in result.stdout.strip().split("\n"):
        line = line.strip()
        if line and not line.endswith(":") and "." in line:
            remote = f"{base}/{line}"
            local = output_path / line.replace("/", "_")
            run_adb(["shell", f"run-as {package} cat {remote}"],
                     timeout=10)
            files.append(str(local))
    return files


def install_app(apk_path: str) -> str:
    """Install APK on device."""
    result = run_adb(["install", "-r", "-d", apk_path], timeout=120)
    return result.stdout


def uninstall_app(package: str) -> str:
    """Uninstall app by package name."""
    result = run_adb(["uninstall", package], timeout=30)
    return result.stdout


def start_activity(package: str, activity: str) -> str:
    """Start an Android activity via adb am start."""
    result = run_adb([
        "shell", "am", "start",
        "-n", f"{package}/{activity}"
    ])
    return result.stdout


def send_intent(action: str, data_uri: str | None = None,
                extras: dict[str, str] | None = None) -> str:
    """Send a broadcast intent via adb."""
    args = ["shell", "am", "broadcast", "-a", action]
    if data_uri:
        args.extend(["-d", data_uri])
    if extras:
        for k, v in extras.items():
            args.extend(["--es", k, v])
    result = run_adb(args)
    return result.stdout

# ---------------------------------------------------------------------------
# JADX — APK Decompilation
# ---------------------------------------------------------------------------

def decompile_apk(apk_path: str, output_dir: str = "decompiled") -> Path:
    """Decompile APK using jadx.

    Returns path to output directory.
    """
    output = Path(output_dir)
    cmd = ["jadx", "-d", str(output), "--show-bad-code", apk_path]
    logger.info("Decompiling %s ...", apk_path)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        logger.warning("jadx stderr: %s", result.stderr[:500])
    return output


def extract_manifest(decompile_dir: str) -> dict:
    """Parse AndroidManifest.xml from decompiled output.

    Returns dict with: package, version, permissions, activities, services,
    receivers, providers, debuggable, allowBackup, etc.
    """
    manifest_path = Path(decompile_dir) / "AndroidManifest.xml"
    if not manifest_path.exists():
        logger.warning("AndroidManifest.xml not found at %s", manifest_path)
        return {}

    text = manifest_path.read_text(encoding="utf-8")
    info: dict = {}

    # Package name
    m = re.search(r'package="([^"]+)"', text)
    if m:
        info["package"] = m.group(1)

    # Permissions
    info["permissions"] = re.findall(r'<uses-permission android:name="([^"]+)"', text)

    # Activities (only match actual <activity> tags, not <uses-permission>)
    info["activities"] = re.findall(
        r'<activity[^>]*android:name="([^"]+)"', text
    )
    info["services"] = re.findall(
        r'<service[^>]*android:name="([^"]+)"', text
    )
    info["receivers"] = re.findall(
        r'<receiver[^>]*android:name="([^"]+)"', text
    )
    info["providers"] = re.findall(
        r'<provider[^>]*android:name="([^"]+)"', text
    )

    # Exported components (handle both orderings of name/exported)
    exported_names = set()
    for tag_pattern in (r'<activity', r'<service', r'<receiver', r'<provider'):
        matches = re.findall(
            r'android:name="([^"]+)"[^>]*android:exported="true"', text
        )
        exported_names.update(matches)
        matches_rev = re.findall(
            r'android:exported="true"[^>]*android:name="([^"]+)"', text
        )
        exported_names.update(matches_rev)
    info["exported_components"] = list(exported_names)

    # Debuggable
    info["debuggable"] = 'android:debuggable="true"' in text

    # Allow backup
    info["allowBackup"] = 'android:allowBackup="true"' in text

    # Intents
    info["intent_filters"] = re.findall(
        r'<action android:name="([^"]+)"', text
    )

    return info


def extract_endpoints(decompile_dir: str) -> list[dict]:
    """Extract URLs, domains, API endpoints from decompiled Java code.

    Returns list of dicts: {type, value, file, confidence}
    """
    endpoints: list[dict] = []
    src_dir = Path(decompile_dir) / "sources"

    if not src_dir.exists():
        logger.warning("Sources dir not found: %s", src_dir)
        return endpoints

    # Patterns
    url_pattern = re.compile(r'https?://[^\s"\'<>]+')
    domain_pattern = re.compile(r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?')
    firebase_pattern = re.compile(r'https?://[a-zA-Z0-9-]+\.firebaseio\.com')
    aws_pattern = re.compile(r'([A-Z0-9]{20})')  # Access key ID pattern

    for java_file in src_dir.rglob("*.java"):
        try:
            text = java_file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        rel = str(java_file.relative_to(src_dir))
        for m in url_pattern.finditer(text):
            url = m.group(0)
            endpoints.append({
                "type": "url",
                "value": url,
                "file": rel,
                "line": text[:m.start()].count("\n") + 1,
                "confidence": "high" if "api" in url.lower() else "medium",
            })

        for m in firebase_pattern.finditer(text):
            fb = m.group(0)
            endpoints.append({
                "type": "firebase",
                "value": fb,
                "file": rel,
                "line": text[:m.start()].count("\n") + 1,
                "confidence": "high",
            })

    # Also scan XML resource files for URLs (jadx outputs strings.xml, network config, etc.)
    res_dir = Path(decompile_dir) / "resources"
    if res_dir.exists():
        for xml_file in res_dir.rglob("*.xml"):
            try:
                text = xml_file.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for m in url_pattern.finditer(text):
                url = m.group(0)
                rel = str(xml_file.relative_to(res_dir))
                if not any(e["value"] == url and e.get("type") == "url" for e in endpoints):
                    endpoints.append({
                        "type": "url",
                        "value": url,
                        "file": rel,
                        "line": text[:m.start()].count("\n") + 1,
                        "confidence": "high" if "api" in url.lower() else "medium",
                    })

    return endpoints


def extract_secrets(decompile_dir: str) -> list[dict]:
    """Find potential secrets in decompiled code.

    Uses regex + entropy analysis.
    Patterns: API keys, tokens, passwords, AWS keys.
    """
    secrets: list[dict] = []
    src_dir = Path(decompile_dir) / "sources"

    patterns = {
        "aws_access_key": re.compile(r'(AKIA[0-9A-Z]{16})'),
        "firebase_key": re.compile(r'(AIza[0-9A-Za-z_-]{35})'),
        "stripe_live": re.compile(r'(sk_live_[0-9a-zA-Z]+)'),
        "stripe_test": re.compile(r'(sk_test_[0-9a-zA-Z]+)'),
        "github_token": re.compile(r'(gh[ps]_[0-9a-zA-Z]{36})'),
        "jwt": re.compile(r'(eyJ[0-9a-zA-Z_-]+\.eyJ[0-9a-zA-Z_-]+\.[0-9a-zA-Z_-]+)'),
        "slack_token": re.compile(r'(xox[baprs]-[0-9a-zA-Z-]+)'),
        "password_var": re.compile(r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']'),
        "api_key_var": re.compile(r'(?i)(api[_-]?key|apikey)\s*=\s*["\'][^"\']+["\']'),
        "secret_var": re.compile(r'(?i)(secret|token|auth)\s*=\s*["\'][^"\']+["\']'),
    }

    for java_file in src_dir.rglob("*.java"):
        try:
            text = java_file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for name, pattern in patterns.items():
            for match in pattern.finditer(text):
                secrets.append({
                    "type": name,
                    "value": match.group(1)[:50],
                    "file": str(java_file.relative_to(src_dir)),
                    "line": text[:match.start()].count("\n") + 1,
                    "confidence": "high" if name != "password_var" else "medium",
                })

    return secrets


def analyze_apk(apk_path: str, output_dir: str = "decompiled") -> dict:
    """Full APK analysis: decompile + manifest + endpoints + secrets.

    Returns a single dict with all results.
    """
    apk_path = str(apk_path)
    out = decompile_apk(apk_path, output_dir)
    return {
        "apk": apk_path,
        "decompiled_at": str(out),
        "manifest": extract_manifest(str(out)),
        "endpoints": extract_endpoints(str(out)),
        "secrets": extract_secrets(str(out)),
    }

# ---------------------------------------------------------------------------
# FRIDA — Dynamic Instrumentation
# ---------------------------------------------------------------------------

def frida_list_devices() -> list[str]:
    """List connected Frida devices."""
    result = subprocess.run(
        ["frida-ls-devices"], capture_output=True, text=True, timeout=10
    )
    return [l for l in result.stdout.strip().split("\n") if l]


def frida_list_processes(device: str = "usb") -> list[str]:
    """List running processes on Frida device."""
    result = subprocess.run(
        ["frida-ps", "-D", device] if device != "usb" else ["frida-ps", "-U"],
        capture_output=True, text=True, timeout=10
    )
    return [l for l in result.stdout.strip().split("\n") if l and not l.startswith("PID")]


def run_frida_script(package: str, script_path: str,
                     device: str = "usb", timeout: int = 30) -> str:
    """Run a Frida script against a package."""
    cmd = [
        "frida", "-U" if device == "usb" else "-D", device,
        "-f", package, "-l", script_path,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return result.stdout


def unpin_certificate(package: str, device: str = "usb",
                      method: str = "frida") -> str:
    """Bypass SSL certificate pinning.

    method='frida': uses frida-multiple-unpin.js script (auto-download).
    method='objection': uses objection sslpinning disable.
    """
    if method == "objection":
        cmd = [
            "objection", "-g", package, "explore",
            "-c", "android sslpinning disable",
            "--quiet"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout

    # Default: Frida with universal unpin script
    unpin_script = _get_unpin_script()
    return run_frida_script(package, unpin_script, device, timeout=60)


def _get_unpin_script() -> str:
    """Return path to universal-unpin.js, download if not exists."""
    script_dir = Path(__file__).parent.parent / "config" / "frida-scripts"
    script_dir.mkdir(parents=True, exist_ok=True)
    script_path = script_dir / "universal-unpin.js"

    if not script_path.exists():
        # Download universal unpin script
        import urllib.request
        url = ("https://raw.githubusercontent.com/"
               "httptoolkit/frida-interception-and-unpinning/main/"
               "frida-scripts/universal-unpin.js")
        logger.info("Downloading universal-unpin.js from %s ...", url)
        urllib.request.urlretrieve(url, script_path)
        logger.info("Saved to %s", script_path)

    return str(script_path)


def check_root_detection(package: str) -> list[str]:
    """Check if app has root detection and attempt to bypass.

    Returns list of detected anti-tampering methods.
    """
    detections: list[str] = []
    script = """
    Java.perform(function() {
        var checks = [
            "RootBeer", "rootbeer", "isRooted", "checkRoot",
            "su", "buildTags", "test-keys",
            "Superuser.apk", "magisk", "phh",
            "SafetyNet", "safetynet", "ctsProfileMatch",
            "Samsung", "Knox", "kNOX"
        ];
        checks.forEach(function(c) {
            var matches = Java.enumerateLoadedClassesSync()
                .filter(function(cls) {
                    return cls.toLowerCase().indexOf(c.toLowerCase()) !== -1;
                });
            if (matches.length > 0) {
                send("DETECT: " + c + " -> " + JSON.stringify(matches));
            }
        });
    });
    """
    script_path = Path(__file__).parent.parent / "config" / "frida-scripts" / "check_root.js"
    script_path.parent.mkdir(parents=True, exist_ok=True)
    script_path.write_text(script)

    output = run_frida_script(package, str(script_path), timeout=30)
    for line in output.split("\n"):
        if "DETECT:" in line:
            detections.append(line.replace("DETECT:", "").strip())
    return detections
