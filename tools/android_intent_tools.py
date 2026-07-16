"""Android intent/deep link analysis and fuzzing tools.

Detects:
  - Intent redirection vulnerabilities (forwarding Intents without validation)
  - Deep link hijacking
  - Exported component testing
  - Content Provider path traversal / SQL injection

Uses decompiled Java/Kotlin source + ADB runtime testing.
"""

import logging
import re
import subprocess
from pathlib import Path
from typing import Any

from tools.workflow import tool_meta

logger = logging.getLogger(__name__)


def _find_java_files(decompile_dir: str) -> list[Path]:
    """Find all Java source files in decompiled directory."""
    candidates = [
        Path(decompile_dir) / "sources",
        Path(decompile_dir) / "resources",
    ]
    files = []
    for d in candidates:
        if d.exists():
            files.extend(d.rglob("*.java"))
    return files


# ------------------------------------------------------------------
# Intent Redirection Detection
# ------------------------------------------------------------------

@tool_meta(
    name="intent_redirection_finder",
    description="Analyze decompiled source for intent forwarding without validation",
    params={
        "input": "Decompiled source directory (jadx output)",
    },
    outputs=["vulnerable_components", "patterns", "result"],
)
def intent_redirection_finder(input: str = "", **kwargs) -> dict:
    """Find intent redirection vulnerabilities in decompiled source.

    Looks for patterns where an Intent received via getIntent()
    is forwarded via startActivity()/startService()/sendBroadcast()
    without proper validation of the source.

    Args:
        input: Decompiled source directory

    Returns:
        Dict with vulnerable components, patterns, result.
    """
    decompile_dir = input or kwargs.get("input", "")
    src_files = _find_java_files(decompile_dir)

    vulnerable: list[dict] = []
    patterns_found: list[str] = []

    INTENT_VAR_PAT = re.compile(r"Intent\s+(\w+)\s*=\s*getIntent\(\)")
    FORWARD_PATS = [
        (r"startActivity\(\s*(\w+)\s*\)", "startActivity"),
        (r"startService\(\s*(\w+)\s*\)", "startService"),
        (r"sendBroadcast\(\s*(\w+)\s*\)", "sendBroadcast"),
        (r"startActivityForResult\(\s*(\w+)", "startActivityForResult"),
    ]

    for f in src_files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        # Look for getIntent() calls
        for im in INTENT_VAR_PAT.finditer(text):
            var_name = im.group(1)

            # Check if this intent is forwarded without validation
            for pat, forward_type in FORWARD_PATS:
                for fm in re.finditer(pat, text):
                    forwarded_var = fm.group(1)
                    if forwarded_var == var_name:
                        # Check context: look for validation keywords nearby
                        start = max(0, fm.start() - 300)
                        context = text[start:fm.end() + 50]

                        has_validation = bool(re.search(
                            r"(getCallingPackage|getCallingActivity|getCallingUid"
                            r"|Intent\.createChooser|resolveActivity|queryIntentActivities"
                            r"|PackageManager|checkCallingPermission)",
                            context,
                        ))

                        if not has_validation:
                            vulnerable.append({
                                "file": str(f.relative_to(Path(decompile_dir))),
                                "intent_variable": var_name,
                                "forward_type": forward_type,
                                "has_validation": False,
                                "line": text[:fm.start()].count("\n") + 1,
                            })
                            patterns_found.append(f"Intent redirection: {forward_type} with {var_name} without getCallingPackage check")
                        else:
                            vulnerable.append({
                                "file": str(f.relative_to(Path(decompile_dir))),
                                "intent_variable": var_name,
                                "forward_type": forward_type,
                                "has_validation": True,
                                "line": text[:fm.start()].count("\n") + 1,
                            })

    # Filter: only report unvalidated ones as findings, validated as info
    findings = [v for v in vulnerable if not v["has_validation"]]
    validated = [v for v in vulnerable if v["has_validation"]]

    return {
        "vulnerable_components": findings,
        "validated_components": validated,
        "patterns": list(set(patterns_found)),
        "vulnerable_count": len(findings),
        "total_intent_forwards": len(vulnerable),
        "result": {"vulnerable": findings, "validated": validated},
    }


# ------------------------------------------------------------------
# Deep Link Extractor + Fuzzer
# ------------------------------------------------------------------

@tool_meta(
    name="deep_link_fuzzer",
    description="Extract deep links from manifest and fuzz them on device",
    params={
        "input": "Decompiled source directory",
        "package": "Android package name for device testing",
        "test_on_device": "If true, send ADB intents to test deep links (default: false)",
    },
    outputs=["deep_links", "schemes", "fuzzable", "result"],
)
def deep_link_fuzzer(input: str = "", package: str = "",
                     test_on_device: bool = False, **kwargs) -> dict:
    """Extract deep link URLs from decompiled APK and optionally fuzz on device.

    Args:
        input: Decompiled source directory
        package: Android package name
        test_on_device: If True, send ADB intents to test deep links

    Returns:
        Dict with deep_links, schemes, fuzzable, result.
    """
    decompile_dir = input or kwargs.get("input", "")
    pkg = package or kwargs.get("package", "")

    # Find AndroidManifest.xml
    manifest_candidates = [
        Path(decompile_dir) / "AndroidManifest.xml",
        Path(decompile_dir) / "resources" / "AndroidManifest.xml",
    ]
    manifest_text = ""
    for mf in manifest_candidates:
        if mf.exists():
            manifest_text = mf.read_text(encoding="utf-8", errors="ignore")
            break

    if not manifest_text:
        return {"error": "AndroidManifest.xml not found", "deep_links": [],
                "schemes": [], "fuzzable": [], "result": {}}

    # Extract intent filters with deep link data
    intent_filters: list[dict] = []
    if_block_pat = re.compile(
        r'<intent-filter[^>]*>(.*?)</intent-filter>', re.DOTALL
    )

    for if_match in if_block_pat.finditer(manifest_text):
        block = if_match.group(1)
        action = ""
        scheme = ""
        host = ""
        path = ""

        am = re.search(r'android:name="([^"]+)"', block)
        if am:
            action = am.group(1)

        dm = re.search(r'android:scheme="([^"]+)"', block)
        if dm:
            scheme = dm.group(1)

        hm = re.search(r'android:host="([^"]+)"', block)
        if hm:
            host = hm.group(1)

        pm = re.search(r'android:path(?:Pattern|Prefix)?="([^"]+)"', block)
        if pm:
            path = pm.group(1)

        if scheme:
            intent_filters.append({
                "action": action,
                "scheme": scheme,
                "host": host,
                "path": path,
                "uri": f"{scheme}://{host}{path}" if host else f"{scheme}://{path}",
            })

    # Deduplicate
    seen_uris = set()
    unique_links: list[dict] = []
    for item in intent_filters:
        key = item["uri"]
        if key not in seen_uris:
            seen_uris.add(key)
            unique_links.append(item)

    schemes = list(set(i["scheme"] for i in unique_links))
    uris = [i["uri"] for i in unique_links]

    # Generate fuzz payloads
    fuzzable = []
    for item in unique_links:
        base = item["uri"]
        fuzzable.extend([
            {"uri": base, "description": "base deep link"},
            {"uri": f"{base}//", "description": "double slash"},
            {"uri": f"{base}/..", "description": "path traversal"},
            {"uri": f"{base}/.%00", "description": "null byte injection"},
            {"uri": f"{base}../../../data/data/{pkg}/databases", "description": "file read attempt"},
            {"uri": f"{base}?token=TEST", "description": "parameter injection"},
            {"uri": f"{base}#test", "description": "fragment injection"},
        ])

    # Optionally test on device via ADB
    device_results = []
    if test_on_device and pkg:
        for item in fuzzable[:10]:
            uri = item["uri"]
            try:
                result = subprocess.run(
                    ["adb", "shell", "am", "start",
                     "-W", "-a", "android.intent.action.VIEW",
                     "-d", uri],
                    capture_output=True, text=True, timeout=10,
                )
                device_results.append({
                    "uri": uri,
                    "stdout": result.stdout[:200],
                    "stderr": result.stderr[:200],
                    "returncode": result.returncode,
                })
            except Exception as e:
                device_results.append({"uri": uri, "error": str(e)})

    return {
        "deep_links": uris,
        "intent_filters": unique_links,
        "schemes": schemes,
        "count": len(uris),
        "fuzzable": fuzzable[:20],
        "device_tests": device_results if test_on_device else [],
        "result": {"intent_filters": unique_links, "fuzzable": fuzzable[:20]},
    }


# ------------------------------------------------------------------
# Exported Component Fuzzer
# ------------------------------------------------------------------

@tool_meta(
    name="component_fuzzer",
    description="Fuzz exported Android components on device via ADB",
    params={
        "package": "Android package name",
        "input": "Decompiled source directory",
        "test_malformed": "Send malformed intents (default: true)",
    },
    outputs=["exported_components", "test_results", "result"],
)
def component_fuzzer(package: str = "", input: str = "",
                     test_malformed: bool = True, **kwargs) -> dict:
    """Test exported components on a live device/emulator via ADB.

    Args:
        package: Android package name
        input: Decompiled source directory (to read manifest)
        test_malformed: Send malformed/crash intents

    Returns:
        Dict with exported components, test results, result.
    """
    pkg = package or kwargs.get("package", "")
    decompile_dir = input or kwargs.get("input", "")

    if not pkg:
        return {"error": "package is required", "exported_components": [],
                "test_results": [], "result": {}}

    # Read manifest for exported components
    from tools.android_tools import extract_manifest, extract_endpoints
    manifest = extract_manifest(decompile_dir) if decompile_dir else {}
    exported = manifest.get("exported_components", [])
    activities = manifest.get("activities", [])
    services = manifest.get("services", [])
    receivers = manifest.get("receivers", [])
    providers = manifest.get("providers", [])

    test_results: list[dict] = []

    if test_malformed:
        # Test exported activities
        for comp in exported:
            # Try to start the activity directly
            try:
                result = subprocess.run(
                    ["adb", "shell", "am", "start",
                     "-n", f"{pkg}/{comp}",
                     "--ei", "crash", "1",
                     "-f", "0x00000000"],
                    capture_output=True, text=True, timeout=10,
                )
                output = (result.stdout + result.stderr)[:500]
                test_results.append({
                    "component": comp,
                    "type": "activity",
                    "action": "am start",
                    "output": output,
                    "crashed": "CRASH" in output or "FATAL" in output,
                })
            except Exception as e:
                test_results.append({
                    "component": comp, "type": "activity",
                    "error": str(e),
                })

        # Test content providers with path traversal
        for prov in providers:
            test_uris = [
                f"content://{prov}/../data/data/{pkg}/databases",
                f"content://{prov}/../../..//data/data/{pkg}/shared_prefs",
                f"content://{prov}/.%00",
            ]
            for uri in test_uris:
                try:
                    result = subprocess.run(
                        ["adb", "shell", "content", "query",
                         "--uri", uri],
                        capture_output=True, text=True, timeout=10,
                    )
                    out = result.stdout.strip()
                    if out and "Error" not in out:
                        test_results.append({
                            "component": prov,
                            "type": "provider_path_traversal",
                            "uri": uri,
                            "output": out[:300],
                            "accessible": True,
                        })
                except Exception:
                    pass

    return {
        "package": pkg,
        "exported_components": exported,
        "activities": len(activities),
        "services": len(services),
        "receivers": len(receivers),
        "providers": len(providers),
        "test_results": test_results,
        "crash_count": sum(1 for t in test_results if t.get("crashed")),
        "result": {
            "exported": exported,
            "test_results": test_results,
        },
    }


# ------------------------------------------------------------------
# Content Provider Scanner
# ------------------------------------------------------------------

@tool_meta(
    name="content_provider_scanner",
    description="Scan for Content Provider vulnerabilities in decompiled source",
    params={
        "input": "Decompiled source directory",
        "package": "Android package name",
    },
    outputs=["providers", "vulnerable_providers", "result"],
)
def content_provider_scanner(input: str = "", package: str = "", **kwargs) -> dict:
    """Analyze Content Provider implementations for path traversal and SQL injection.

    Args:
        input: Decompiled source directory
        package: Android package name

    Returns:
        Dict with provider analysis.
    """
    decompile_dir = input or kwargs.get("input", "")
    src_files = _find_java_files(decompile_dir)

    providers: list[dict] = []

    # Patterns for vulnerable Content Provider patterns
    VULN_PATTERNS = [
        ("path_traversal", r"openFile\s*\(\s*Uri\s+\w+"),
        ("sql_injection_raw", r"rawQuery\s*\(\s*[^)]*Uri"),
        ("sql_injection_concat", r"SQLiteDatabase.*execSQL.*\\+"),
        ("no_validate", r"@Override\s+(public\s+)?(Cursor|ParcelFileDescriptor)\s+(query|openFile)"),
        ("file_mode_bypass", r"mode_readable|MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE"),
    ]

    for f in src_files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        # Check if this file extends ContentProvider
        if not re.search(r"extends\s+ContentProvider", text):
            continue

        rel_path = str(f.relative_to(Path(decompile_dir)))
        provider_info: dict = {
            "file": rel_path,
            "class_name": "",
            "authority": "",
            "vulnerabilities": [],
        }

        # Extract class name
        cm = re.search(r"(?:public\s+)?class\s+(\w+)", text)
        if cm:
            provider_info["class_name"] = cm.group(1)

        # Extract authority from manifest or @Path annotation
        authority_match = re.search(r'android:authorities="([^"]+)"', text)
        if not authority_match:
            authority_match = re.search(r"@Path\s*\(\s*[\"']([^\"']+)[\"']\s*\)", text)
        if authority_match:
            provider_info["authority"] = authority_match.group(1)

        # Check each vulnerability pattern
        for vuln_name, pattern in VULN_PATTERNS:
            if re.search(pattern, text):
                provider_info["vulnerabilities"].append(vuln_name)

        if provider_info["vulnerabilities"]:
            providers.append(provider_info)

    return {
        "providers": providers,
        "vulnerable_providers": [p for p in providers if p["vulnerabilities"]],
        "count": len(providers),
        "vulnerable_count": sum(1 for p in providers if p["vulnerabilities"]),
        "result": {"providers": providers},
    }
