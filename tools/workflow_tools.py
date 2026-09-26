"""Workflow tool implementations with @tool_meta decorators.

Each function maps to an abstract tool name in workflow YAML files.
Discovered automatically by ToolRegistry._load_builtins().
"""

import json
import logging
import re
from pathlib import Path
from typing import Any

from tools.storage import StorageManager
from tools.workflow import tool_meta

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# PHASE 0: Program & Scope Intelligence
# ------------------------------------------------------------------

_OUT_OF_SCOPE_SIGNALS = {
    "uri_leak": {"keywords": ["uri", "leak", "malicious app"], "phase": "static"},
    "cert_pinning": {"keywords": ["certificate pinning", "cert pinning"], "phase": "dynamic"},
    "sensitive_data_tls": {"keywords": ["sensitive data in url", "sensitive data in body", "tls"], "phase": "traffic"},
    "external_storage": {"keywords": ["external storage", "unencrypted storage"], "phase": "storage"},
    "obfuscation": {"keywords": ["obfuscation", "binary protection"], "phase": "static"},
    "crash_intent": {"keywords": ["crash", "malformed intent", "denial of service"], "phase": "ipc"},
    "private_dir_data": {"keywords": ["private directory", "app private directory"], "phase": "storage"},
    "frida_rooted": {"keywords": ["frida", "rooted", "jailbroken", "runtime hacking"], "phase": "dynamic"},
}

_OUT_OF_SCOPE_EFFORT_REDIRECT = {
    "uri_leak": "skip — platform behavior, not app bug",
    "cert_pinning": "bypass internally for traffic observation, do NOT report bypass",
    "sensitive_data_tls": "check authorization logic in that data (IDOR/BOLA) instead",
    "external_storage": "remove external storage from checklist entirely",
    "obfuscation": "leverage easy-to-read code for faster static analysis",
    "crash_intent": "push further to prove data leakage or auth bypass, stop at crash",
    "private_dir_data": "skip local DB/prefs in private dir unless pivot to backend",
    "frida_rooted": "final PoC must be reproducible on non-rooted device",
}

_SCOPE_PATTERNS = {
    "in_scope_android": [
        "exported component", "data leakage", "intent", "deep link",
        "app link", "webview", "javascript bridge", "content provider",
        "path traversal", "sql injection",
    ],
    "in_scope_backend": [
        "idor", "bola", "authentication", "authorization", "graphql",
        "rate limit", "otp", "business logic", "race condition",
    ],
}


def _parse_scope_matrix(policy_text: str) -> dict:
    """Parse policy text into scope matrix with out-of-scope flags.

    Returns {category: {out_of_scope: bool, redirect: str, evidence: str}}.
    """
    matrix = {}
    text_lower = policy_text.lower()

    for cat, info in _OUT_OF_SCOPE_SIGNALS.items():
        found = any(kw in text_lower for kw in info["keywords"])
        matrix[cat] = {
            "out_of_scope": found,
            "phase": info["phase"],
            "redirect": _OUT_OF_SCOPE_EFFORT_REDIRECT[cat] if found else "in scope",
            "evidence": "",
        }
        if found:
            for kw in info["keywords"]:
                idx = text_lower.find(kw)
                if idx >= 0:
                    matrix[cat]["evidence"] = policy_text[max(0, idx - 30):idx + len(kw) + 30]
                    break

    return matrix


def _detect_tier_signals(policy_text: str) -> dict:
    """Extract maturity signals from policy text."""
    text_lower = policy_text.lower()
    signals = {
        "has_bounty_table": "$" in policy_text or "bounty" in text_lower,
        "max_bounty": 0,
        "has_out_of_scope": any(kw in text_lower for kw in ["out of scope", "not eligible", "excluded"]),
        "policy_detail_level": "low",
        "has_hof": "hall of fame" in text_lower or "hof" in text_lower,
    }

    # Try to extract max bounty
    for m in re.finditer(r'\$\s*([\d,]+)', policy_text):
        val = int(m.group(1).replace(",", ""))
        if val > signals["max_bounty"]:
            signals["max_bounty"] = val

    # Policy detail level
    oos_items = sum(1 for kw in ["out of scope", "not eligible", "excluded", "ineligible"]
                    if kw in text_lower)
    signals["policy_detail_level"] = "high" if oos_items > 3 else "medium" if oos_items > 0 else "low"

    return signals


@tool_meta(
    name="program_intelligence",
    description="Analyze bug bounty program policy, build scope matrix, tier classification",
    params={
        "program_name": "Program name (e.g. Grab)",
        "policy_text": "Full policy text or URL",
        "package_name": "Target package name",
        "signal_count": "Number of existing public submissions (approximate)",
    },
    outputs=["scope_matrix", "tier", "strategy", "effort_redirect_map"],
)
def program_intelligence(
    program_name: str = "",
    policy_text: str = "",
    package_name: str = "",
    signal_count: int = 0,
    **kwargs,
) -> dict:
    """Phase 0: Analyze program policy and classify target.

    Returns scope matrix, tier classification, and effort redirect map.
    """
    text = policy_text or kwargs.get("policy_text", "")
    pname = program_name or kwargs.get("program_name", program_name)
    pkg = package_name or kwargs.get("package_name", package_name)

    if not text:
        return {
            "program": pname,
            "package": pkg,
            "tier": "unknown",
            "strategy": "breadth",
            "error": "No policy_text provided",
        }

    scope_matrix = _parse_scope_matrix(text)
    signals = _detect_tier_signals(text)

    # Tier classification
    tier = "B"
    strategy = "breadth"
    reasons = []

    if signals["max_bounty"] >= 5000 and signals["has_out_of_scope"]:
        tier = "A"
        strategy = "depth"
        reasons.append(f"Max bounty ${signals['max_bounty']:,} + detailed out-of-scope")

    if signal_count > 50:
        tier = "A"
        strategy = "depth"
        reasons.append(f"High signal: ~{signal_count}+ public submissions")

    if signals["has_hof"]:
        tier = "A"
        strategy = "depth"
        reasons.append("Has Hall of Fame (well-established program)")

    if tier == "B":
        reasons.append("Lower or no maturity signals — breadth-first approach")

    # Build effort redirect map
    redirects = {}
    for cat, info in scope_matrix.items():
        if info["out_of_scope"]:
            redirects[cat] = info["redirect"]

    # ID which phases should be skipped or trimmed
    oos_phases = set()
    for cat, info in scope_matrix.items():
        if info["out_of_scope"]:
            oos_phases.add(info["phase"])
    phase_actions = {}
    for phase in ["static", "dynamic", "traffic", "storage", "ipc"]:
        if phase in oos_phases:
            phase_actions[phase] = "filtered"
        else:
            phase_actions[phase] = "full"

    return {
        "program": pname,
        "package": pkg,
        "tier": tier,
        "strategy": strategy,
        "reasons": reasons,
        "scope_matrix": scope_matrix,
        "effort_redirect_map": redirects,
        "phase_actions": phase_actions,
        "signals": signals,
    }


@tool_meta(
    name="tier_classifier",
    description="Classify target maturity: Tier A (mature) vs Tier B (new/underscoped)",
    params={
        "max_bounty": "Maximum bounty amount in USD",
        "out_of_scope_count": "Number of out-of-scope items",
        "submission_estimate": "Estimated number of past submissions",
        "has_hall_of_fame": "Program has public Hall of Fame",
        "policy_detail": "high|medium|low",
    },
    outputs=["tier", "strategy", "reasons"],
)
def tier_classifier(
    max_bounty: int = 0,
    out_of_scope_count: int = 0,
    submission_estimate: int = 0,
    has_hall_of_fame: bool = False,
    policy_detail: str = "low",
    **kwargs,
) -> dict:
    """Classify target into Tier A (mature, competitive) or Tier B (new, less hunted).

    Tier A → depth strategy: focus on backend API, business logic, chaining.
    Tier B → breadth strategy: full MASTG checklist, low-hanging fruit.
    """
    max_bounty = max_bounty or kwargs.get("max_bounty", 0)
    out_of_scope_count = out_of_scope_count or kwargs.get("out_of_scope_count", 0)
    submission_estimate = submission_estimate or kwargs.get("submission_estimate", 0)

    reasons = []
    tier = "B"

    if max_bounty >= 5000:
        tier = "A"
        reasons.append(f"Bounty ≥ $5,000 (${max_bounty:,})")
    if out_of_scope_count >= 5:
        tier = "A"
        reasons.append(f"Detailed out-of-scope policy ({out_of_scope_count} items)")
    if submission_estimate > 100:
        tier = "A"
        reasons.append(f"Heavily hunted (~{submission_estimate}+ submissions)")
    if has_hall_of_fame:
        tier = "A"
        reasons.append("Public Hall of Fame (mature program)")

    strategy = "depth" if tier == "A" else "breadth"
    if not reasons:
        reasons.append("Low maturity signals — breadth-first approach recommended")

    return {
        "tier": tier,
        "strategy": strategy,
        "reasons": reasons,
        "recommendation": (
            "Prioritize backend API testing, business logic, and chaining. "
            "Skip local-device hardening checks filtered by scope matrix."
            if tier == "A"
            else "Run full MASTG checklist — likely undiscovered low-hanging fruit."
        ),
    }


# ------------------------------------------------------------------
# PHASE 1: Reconnaissance & Preparation
# ------------------------------------------------------------------

@tool_meta(
    name="apk_importer",
    description="Import APK into workspace, compute SHA256, register target",
    params={
        "apk_path": "Path to APK file",
        "package_name": "Android package name (e.g. com.target.app)",
        "app_name": "Optional app display name",
    },
    outputs=["target_id", "apk_id", "apk_path"],
)
def apk_importer(apk_path: str = "", package_name: str = "",
                 app_name: str = "", **kwargs) -> dict:
    apk_path = apk_path or kwargs.get("apk_path", "")
    package_name = package_name or kwargs.get("package_name", "")
    storage: StorageManager = kwargs.get("_storage")
    if not storage:
        raise ValueError("_storage required for apk_importer")
    target_id = storage.create_target(package_name, app_name=app_name)
    apk_info = storage.save_apk(target_id, apk_path)
    return {
        "target_id": target_id,
        "apk_id": apk_info["id"],
        "apk_path": apk_info["path"],
        "package_name": package_name,
    }


@tool_meta(
    name="env_checker",
    description="Verify required tools are available",
    params={"required": "List of tool names to check"},
    outputs=["missing", "available"],
)
def env_checker(required: list | None = None, **kwargs) -> dict:
    import shutil
    required = required or []
    available: dict[str, bool] = {}
    missing: list[str] = []
    for tool in required:
        found = shutil.which(tool) is not None
        if not found:
            try:
                from tools.recon import check_tool
                found = check_tool(tool)
            except Exception:
                pass
        available[tool] = found
        if not found:
            missing.append(tool)
    return {"available": available, "missing": missing, "ok": len(missing) == 0}


# ------------------------------------------------------------------
# PHASE 2: Static Analysis
# ------------------------------------------------------------------

@tool_meta(
    name="jadx",
    description="Decompile APK with jadx",
    params={"apk": "Path to APK", "output": "Output directory"},
    outputs=["decompile_dir", "output"],
)
def jadx(apk: str = "", output: str = "", **kwargs) -> dict:
    import subprocess
    apk = apk or kwargs.get("apk", "")
    output = output or kwargs.get("output", "")
    if not output:
        stem = Path(apk).stem if apk else "decompiled"
        output = str(Path("workspace") / "jadx" / stem)
    output_abs = Path(output).resolve()
    output_abs.mkdir(parents=True, exist_ok=True)

    # Convert Windows path to WSL2 path
    def _to_wsl(path: str) -> str:
        p = Path(path).resolve()
        drive = p.drive.lower().rstrip(":")
        rest = str(p.relative_to(p.anchor)).replace("\\", "/")
        return f"/mnt/{drive}/{rest}"

    wsl_apk = _to_wsl(apk)
    wsl_out = _to_wsl(str(output_abs))

    cmd = f"jadx -d {wsl_out} --show-bad-code {wsl_apk}"
    logger.info("jadx (WSL2): decompiling %s ...", apk)
    result = subprocess.run(
        ["wsl.exe", "bash", "-c", cmd],
        capture_output=True, text=True, timeout=1800,
    )
    if result.returncode != 0:
        logger.warning("jadx stderr: %s", result.stderr[:500])
    return {"decompile_dir": str(output_abs), "output": str(output_abs)}


@tool_meta(
    name="manifest_parser",
    description="Extract and analyze AndroidManifest.xml",
    params={
        "input": "Decompiled source directory",
        "extract_components": "Extract components (default true)",
        "extract_permissions": "Extract permissions (default true)",
    },
    outputs=["package", "permissions", "activities", "exported_components",
             "debuggable", "allow_backup", "intent_filters", "components"],
)
def manifest_parser(input: str = "", extract_components: bool = True,
                    extract_permissions: bool = True, **kwargs) -> dict:
    from tools.android_tools import extract_manifest
    decompile_dir = input or kwargs.get("input", "")
    manifest = extract_manifest(decompile_dir)
    if not manifest.get("package") and Path(decompile_dir).exists():
        # jadx 1.5+ puts AndroidManifest.xml in resources/
        alt = Path(decompile_dir) / "resources" / "AndroidManifest.xml"
        if alt.exists():
            manifest = extract_manifest(str(Path(decompile_dir) / "resources"))
    if not manifest.get("package"):
        for cand in Path(decompile_dir).rglob("AndroidManifest.xml"):
            manifest = extract_manifest(str(cand.parent))
            if manifest.get("package"):
                break
    components = []
    for comp_type in ("activities", "services", "receivers", "providers"):
        for name in manifest.get(comp_type, []):
            exported = name in manifest.get("exported_components", [])
            components.append({"type": comp_type.rstrip("s"),
                               "name": name, "exported": exported})

    storage: StorageManager | None = kwargs.get("_storage")
    target_id = kwargs.get("_target_id")
    if storage and target_id:
        try:
            storage.save_manifest(target_id, components,
                                  manifest.get("permissions", []),
                                  run_id=kwargs.get("_run_id"))
        except Exception as exc:
            logger.warning("manifest persist failed: %s", exc)

    return {
        "package": manifest.get("package", ""),
        "permissions": manifest.get("permissions", []),
        "activities": manifest.get("activities", []),
        "exported_components": manifest.get("exported_components", []),
        "debuggable": manifest.get("debuggable", False),
        "allow_backup": manifest.get("allowBackup", False),
        "intent_filters": manifest.get("intent_filters", []),
        "components": components,
        "result": manifest,
    }


@tool_meta(
    name="endpoint_extractor",
    description="Extract all URLs/API endpoints from decompiled source",
    params={"input": "Decompiled source directory", "min_confidence": "low|medium|high"},
    outputs=["urls", "result"],
)
def endpoint_extractor(input: str = "", min_confidence: str = "low", **kwargs) -> dict:
    from tools.android_tools import extract_endpoints
    decompile_dir = input or kwargs.get("input", "")
    endpoints = extract_endpoints(decompile_dir)
    # Rank high > medium > low; keep endpoints at or above min_confidence.
    confidence_rank = {"high": 3, "medium": 2, "low": 1}
    min_rank = confidence_rank.get(min_confidence, 1)
    filtered = [e for e in endpoints
                if confidence_rank.get(e.get("confidence", "low"), 1) >= min_rank]

    storage: StorageManager | None = kwargs.get("_storage")
    target_id = kwargs.get("_target_id")
    if storage and target_id:
        try:
            rows = []
            for e in filtered:
                url = e["value"]
                rows.append({
                    "url": url,
                    "category": storage.auto_categorize_endpoint(url),
                    "source": "jadx",
                    "source_file": e.get("file", ""),
                    "params": {"confidence": e.get("confidence", "low"),
                               "type": e.get("type", "url"),
                               "line": e.get("line")},
                })
            storage.add_endpoints_bulk(target_id, rows,
                                       run_id=kwargs.get("_run_id"))
        except Exception as exc:
            logger.warning("endpoint persist failed: %s", exc)

    return {"urls": [e["value"] for e in filtered], "result": filtered}


@tool_meta(
    name="secret_hunter",
    description="Hunt for hardcoded secrets in decompiled source",
    params={"input": "Decompiled source directory", "patterns": "List of regex pattern configs"},
    outputs=["secrets", "result"],
)
def secret_hunter(input: str = "", patterns: list | None = None, **kwargs) -> dict:
    import hashlib
    from tools.android_tools import extract_secrets
    decompile_dir = input or kwargs.get("input", "")
    base_secrets = extract_secrets(decompile_dir)
    all_secrets = list(base_secrets)

    src_dir = Path(decompile_dir) / "sources"
    if patterns and src_dir.exists():
        for cfg in patterns:
            ptype = cfg.get("type", "generic")
            try:
                regex = re.compile(cfg["regex"])
            except (KeyError, re.error):
                continue
            for f in src_dir.rglob("*.java"):
                try:
                    text = f.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                for m in regex.finditer(text):
                    val = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(1)
                    all_secrets.append({
                        "type": ptype,
                        "value": val[:80],
                        "file": str(f.relative_to(src_dir)),
                        "confidence": cfg.get("confidence", "medium"),
                        "context": text[max(0, m.start() - 40):m.end() + 40],
                    })

    seen = set()
    deduped = []
    for s in all_secrets:
        key = hashlib.md5(f"{s['type']}:{s['value']}".encode()).hexdigest()
        if key not in seen:
            seen.add(key)
            deduped.append(s)

    storage: StorageManager | None = kwargs.get("_storage")
    target_id = kwargs.get("_target_id")
    if storage and target_id:
        try:
            rows = [{
                "type": s.get("type", "generic"),
                "value": s.get("value", ""),
                "confidence": s.get("confidence", "medium"),
                "source_file": s.get("file", ""),
                "line_number": s.get("line"),
                "context": (s.get("context") or "")[:200],
            } for s in deduped]
            storage.add_secrets_bulk(target_id, rows, run_id=kwargs.get("_run_id"))
        except Exception as exc:
            logger.warning("secret persist failed: %s", exc)

    return {"secrets": deduped, "count": len(deduped), "result": deduped}


@tool_meta(
    name="obfuscation_detector",
    description="Detect ProGuard/R8 obfuscation, string encryption, reflection",
    params={"input": "Decompiled source directory"},
    outputs=["obfuscated", "techniques", "confidence"],
)
def obfuscation_detector(input: str = "", **kwargs) -> dict:
    decompile_dir = input or kwargs.get("input", "")
    src_dir = Path(decompile_dir) / "sources"
    findings = []
    if not src_dir.exists():
        return {"obfuscated": False, "techniques": [], "confidence": "low"}

    java_files = list(src_dir.rglob("*.java"))
    total = len(java_files)
    if total == 0:
        return {"obfuscated": False, "techniques": [], "confidence": "low"}

    short_names = sum(1 for f in java_files
                      if len(f.stem) <= 2 and f.stem.isalpha())
    ratio = short_names / total if total else 0
    if ratio > 0.3:
        findings.append("proguard_short_names")

    reflection_count = 0
    string_encrypt = False
    for f in java_files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if "forName" in text or "getMethod" in text or "invoke" in text:
            reflection_count += 1
        if re.search(r'[\\u00][0-9a-fA-F]{4}', text):
            string_encrypt = True

    if reflection_count > total * 0.1:
        findings.append("heavy_reflection")
    if string_encrypt:
        findings.append("string_encryption")
    if ratio > 0.5:
        findings.append("proguard_aggressive")

    return {
        "obfuscated": len(findings) > 0,
        "techniques": findings,
        "confidence": "high" if ratio > 0.5 else "medium" if findings else "low",
        "class_count": total,
        "short_name_ratio": round(ratio, 3),
    }


@tool_meta(
    name="third_party_analyzer",
    description="Identify third-party SDKs and their versions",
    params={"input": "Decompiled source directory"},
    outputs=["sdks", "result"],
)
def third_party_analyzer(input: str = "", **kwargs) -> dict:
    decompile_dir = input or kwargs.get("input", "")
    src_dir = Path(decompile_dir) / "sources"
    known_packages = {
        "com.google.firebase": "Firebase",
        "com.google.android.gms": "Google Play Services",
        "com.facebook": "Facebook SDK",
        "com.adjust": "Adjust Analytics",
        "com.appsflyer": "AppsFlyer",
        "com.amplitude": "Amplitude",
        "com.mixpanel": "Mixpanel",
        "com.flurry": "Flurry",
        "com.branch": "Branch IO",
        "com.squareup": "Square (OkHttp/Retrofit)",
        "com.onesignal": "OneSignal",
        "io.sentry": "Sentry",
        "com.newrelic": "New Relic",
        "com.crashlytics": "Crashlytics",
        "com.segment": "Segment",
        "com.optimizely": "Optimizely",
        "com.unity3d": "Unity Ads",
        "com.chartboost": "Chartboost",
        "com.vungle": "Vungle",
        "org.apache": "Apache",
        "com.microsoft": "Microsoft",
        "com.amazon": "Amazon",
    }
    detected = {}
    if src_dir.exists():
        for pkg, name in known_packages.items():
            if (src_dir / pkg.replace(".", "/")).exists():
                detected[name] = "present"
    return {"sdks": list(detected.keys()), "result": detected}


@tool_meta(
    name="native_analyzer",
    description="Analyze native .so libraries for exported functions and strings",
    params={"input": "Decompiled source directory"},
    outputs=["libraries", "result"],
)
def native_analyzer(input: str = "", **kwargs) -> dict:
    decompile_dir = input or kwargs.get("input", "")
    lib_root = Path(decompile_dir) / "resources" / "lib"
    if not lib_root.exists():
        lib_root = Path(decompile_dir)
    libs = []
    for so in sorted(lib_root.rglob("*.so")):
        rel = str(so.relative_to(decompile_dir))
        arch = so.parent.name if so.parent.name in ("armeabi-v7a", "arm64-v8a",
                                                      "x86", "x86_64") else "unknown"
        size = so.stat().st_size
        libs.append({"path": rel, "architecture": arch, "size": size,
                      "filename": so.name})
    return {"libraries": libs, "count": len(libs), "result": libs}


@tool_meta(
    name="cloud_checker",
    description="Check discovered cloud URLs (Firebase, AWS) for public access",
    params={"endpoints": "List of extracted endpoints", "secrets": "List of extracted secrets",
            "verify": "If true, actually test endpoints"},
    outputs=["cloud_services", "findings", "result"],
)
def cloud_checker(endpoints: list | None = None, secrets: list | None = None,
                  verify: bool = True, **kwargs) -> dict:
    from tools.apk_analyzer import _check_firebase, _check_aws_key
    services = []
    findings = []

    ep_list = endpoints or kwargs.get("endpoints", [])
    sec_list = secrets or kwargs.get("secrets", [])

    for ep in ep_list:
        if isinstance(ep, dict):
            url = ep.get("value", ep.get("url", ""))
            conf = ep.get("confidence", "medium")
        else:
            url, conf = str(ep), "medium"
        if "firebaseio.com" in url:
            services.append({"service": "Firebase", "url": url, "confidence": conf})
        if "amazonaws.com" in url:
            services.append({"service": "AWS", "url": url, "confidence": conf})

    for sec in sec_list:
        if isinstance(sec, dict):
            val = sec.get("value", "")
            stype = sec.get("type", "")
            sfile = sec.get("file", "")
        else:
            val, stype, sfile = str(sec), "", ""
        if stype == "aws_key" or "AKIA" in val:
            ck = _check_aws_key(val)
            if ck.get("valid_format"):
                findings.append({"type": "aws_key_exposed", "severity": "critical",
                                 "description": f"AWS key exposed in {sfile}"})

    if verify:
        for svc in list(services):
            if svc["service"] == "Firebase":
                try:
                    fb = _check_firebase(svc["url"])
                    if fb.get("accessible"):
                        findings.append({"type": "firebase_open", "severity": "critical",
                                         "description": f"Firebase open: {svc['url']}"})
                        svc["accessible"] = True
                        svc["data_preview"] = fb.get("data_preview", "")
                except Exception:
                    pass

    return {"cloud_services": services, "findings": findings, "result": services}


@tool_meta(
    name="finding_aggregator",
    description="Generate structural findings from manifest + obfuscation analysis",
    params={"manifest": "Manifest analysis result", "obfuscation": "Obfuscation detection result"},
    outputs=["findings", "result"],
)
def finding_aggregator(manifest: dict | None = None,
                       obfuscation: dict | None = None, **kwargs) -> dict:
    m = manifest or kwargs.get("manifest", {}) or {}
    o = obfuscation or kwargs.get("obfuscation", {}) or {}
    findings = []
    if m.get("debuggable"):
        findings.append({"type": "debuggable_app", "severity": "high",
                         "description": "App is debuggable"})
    if m.get("allow_backup"):
        findings.append({"type": "allow_backup", "severity": "medium",
                         "description": "App allows ADB backup"})
    if len(m.get("exported_components", [])) > 5:
        findings.append({"type": "many_exported", "severity": "medium",
                         "description": f"{len(m['exported_components'])} exported components"})
    if o.get("obfuscated"):
        findings.append({"type": "obfuscated_code", "severity": "info",
                         "description": f"Obfuscation: {', '.join(o.get('techniques', []))}"})
    return {"findings": findings, "count": len(findings), "result": findings}


# ------------------------------------------------------------------
# PHASE 3: IPC & Component Testing
# ------------------------------------------------------------------

@tool_meta(
    name="component_analyzer",
    description="List all exported activities, services, receivers, providers",
    params={"manifest": "Manifest analysis result"},
    outputs=["components", "exported", "result"],
)
def component_analyzer(manifest: dict | None = None, **kwargs) -> dict:
    m = manifest or kwargs.get("manifest", {}) or {}
    components = []
    for c in m.get("components", []):
        components.append(c)
    exported = m.get("exported_components", [])
    return {"components": components, "exported": exported,
            "count": len(components), "exported_count": len(exported),
            "result": components}


@tool_meta(
    name="deep_link_analyzer",
    description="Extract and analyze deep link URLs from decompiled source",
    params={"input": "Decompiled source directory"},
    outputs=["deep_links", "result"],
)
def deep_link_analyzer(input: str = "", **kwargs) -> dict:
    decompile_dir = input or kwargs.get("input", "")
    deep_links = []
    manifest_candidates = [
        Path(decompile_dir) / "AndroidManifest.xml",
        Path(decompile_dir) / "resources" / "AndroidManifest.xml",
    ]
    for manifest_xml in manifest_candidates:
        if manifest_xml.exists():
            text = manifest_xml.read_text(encoding="utf-8", errors="ignore")
            intent_pat = re.compile(r'android:scheme="([^"]+)".*?android:host="([^"]+)"',
                                     re.DOTALL)
            for m in intent_pat.finditer(text):
                scheme, host = m.group(1), m.group(2)
                deep_links.append(f"{scheme}://{host}")
            scheme_pat = re.compile(r'android:scheme="([^"]+)"')
            host_pat = re.compile(r'android:host="([^"]+)"')
            schemes = scheme_pat.findall(text)
            hosts = host_pat.findall(text)
            min_len = min(len(schemes), len(hosts))
            for i in range(min_len):
                deep_links.append(f"{schemes[i]}://{hosts[i]}")
    return {"deep_links": list(set(deep_links)), "result": list(set(deep_links))}


@tool_meta(
    name="intent_analyzer",
    description="Analyze intent filters and intent redirection patterns",
    params={"input": "Decompiled source directory",
            "components": "List of manifest components"},
    outputs=["intents", "result"],
)
def intent_analyzer(input: str = "", components: list | None = None, **kwargs) -> dict:
    decompile_dir = input or kwargs.get("input", "")
    src_dir = Path(decompile_dir) / "sources"
    intents = []
    if src_dir.exists():
        for f in src_dir.rglob("*.java"):
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if "Intent" in text and ("getIntent" in text or "new Intent" in text):
                intents.append({"file": str(f.relative_to(src_dir)),
                                "has_get_intent": "getIntent" in text,
                                "has_new_intent": "new Intent" in text})
    pending_intents = [i for i in intents
                       if i.get("has_pending_intent") or "FLAG_GRANT" in str(i)]
    return {"intents": intents, "pending_intent_count": len(pending_intents),
            "result": intents}


# ------------------------------------------------------------------
# PHASE 4: Dynamic Analysis & Network
# ------------------------------------------------------------------

@tool_meta(
    name="frida",
    description="Run Frida script against a target package",
    params={"package": "Android package name", "script": "Path to Frida JS script"},
    outputs=["output", "result"],
)
def frida(package: str = "", script: str = "", **kwargs) -> dict:
    from tools.android_tools import run_frida_script, unpin_certificate
    package = package or kwargs.get("package", "")
    script = script or kwargs.get("script", "")
    if script:
        output = run_frida_script(package, script)
    else:
        output = unpin_certificate(package)
    return {"output": output[:2000], "result": output[:2000]}


@tool_meta(
    name="android_proxy",
    description="Set or remove Android emulator HTTP proxy",
    params={"action": "set|remove|status", "port": "Proxy port (default 8080)"},
    outputs=["status", "result"],
)
def android_proxy(action: str = "status", port: int = 8080, **kwargs) -> dict:
    from tools.android_tools import set_proxy, remove_proxy
    action = action or kwargs.get("action", "status")
    if action == "set":
        out = set_proxy(port=port)
        return {"status": "set", "result": out}
    elif action == "remove":
        out = remove_proxy()
        return {"status": "removed", "result": out}
    return {"status": "unknown", "result": ""}


@tool_meta(
    name="traffic_capturer",
    description="Capture HTTP/HTTPS traffic via Burp proxy",
    params={"target_id": "Target ID in storage", "duration": "Capture duration in seconds",
            "source": "burp or mitmproxy"},
    outputs=["requests", "result"],
)
def traffic_capturer(target_id: int = 0, duration: int = 60, source: str = "burp",
                     **kwargs) -> dict:
    import time
    from burp_mcp.client import BurpClient
    target_id = target_id or kwargs.get("target_id", 0)
    if source == "burp":
        client = BurpClient()
        client.connect()
        before = client.get_proxy_http_history(offset=0, count=100)
        time.sleep(duration)
        after = client.get_proxy_http_history(offset=0, count=100)
        client.close()
        new_entries = []
        before_ids = {json.dumps(e.get("request", {}), sort_keys=True) for e in before}
        for entry in after:
            if json.dumps(entry.get("request", {}), sort_keys=True) not in before_ids:
                new_entries.append(entry)
        return {"requests": new_entries, "count": len(new_entries), "result": new_entries}
    return {"requests": [], "count": 0, "result": []}


@tool_meta(
    name="api_discovery",
    description="Extract API endpoints from captured HTTP traffic",
    params={"requests": "List of captured HTTP requests"},
    outputs=["endpoints", "result"],
)
def api_discovery(requests: list | None = None, **kwargs) -> dict:
    reqs = requests or kwargs.get("requests", []) or []
    endpoints = []
    seen = set()
    for req in reqs:
        request = req.get("request", {}) if isinstance(req, dict) else {}
        url = request.get("url", "") if isinstance(request, dict) else ""
        method = request.get("method", "GET") if isinstance(request, dict) else "GET"
        if url and url not in seen:
            seen.add(url)
            parsed = {"url": url, "method": method}
            if "api" in url.lower():
                parsed["category"] = "api"
            endpoints.append(parsed)
    return {"endpoints": endpoints, "count": len(endpoints), "result": endpoints}


@tool_meta(
    name="websocket_checker",
    description="Check for WebSocket connections in captured traffic",
    params={"requests": "List of captured HTTP requests"},
    outputs=["websockets", "result"],
)
def websocket_checker(requests: list | None = None, **kwargs) -> dict:
    reqs = requests or kwargs.get("requests", []) or []
    ws_connections = []
    for req in reqs:
        if isinstance(req, dict):
            url = ""
            for key in ("url", "request", "host"):
                val = req.get(key)
                if isinstance(val, dict):
                    url = val.get("url", "")
                elif isinstance(val, str):
                    url = val
                if url:
                    break
            if "ws" in str(url).lower() or "websocket" in str(url).lower():
                ws_connections.append({"url": url, "type": "websocket"})
    return {"websockets": ws_connections, "count": len(ws_connections),
            "result": ws_connections}


# ------------------------------------------------------------------
# PHASE 5: Local Storage
# ------------------------------------------------------------------

@tool_meta(
    name="shared_prefs_analyzer",
    description="Extract and analyze SharedPreferences XML via ADB",
    params={"package": "Android package name"},
    outputs=["files", "result"],
)
def shared_prefs_analyzer(package: str = "", **kwargs) -> dict:
    from tools.android_tools import run_adb
    package = package or kwargs.get("package", "")
    prefs_dir = f"/data/data/{package}/shared_prefs"
    result = run_adb(["shell", f"run-as {package} ls {prefs_dir}"], timeout=10)
    files = [l.strip() for l in result.stdout.strip().split("\n") if l.strip() and l.strip() != "ls:"]
    prefs = []
    for fname in files:
        if fname.endswith(".xml"):
            content = run_adb(["shell", f"run-as {package} cat {prefs_dir}/{fname}"], timeout=10)
            prefs.append({"file": fname, "content": content.stdout[:1000]})
    return {"files": files, "preferences": prefs, "result": prefs}


@tool_meta(
    name="sqlite_analyzer",
    description="Extract and analyze local SQLite databases via ADB",
    params={"package": "Android package name"},
    outputs=["databases", "result"],
)
def sqlite_analyzer(package: str = "", **kwargs) -> dict:
    from tools.android_tools import run_adb
    package = package or kwargs.get("package", "")
    db_dir = f"/data/data/{package}/databases"
    result = run_adb(["shell", f"run-as {package} ls {db_dir}"], timeout=10)
    files = [l.strip() for l in result.stdout.strip().split("\n") if l.strip() and l.strip() != "ls:"]
    dbs = []
    for fname in files:
        if fname.endswith(".db") or fname.endswith(".sqlite"):
            dbs.append({"file": fname, "path": f"{db_dir}/{fname}"})
    return {"databases": dbs, "count": len(dbs), "result": dbs}


@tool_meta(
    name="file_system_analyzer",
    description="List app files and caches for sensitive data",
    params={"package": "Android package name"},
    outputs=["files", "result"],
)
def file_system_analyzer(package: str = "", **kwargs) -> dict:
    from tools.android_tools import run_adb
    package = package or kwargs.get("package", "")
    dirs = ["", "cache", "files", "code_cache", "no_backup"]
    all_files = []
    for sub in dirs:
        target = f"/data/data/{package}/{sub}" if sub else f"/data/data/{package}"
        result = run_adb(["shell", f"run-as {package} ls -R {target}"], timeout=10)
        lines = [l.strip() for l in result.stdout.strip().split("\n") if l.strip() and l.strip() != "ls:"]
        for line in lines:
            if "." in line and not line.endswith(":"):
                all_files.append({"path": f"{target}/{line}", "directory": sub or "root"})
    return {"files": all_files, "count": len(all_files), "result": all_files}


@tool_meta(
    name="keystore_analyzer",
    description="Check Android Keystore usage and implementation",
    params={"input": "Decompiled source directory", "package": "Android package name"},
    outputs=["keystore_usage", "result"],
)
def keystore_analyzer(input: str = "", package: str = "", **kwargs) -> dict:
    decompile_dir = input or kwargs.get("input", "")
    src_dir = Path(decompile_dir) / "sources"
    usage = []
    if src_dir.exists():
        ks_pat = re.compile(r'(KeyStore|KeyPairGenerator|Signature)\b')
        for f in src_dir.rglob("*.java"):
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for m in ks_pat.finditer(text):
                usage.append({"file": str(f.relative_to(src_dir)),
                              "type": m.group(1)})
    return {"keystore_usage": usage, "count": len(usage), "result": usage}


# ------------------------------------------------------------------
# PHASE 6: Backend API Testing
# ------------------------------------------------------------------

@tool_meta(
    name="domain_extractor",
    description="Extract unique domains from endpoints and traffic",
    params={"endpoints": "List of endpoints", "traffic": "List of captured traffic"},
    outputs=["domains", "result"],
)
def domain_extractor(endpoints: list | None = None,
                     traffic: list | None = None, **kwargs) -> dict:
    from urllib.parse import urlparse
    ep_list = endpoints or kwargs.get("endpoints", []) or []
    tr_list = traffic or kwargs.get("traffic", []) or []
    urls = []
    for e in ep_list:
        if isinstance(e, dict):
            urls.append(e.get("value", e.get("url", "")))
        else:
            urls.append(str(e))
    for t in tr_list:
        if isinstance(t, dict):
            req = t.get("request", t)
            if isinstance(req, dict):
                urls.append(req.get("url", ""))
    domains = set()
    for u in urls:
        try:
            p = urlparse(u)
            if p.hostname:
                domains.add(p.hostname)
        except Exception:
            continue
    return {"domains": sorted(domains), "result": sorted(domains)}


@tool_meta(
    name="subfinder",
    description="Passive subdomain enumeration with subfinder in WSL2",
    params={"domain": "Target domain or list of domains"},
    outputs=["subdomains", "result"],
)
def subfinder(domain: str = "", max_domains: int = 10, **kwargs) -> dict:
    from tools.recon import run_subfinder
    domain = domain or kwargs.get("domain") or kwargs.get("domains", "")
    if isinstance(domain, str) and "," in domain:
        domain = [d.strip() for d in domain.split(",") if d.strip()]
    if isinstance(domain, str):
        domains = [domain] if domain else []
    else:
        domains = [str(d) for d in domain if d]
    if len(domains) > max_domains:
        logger.info("subfinder: capping %d domains -> %d",
                    len(domains), max_domains)
        domains = domains[:max_domains]

    subs: set = set()
    for d in domains:
        try:
            subs.update(run_subfinder(d))
        except Exception as exc:
            logger.warning("subfinder failed for %s: %s", d, exc)
        if d:
            subs.add(d)  # apex domain is always worth probing
    merged = sorted(subs)

    storage: StorageManager | None = kwargs.get("_storage")
    target_id = kwargs.get("_target_id")
    if storage and target_id and merged:
        try:
            storage.add_subdomains(target_id, merged, source="subfinder",
                                   run_id=kwargs.get("_run_id"))
        except Exception as exc:
            logger.warning("subdomain persist failed: %s", exc)

    return {"subdomains": merged, "count": len(merged), "result": merged}


@tool_meta(
    name="httpx",
    description="HTTP probing and tech detection with httpx in WSL2",
    params={"targets": "List of target subdomains/URLs"},
    outputs=["hosts", "result"],
)
def httpx(targets: list | None = None, **kwargs) -> dict:
    from tools.recon import run_httpx
    t = targets or kwargs.get("targets", []) or []
    t_str = []
    for item in t:
        if isinstance(item, dict):
            t_str.append(item.get("domain", item.get("url", "")))
        else:
            t_str.append(str(item))
    hosts = run_httpx(t_str)
    urls = [h.get("url", "") for h in hosts if h.get("url")]
    return {"hosts": hosts, "urls": urls, "count": len(hosts), "result": hosts}


@tool_meta(
    name="nuclei",
    description="Vulnerability scanning with nuclei in WSL2",
    params={"targets": "List of target URLs", "severity": "Severity filter"},
    outputs=["findings", "result"],
)
def nuclei(targets: list | None = None, severity: str = "", **kwargs) -> dict:
    from tools.recon import run_nuclei
    t = targets or kwargs.get("targets", []) or []
    t_str = [str(item) for item in t]
    findings = run_nuclei(t_str, severity=severity or kwargs.get("severity", ""))

    storage: StorageManager | None = kwargs.get("_storage")
    target_id = kwargs.get("_target_id")
    if storage and target_id and findings:
        try:
            rows = []
            for item in findings:
                info = item.get("info", {}) if isinstance(item, dict) else {}
                rows.append({
                    "type": "nuclei",
                    "severity": str(info.get("severity", "info")).lower(),
                    "title": info.get("name", item.get("template-id", "nuclei finding")),
                    "description": (info.get("description", "")
                                    or item.get("template-id", ""))[:1000],
                    "evidence": json.dumps(item, ensure_ascii=False)[:2000],
                    "url": item.get("matched-at", ""),
                    "source": "nuclei",
                })
            storage.add_findings_bulk(target_id, rows, run_id=kwargs.get("_run_id"))
        except Exception as exc:
            logger.warning("nuclei persist failed: %s", exc)

    return {"findings": findings, "count": len(findings), "result": findings}


@tool_meta(
    name="api_fuzzer",
    description="Fuzz API endpoints for common vulnerabilities",
    params={"endpoints": "List of endpoints to fuzz",
            "payloads": "Dict of payload_type to wordlist path"},
    outputs=["results", "result"],
)
def api_fuzzer(endpoints: list | None = None,
               payloads: dict | None = None, **kwargs) -> dict:
    from tools.fuzzing import fuzz_get_param, get_payloads
    ep_list = endpoints or kwargs.get("endpoints", []) or []
    if isinstance(ep_list, dict):
        ep_list = ep_list.get("result", ep_list.get("urls", []))
    pl = payloads or kwargs.get("payloads", {})
    all_results = []
    for ep in ep_list:
        url = ep.get("value", ep.get("url", "")) if isinstance(ep, dict) else str(ep)
        if not url:
            continue
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys()) or ["q"]
        custom_types = [k for k in (pl or {})] if isinstance(pl, dict) else []
        payload_types = custom_types or ("xss", "sqli")
        for ptype in payload_types:
            payload_path = pl.get(ptype, "") if isinstance(pl, dict) else ""
            payload_list = get_payloads(ptype) if not payload_path else []
            if payload_path:
                try:
                    from pathlib import Path
                    payload_list = [l.strip() for l in Path(payload_path).read_text().splitlines() if l.strip()]
                except Exception:
                    payload_list = get_payloads(ptype)
            for param_name in params:
                results = fuzz_get_param(url, param_name, payload_type=ptype,
                                          payloads=payload_list, use_burp=False)
                for r in results:
                    all_results.append({
                        "url": url, "param": param_name, "type": ptype,
                        "payload": r.payload, "status": r.status_code,
                        "interesting": r.is_interesting, "reason": r.reason,
                    })
    interesting = [r for r in all_results if r.get("interesting")]

    storage: StorageManager | None = kwargs.get("_storage")
    target_id = kwargs.get("_target_id")
    if storage and target_id and all_results:
        try:
            storage.add_fuzz_results(target_id, all_results,
                                     run_id=kwargs.get("_run_id"))
        except Exception as exc:
            logger.warning("fuzz persist failed: %s", exc)

    return {"results": interesting, "count": len(interesting),
            "total_fuzzed": len(all_results), "result": interesting}


@tool_meta(
    name="auth_tester",
    description="Test authentication and authorization on endpoints",
    params={"endpoints": "List of endpoints", "traffic": "Captured traffic"},
    outputs=["findings", "result"],
)
def auth_tester(endpoints: list | None = None,
                traffic: list | None = None, **kwargs) -> dict:
    from tools.http_tools import send_http
    ep_list = endpoints or kwargs.get("endpoints", []) or []
    if isinstance(ep_list, dict):
        ep_list = ep_list.get("result", ep_list.get("endpoints", []))
    findings = []
    sensitive_paths = ["admin", "dashboard", "api/admin", "config", "debug",
                       ".env", "backup", "wp-admin"]
    for ep in ep_list:
        url = ep.get("value", ep.get("url", "")) if isinstance(ep, dict) else str(ep)
        if not url:
            continue
        for path in sensitive_paths:
            test_url = f"{url.rstrip('/')}/{path}"
            resp = send_http("GET", test_url, use_burp=False)
            if resp and resp.get("status_code") in (200, 201, 403):
                findings.append({
                    "url": test_url, "status": resp["status_code"],
                    "type": "auth_bypass",
                    "severity": "high" if resp["status_code"] == 200 else "medium",
                    "evidence": f"HTTP {resp['status_code']} without auth header",
                })
    return {"findings": findings, "count": len(findings), "result": findings}


# ------------------------------------------------------------------
# PHASE 7: Advanced Testing
# ------------------------------------------------------------------

@tool_meta(
    name="webview_analyzer",
    description="Analyze WebView configurations and JS interfaces",
    params={"input": "Decompiled source directory"},
    outputs=["webviews", "result"],
)
def webview_analyzer(input: str = "", **kwargs) -> dict:
    decompile_dir = input or kwargs.get("input", "")
    src_dir = Path(decompile_dir) / "sources"
    webviews = []
    if src_dir.exists():
        wv_pat = re.compile(r'(WebView|WebChromeClient|WebViewClient)\b')
        js_pat = re.compile(r'addJavascriptInterface\s*\(')
        js_enabled = re.compile(r'getSettings\(\).*setJavaScriptEnabled\s*\(\s*true\s*\)',
                                re.DOTALL)
        for f in src_dir.rglob("*.java"):
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if wv_pat.search(text):
                entry = {"file": str(f.relative_to(src_dir))}
                if js_pat.search(text):
                    entry["js_interface"] = True
                if js_enabled.search(text):
                    entry["js_enabled"] = True
                webviews.append(entry)
    return {"webviews": webviews, "count": len(webviews), "result": webviews}


@tool_meta(
    name="js_interface_tester",
    description="Test JavaScript bridge for RCE and data leakage",
    params={"input": "Decompiled source directory",
            "webviews": "List of WebView analysis results"},
    outputs=["vulnerable", "result"],
)
def js_interface_tester(input: str = "", webviews: list | None = None, **kwargs) -> dict:
    wv_list = webviews or kwargs.get("webviews", []) or []
    vulnerable = [w for w in wv_list if w.get("js_interface") and w.get("js_enabled")]
    return {
        "vulnerable": vulnerable,
        "count": len(vulnerable),
        "result": vulnerable,
    }


@tool_meta(
    name="crypto_analyzer",
    description="Analyze cryptographic implementations for weaknesses",
    params={"input": "Decompiled source directory"},
    outputs=["weak_crypto", "result"],
)
def crypto_analyzer(input: str = "", **kwargs) -> dict:
    decompile_dir = input or kwargs.get("input", "")
    src_dir = Path(decompile_dir) / "sources"
    weak = []
    if src_dir.exists():
        weak_patterns = [
            ("MD5", re.compile(r'MessageDigest.*MD5')),
            ("SHA1", re.compile(r'MessageDigest.*SHA-?1')),
            ("DES", re.compile(r'DES/|DES\b')),
            ("RC4", re.compile(r'RC4')),
            ("ECB", re.compile(r'AES/ECB/')),
            ("Static IV", re.compile(r'IvParameterSpec.*new byte\[\]')),
            ("Hardcoded Key", re.compile(r'SecretKeySpec.*new byte\[\]')),
        ]
        for f in src_dir.rglob("*.java"):
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for name, pat in weak_patterns:
                if pat.search(text):
                    weak.append({"algorithm": name, "file": str(f.relative_to(src_dir))})
    return {"weak_crypto": weak, "count": len(weak), "result": weak}


@tool_meta(
    name="backup_tester",
    description="Test ADB backup and auto-backup configurations",
    params={"package": "Android package name", "allow_backup": "From manifest analysis"},
    outputs=["backup_possible", "result"],
)
def backup_tester(package: str = "", allow_backup: bool = False, **kwargs) -> dict:
    from tools.android_tools import run_adb
    package = package or kwargs.get("package", "")
    ab = allow_backup or kwargs.get("allow_backup", False)
    result = {"allow_backup": bool(ab), "package": package}
    if ab:
        try:
            out = run_adb(["backup", "-f", "backup.ab", package], timeout=15)
            result["adb_backup_tried"] = True
            result["adb_backup_output"] = out.stdout[:200]
        except Exception as e:
            result["adb_backup_error"] = str(e)
    return {"backup_possible": bool(ab), "result": result}


# ------------------------------------------------------------------
# PHASE 8: Reporting
# ------------------------------------------------------------------

@tool_meta(
    name="sast_scan",
    description="Rule-based SAST over decompiled sources (TLS, crypto, WebView, IPC, injection)",
    params={"input": "Decompiled source directory"},
    outputs=["findings", "summary", "result"],
)
def sast_scan(input: str = "", include_third_party: bool = False,
              **kwargs) -> dict:
    from tools.sast import scan_source, summarize
    decompile_dir = input or kwargs.get("input", "")
    findings = scan_source(
        decompile_dir,
        exclude_prefixes=() if include_third_party else None)
    summary = summarize(findings)

    storage: StorageManager | None = kwargs.get("_storage")
    target_id = kwargs.get("_target_id")
    if storage and target_id:
        try:
            # replace previous sast run for this target (idempotent)
            storage._execute(
                "DELETE FROM findings WHERE target_id=? AND source='sast'",
                (target_id,))
            storage._conn.commit()
            rows = []
            for f in findings:
                ev = f"{f['file']}:{f['line']}\n  {f['snippet']}"
                if f.get("exported_component"):
                    ev += f"\n  exported_component: {f['exported_component']}"
                if f.get("note"):
                    ev += f"\n  note: {f['note']}"
                rows.append({
                    "type": f"sast:{f['rule']}",
                    "severity": f["severity"],
                    "title": f["title"],
                    "description": f["description"][:1000],
                    "evidence": ev,
                    "url": f"sources/{f['file']}:{f['line']}",
                    "source": "sast",
                })
            storage.add_findings_bulk(target_id, rows,
                                      run_id=kwargs.get("_run_id"))
        except Exception as exc:
            logger.warning("sast persist failed: %s", exc)

    return {"findings": findings, "summary": summary,
            "count": len(findings), "result": findings}


@tool_meta(
    name="report_generator",
    description="Generate markdown/JSON pentest report from storage",
    params={"target_id": "Target ID", "format": "markdown or json",
            "output": "Output file path"},
    outputs=["report_path", "result"],
)
def report_generator(target_id: int = 0, format: str = "markdown",
                     output: str = "", **kwargs) -> dict:
    storage: StorageManager = kwargs.get("_storage")
    target_id = target_id or kwargs.get("target_id", 0)
    if not storage:
        raise ValueError("_storage required for report_generator")
    if format == "json":
        report = storage.export_json(target_id)
    else:
        report = storage.generate_report(target_id)

    report_path = output
    if output:
        p = Path(output)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(report, encoding="utf-8")
        report_path = str(p.resolve())

    # Always materialize INDEX/recon/source artifacts (opencode-readable).
    artifacts: dict = {}
    try:
        from tools.recon_artifacts import write_target_artifacts
        artifacts = write_target_artifacts(target_id, storage=storage)
    except Exception as exc:
        logger.warning("recon artifacts failed: %s", exc)

    return {"report": report, "report_path": report_path, "format": format,
            "artifacts": artifacts, "result": report}
