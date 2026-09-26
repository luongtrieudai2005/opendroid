"""SAST engine for decompiled Android sources (jadx output).

Rule-based static analysis over ``<jadx>/sources/**/*.java`` plus manifest
level checks (exported components, deep links, debuggable/backup/cleartext).

Design:
  - Every rule carries a literal ``trigger`` for a fast pre-filter
    (skip file entirely when the trigger string is absent) — keeps scans of
    50k+ file trees fast.
  - Multi-stage checks (intent redirection, trust-all TLS, WebView SSL
    errors) run as custom checkers.
  - Findings are deduped per (rule, file, line) and capped at first match
    per rule per file to control noise.

Usage::

    from tools.sast import scan_source
    findings = scan_source("workspace/jadx/com.example.app")
"""

import logging
import os
import re
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Rule model
# ------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str            # critical | high | medium | low | info
    category: str
    trigger: str             # literal pre-filter ("" = always run)
    pattern: str             # regex (re.MULTILINE)
    description: str
    flags: int = re.MULTILINE
    file_filter: str = ""    # regex that the relative file path must match


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# ------------------------------------------------------------------
# Rules (Android SAST)
# ------------------------------------------------------------------

RULES: list[Rule] = [
    # ---- TLS / crypto ----
    Rule("tls_trust_all_manager", "Trust-all X509TrustManager",
         "critical", "tls", "checkServerTrusted",
         r"checkServerTrusted\s*\(\s*[^)]*\)\s*(throws\s+[\w.,\s]+)?\{\s*(return\s*;)?\s*\}",
         "checkServerTrusted() has an empty body — every server certificate "
         "is accepted, disabling TLS authentication."),
    Rule("tls_hostname_all", "HostnameVerifier accepts any host",
         "critical", "tls", "HostnameVerifier",
         r"verify\s*\(\s*String\s+\w+\s*,\s*[\w.$<>\[\]]+\s+\w+\s*\)"
         r"\s*\{\s*return\s+true\s*;?\s*\}",
         "HostnameVerifier.verify() always returns true — certificate "
         "hostname mismatch attacks succeed."),
    Rule("tls_no_validation", "X509TrustManager implemented without validation",
         "high", "tls", "X509TrustManager",
         r"class\s+\w+\s+implements\s+[^{]*X509TrustManager",
         "Custom X509TrustManager — verify it does not bypass certificate "
         "validation (paired checks: checkServerTrusted/checkClientTrusted)."),
    Rule("tls_legacy_protocol", "Legacy TLS protocol forced",
         "medium", "tls", "SSLContext.getInstance",
         r"SSLContext\.getInstance\(\s*\"(SSLv3|TLSv1|TLSv1\.1)\"",
         "Uses SSLv3/TLSv1(1) — deprecated, downgrade/vuln-prone protocols."),
    Rule("ssl_error_proceed", "WebView SSL error ignored",
         "critical", "tls", "onReceivedSslError",
         r"onReceivedSslError\s*\([^)]*\)\s*\{[^}]*\.proceed\s*\(\s*\)",
         "onReceivedSslError calls handler.proceed() — certificate errors "
         "are ignored in WebView.", re.MULTILINE | re.DOTALL),
    Rule("crypto_ecb", "ECB cipher mode",
         "medium", "crypto", "AES/ECB",
         r"\"AES/ECB/[^\"]*\"",
         "ECB mode leaks plaintext structure — use GCM/CBC with random IV."),
    Rule("crypto_weak_algo", "Weak crypto algorithm",
         "medium", "crypto", "SecretKeySpec",
         r"\"(DES|DESede|RC4|ARC4|PBEWithMD5AndDES)\"",
         "Weak algorithm (DES/3DES/RC4) referenced — consider AES-GCM."),
    Rule("crypto_static_iv", "Static/zero IV",
         "medium", "crypto", "IvParameterSpec",
         r"IvParameterSpec\s*\(\s*(new\s+byte\s*\[[^\]]*\]|\"[^\"]{0,16}\"|"
         r"[A-Za-z_]?\w*(?:zero|static|DEFAULT_IV|FIXED|fixedIv)\w*)",
         "IvParameterSpec built from a fixed/zero IV — IV must be unique "
         "per encryption.", re.MULTILINE | re.IGNORECASE),
    Rule("crypto_hardcoded_key", "Hardcoded secret key",
         "high", "crypto", "SecretKeySpec",
         r"SecretKeySpec\s*\(\s*\"[^\"]{8,}\"",
         "SecretKeySpec initialized with an inline string key — key is "
         "recoverable from the binary."),
    Rule("crypto_weak_random", "java.util.Random for security values",
         "low", "crypto", "new Random",
         r"new\s+Random\s*\(\s*\)",
         "java.util.Random is predictable — use SecureRandom for "
         "tokens/keys/nonces.", re.MULTILINE,
         file_filter=r"(?i)(key|token|auth|session|secret|secure|login|sign|nonce|otp)"),

    Rule("crypto_weak_hash", "Weak hash algorithm",
         "medium", "crypto", "MessageDigest.getInstance",
         r"MessageDigest\.getInstance\s*\(\s*\"(MD5|SHA-?1)\"",
         "MD5/SHA-1 used for hashing — collision-prone; use SHA-256+ for "
         "integrity/signing.", re.MULTILINE,
         file_filter=r"(?i)(hash|digest|sign|checksum|signature|password|token|fingerprint)"),

    # ---- Injection ----
    Rule("sql_injection", "SQLite query built by concatenation",
         "high", "injection", "",
         r"(rawQuery|execSQL)\s*\(\s*([^;]*?)(\+\s*\w+|String\.format)",
         "Query string is built by concatenation — check whether the "
         "concatenated value is attacker- or IPC-controlled (a type-constrained "
         "long/int lowers impact; a String/selection is exploitable)."),
    Rule("cmd_injection", "Shell command built by concatenation",
         "high", "injection", ".exec(",
         r"Runtime\.getRuntime\(\)\.exec\s*\(\s*[^;]*\+",
         "Command line is concatenated with variable data — command "
         "injection risk."),
    Rule("path_traversal", "File path concatenated with input",
         "medium", "injection", "",
         r"(openFileInput|openFileOutput|new\s+File\s*\()\s*\(\s*[^;]*\+",
         "File path built by concatenation — path traversal risk if input "
         "is attacker-controlled."),

    # ---- WebView ----
    Rule("webview_js_interface", "addJavascriptInterface exposed",
         "high", "webview", "addJavascriptInterface",
         r"addJavascriptInterface\s*\(",
         "JavaScript bridge exposed to page content — review reachable "
         "methods (RCE/phone-home risk on untrusted content)."),
    Rule("webview_file_access", "WebView file access enabled",
         "high", "webview", "setAllowFileAccess",
         r"setAllow(FileAccessFromFileURLs|UniversalAccessFromFileURLs)\s*\(\s*true",
         "WebView allows file:// JS access — local file exfiltration from "
         "injected/attacker JS."),
    Rule("webview_mixed_content", "WebView mixed content allowed",
         "medium", "webview", "setMixedContentMode",
         r"setMixedContentMode\s*\(\s*(MIXED_CONTENT_ALWAYS_ALLOW|0)\b",
         "Mixed HTTP content allowed on HTTPS pages — MITM of subresources."),
    Rule("webview_js_enabled", "WebView JavaScript enabled",
         "low", "webview", "setJavaScriptEnabled",
         r"setJavaScriptEnabled\s*\(\s*true\s*\)",
         "JS enabled in WebView — increases impact of any XSS/injection."),

    # ---- IPC / intents ----
    Rule("pending_intent_mutable", "Mutable PendingIntent (no FLAG_IMMUTABLE)",
         "medium", "ipc", "PendingIntent.",
         r"PendingIntent\.get\w+\s*\((?![^;]*FLAG_IMMUTABLE)[^;]*\)\s*;",
         "PendingIntent created without FLAG_IMMUTABLE — receivers can "
         "modify the wrapped Intent (fill-in attack)."),
    Rule("intent_redirection", "Intent redirection (untrusted Intent forwarded)",
         "high", "ipc", "getParcelableExtra",
         r"__custom_intent_redirection__",
         "An Intent from getParcelableExtra is forwarded via "
         "startActivity/startService — intent redirection / confused deputy."),
    Rule("webview_load_untrusted", "WebView loads data from Intent URI",
         "medium", "webview", "getIntent()",
         r"loadUrl\s*\(\s*[^;]*?(getDataString|getData|getIntent)",
         "WebView URL comes from the launching Intent — attacker-controlled "
         "content if the component is exported."),

    # ---- Secrets / data ----
    Rule("creds_in_url", "Credentials embedded in URL",
         "high", "secrets", "://",
         r"https?://[^\s\"'@/]+:[^\s\"'@/]+@",
         "user:password@ in URL — credentials leak via logs/proxies."),
    Rule("log_sensitive", "Sensitive value logged",
         "low", "logging", "Log.",
         r"Log\.[dive]\s*\([^;]*?\b(password|passwd|token|secret|api[_-]?key|authorization)\b",
         "Log call includes a sensitive variable — data leak via logcat."),
    Rule("cleartext_ws", "Cleartext WebSocket URL",
         "low", "network", "ws://",
         r"\"ws://[^\s\"]+\"",
         "Unencrypted ws:// endpoint — traffic readable/modifiable."),

    # ---- Storage ----
    Rule("world_readable_mode", "World-readable/writable file mode",
         "medium", "storage", "MODE_WORLD",
         r"MODE_WORLD_(READABLE|WRITEABLE)",
         "MODE_WORLD_* exposes app data to other apps (deprecated/insecure)."),
    Rule("shared_prefs_clear", "Sensitive data stored in SharedPreferences as plaintext",
         "medium", "storage", "SharedPreferences",
         r"(putString|putInt|putLong)\s*\(\s*\"[^\"]*(token|password|secret|session|auth)[^\"]*\"",
         "Sensitive value persisted via SharedPreferences — readable by "
         "root/backup extraction; consider EncryptedSharedPreferences."),
]


# ------------------------------------------------------------------
# Custom multi-stage checkers
# ------------------------------------------------------------------

def _check_intent_redirection(rel: str, text: str) -> list[dict]:
    """Untrusted Intent extra forwarded to a privileged API."""
    if "getParcelableExtra" not in text:
        return []
    # Collect variable names assigned from getParcelableExtra (Intent kind).
    vars_found = set(re.findall(
        r"(?:Intent|android\.content\.Intent)\s+(\w+)\s*=\s*[^;]*getParcelableExtra", text))
    if not vars_found:
        # chained form: x = getIntent().getParcelableExtra(...)
        vars_found = set(re.findall(r"(\w+)\s*=\s*[^;]{0,120}getParcelableExtra", text))
    out = []
    for v in sorted(vars_found):
        if v in ("null", "true", "false"):
            continue
        m = re.search(
            r"(startActivity|startActivities|startService|startForegroundService|"
            r"sendBroadcast|sendOrderedBroadcast)\s*\(\s*" + re.escape(v) + r"\b", text)
        if m:
            line = text[:m.start()].count("\n") + 1
            out.append({
                "rule": "intent_redirection", "line": line,
                "snippet": _snippet(text, m.start()),
                "detail": f"var '{v}' from getParcelableExtra passed to {m.group(1)}()",
            })
            break  # one finding per file is enough
    return out


CUSTOM_CHECKS = [
    _check_intent_redirection,
]


def _snippet(text: str, pos: int, width: int = 160) -> str:
    start = text.rfind("\n", 0, max(0, pos - width)) + 1
    end = text.find("\n", min(len(text), pos + width))
    if end == -1:
        end = len(text)
    return text[start:end].strip()[:width]


# ------------------------------------------------------------------
# File scanning
# ------------------------------------------------------------------

_RULE_SPEC: list[tuple] = []  # (id, title, severity, category, trigger, pattern, desc, flags)


def _rule_spec() -> list[tuple]:
    if not _RULE_SPEC:
        for r in RULES:
            _RULE_SPEC.append((r.id, r.title, r.severity, r.category,
                               r.trigger, r.pattern, r.description, r.flags,
                               r.file_filter))
    return _RULE_SPEC


def _scan_files(args: tuple) -> list[dict]:
    """Worker: scan a chunk of files. Top-level for pickling (spawn)."""
    base_str, rels = args
    base = Path(base_str)
    compiled = [(rid, title, sev, cat, trig, re.compile(pat, fl), desc, ff)
                for rid, title, sev, cat, trig, pat, desc, fl, ff in _rule_spec()]
    results: list[dict] = []
    for rel in rels:
        path = base / rel
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for rid, title, sev, cat, trig, rx, desc, ff in compiled:
            if trig and trig not in text:
                continue
            if ff and not re.search(ff, rel):
                continue
            m = rx.search(text)
            if not m:
                continue
            results.append({
                "rule": rid, "title": title, "severity": sev, "category": cat,
                "description": desc, "line": text[:m.start()].count("\n") + 1,
                "snippet": _snippet(text, m.start()), "file": rel,
            })
        for check in CUSTOM_CHECKS:
            for hit in check(rel, text):
                rule = next((r for r in RULES if r.id == hit["rule"]), None)
                if not rule:
                    continue
                results.append({
                    "rule": rule.id, "title": rule.title,
                    "severity": rule.severity, "category": rule.category,
                    "description": rule.description + " " + hit.get("detail", ""),
                    "line": hit["line"], "snippet": hit["snippet"], "file": rel,
                })
    return results


# ------------------------------------------------------------------
# Manifest-level checks
# ------------------------------------------------------------------

_COMP_TAGS = ("activity", "service", "receiver", "provider")


def scan_manifest(decompile_dir: str) -> list[dict]:
    """Static checks straight from AndroidManifest.xml."""
    out: list[dict] = []
    manifest_path = None
    for cand in (Path(decompile_dir) / "resources" / "AndroidManifest.xml",
                 Path(decompile_dir) / "AndroidManifest.xml"):
        if cand.exists():
            manifest_path = cand
            break
    if not manifest_path:
        return out
    text = manifest_path.read_text(encoding="utf-8", errors="ignore")
    rel = str(manifest_path.relative_to(decompile_dir))

    def add(rule: str, line: int, snippet: str, detail: str,
            title: str, severity: str, category: str, desc: str):
        out.append({"rule": rule, "title": title, "severity": severity,
                    "category": category, "description": desc + " " + detail,
                    "line": line, "snippet": snippet[:160], "file": rel})

    def owner(pos: int) -> str:
        """Nearest enclosing component name before offset."""
        head = text[:pos]
        m = None
        for cm in re.finditer(
                r"<(activity|activity-alias|service|receiver|provider)\b[^>]*"
                r'android:name="([^"]+)"', head):
            m = cm
        return m.group(2) if m else "?"

    # application-level flags
    if 'android:debuggable="true"' in text:
        line = text[:text.index('android:debuggable="true"')].count("\n") + 1
        add("manifest_debuggable", line, "android:debuggable=\"true\"", "",
            "App debuggable", "high", "manifest",
            "android:debuggable=true — arbitrary code/DB inspection via run-as.")
    if 'android:allowBackup="true"' in text:
        line = text[:text.index('android:allowBackup="true"')].count("\n") + 1
        add("manifest_allow_backup", line, "android:allowBackup=\"true\"", "",
            "ADB backup allowed", "medium", "manifest",
            "allowBackup=true — app data extractable via adb backup.")
    if 'android:usesCleartextTraffic="true"' in text:
        line = text[:text.index('android:usesCleartextTraffic="true"')].count("\n") + 1
        add("manifest_cleartext", line, "android:usesCleartextTraffic=\"true\"", "",
            "Cleartext traffic permitted", "medium", "manifest",
            "usesCleartextTraffic=true — HTTP allowed app-wide.")

    # per-component: exported without permission guard
    for tag in _COMP_TAGS:
        for m in re.finditer(r"<" + tag + r"\b([^>]*?)/?>", text):
            attrs = m.group(1)
            nm = re.search(r'android:name="([^"]+)"', attrs)
            if not nm:
                continue
            exported = 'android:exported="true"' in attrs
            guarded = ('android:permission="' in attrs
                       or 'android:readPermission="' in attrs
                       or 'android:writePermission="' in attrs)
            if exported and not guarded:
                line = text[:m.start()].count("\n") + 1
                add("exported_unguarded", line, m.group(0)[:160],
                    f"<{tag}> {nm.group(1)}",
                    "Exported component without permission guard",
                    "high", "manifest",
                    f"Exported {tag} has no android:permission — any app can "
                    "invoke it (IPC attack surface).")

            # task hijacking: exported activity with singleTask/singleInstance
            lm = re.search(r'android:launchMode="([^"]+)"', attrs)
            if exported and not guarded and lm and lm.group(1) in (
                    "singleTask", "singleInstance"):
                line = text[:m.start()].count("\n") + 1
                add("task_hijacking", line, m.group(0)[:160],
                    f"{nm.group(1)} launchMode={lm.group(1)}",
                    "Exported activity with singleTask/singleInstance",
                    "high", "manifest",
                    "Exported singleTask/singleInstance activity without "
                    "permission — a malicious app can send a crafted Intent "
                    "and be treated as the same task (phishing/data theft).")

    # intent-filters without autoVerify (scheme hijack)
    for m in re.finditer(r"<intent-filter\b([^>]*)>(.*?)</intent-filter>",
                         text, re.S):
        body = m.group(2)
        if "<data" in body and "autoVerify" not in m.group(1) and \
                'android:autoVerify' not in body:
            line = text[:m.start()].count("\n") + 1
            scheme = re.search(r'android:scheme="([^"]+)"', body)
            add("deeplink_no_verify", line, m.group(0)[:160],
                f"component={owner(m.start())} "
                f"scheme={scheme.group(1) if scheme else '?'}",
                "Deep link not verified (no autoVerify)",
                "medium", "manifest",
                "Intent filter with <data> lacks android:autoVerify — "
                "custom-scheme links can be hijacked by another app.")
            host = re.search(r'android:host="([^"]+)"', body)
            if scheme and (host is None or "*" in host.group(1)):
                add("deeplink_wildcard", line, m.group(0)[:160],
                    f"component={owner(m.start())} "
                    f"scheme={scheme.group(1)} "
                    f"host={host.group(1) if host else 'none'}",
                    "Deep link scheme without host restriction",
                    "medium", "manifest",
                    "Custom scheme with no/wildcard host — any app can register "
                    "the same scheme and intercept links (or claim any path).")
    return out


def load_exported_components(decompile_dir: str) -> dict[str, str]:
    """Map exported component class simple-name -> full name.

    Used to annotate findings with reachability (``in_exported_component``),
    so triage can separate "reachable by any app" from internal-only code.
    """
    out: dict[str, str] = {}
    for cand in (Path(decompile_dir) / "resources" / "AndroidManifest.xml",
                 Path(decompile_dir) / "AndroidManifest.xml"):
        if not cand.exists():
            continue
        text = cand.read_text(encoding="utf-8", errors="ignore")
        pkg = (re.search(r'package="([^"]+)"', text) or [None, ""])[1]
        for tag in _COMP_TAGS + ("activity-alias",):
            for m in re.finditer(r"<" + tag + r"\b([^>]*?)/?>", text):
                attrs = m.group(1)
                if 'android:exported="true"' not in attrs:
                    continue
                nm = re.search(r'android:name="([^"]+)"', attrs)
                if not nm:
                    continue
                full = nm.group(1)
                if full.startswith("."):
                    full = pkg + full
                simple = full.rsplit(".", 1)[-1]
                out[simple] = full
        break
    return out


def _annotate_reachability(findings: list[dict],
                           exported: dict[str, str]) -> None:
    """Tag each source finding with the exported component it lives in."""
    ipc_rules = {"intent_redirection", "webview_load_untrusted",
                 "pending_intent_mutable", "sql_injection", "cmd_injection",
                 "path_traversal", "webview_js_interface",
                 "webview_file_access", "webview_mixed_content"}
    for f in findings:
        if f["file"].endswith("AndroidManifest.xml"):
            f["in_exported_component"] = True
            f["exported_component"] = ""
            continue
        name = f["file"].rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        if not name.endswith(".java"):
            name = ""
        simple = name[:-5] if name.endswith(".java") else ""
        # inner classes: Outer$Inner -> Outer
        simple = simple.split("$")[0] if simple else ""
        comp = exported.get(simple, "")
        f["in_exported_component"] = bool(comp)
        f["exported_component"] = comp
        if f["rule"] in ipc_rules and not comp:
            f["note"] = ("class is not an exported component — verify it is "
                         "unreachable from other apps before reporting")


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------


# ------------------------------------------------------------------
# Third-party exclusion (noise control)
# ------------------------------------------------------------------

DEFAULT_EXCLUDE_PREFIXES = (
    "androidx/", "kotlin/", "kotlinx/", "okhttp3/", "okio/", "retrofit2/",
    "com/google/", "com/squareup/", "com/bumptech/", "com/facebook/",
    "com/fasterxml/", "com/android/", "dagger/", "lottie/", "org/chromium/",
    "org/intellij/", "org/jetbrains/", "org/json/", "org/apache/",
    "io/reactivex/", "io/grpc/", "io/netty/", "io/sentry/", "io/flutter/",
    "sun/", "javax/", "java/", "de/", "javax.inject/",
)


def scan_source(decompile_dir: str, workers: int | None = None,
                exclude_prefixes: tuple | list | None = None) -> list[dict]:
    """Run all SAST rules over a jadx decompile tree.

    ``exclude_prefixes`` (default: third-party libs listed above) keeps
    findings focused on app code — internal SDK queries/patterns otherwise
    dominate the report with false positives.

    Returns findings sorted by severity, each:
    ``{rule, title, severity, category, description, file, line, snippet}``
    """
    base = Path(decompile_dir)
    src = base / "sources"
    if not src.is_dir():
        logger.warning("No sources/ under %s — nothing to scan", decompile_dir)
        return scan_manifest(decompile_dir)

    excl = tuple(exclude_prefixes if exclude_prefixes is not None
                 else DEFAULT_EXCLUDE_PREFIXES)
    rels: list[str] = []
    skipped = 0
    for p in src.rglob("*.java"):
        try:
            rel = str(p.relative_to(base)).replace("\\", "/")
        except ValueError:
            continue
        pkg_rel = rel[len("sources/"):] if rel.startswith("sources/") else rel
        if excl and any(pkg_rel.startswith(x) for x in excl):
            skipped += 1
            continue
        rels.append(rel)
    logger.info("SAST: %d java files under %s (%d third-party skipped)",
                len(rels), src, skipped)

    n_workers = workers or min(8, os.cpu_count() or 2)
    chunk_size = max(200, len(rels) // (n_workers * 4) + 1)
    chunks = [(str(base), rels[i:i + chunk_size])
              for i in range(0, len(rels), chunk_size)]

    findings: list[dict] = []
    if len(chunks) > 1 and n_workers > 1:
        with ProcessPoolExecutor(max_workers=n_workers) as pool:
            for part in pool.map(_scan_files, chunks):
                findings.extend(part)
    else:
        findings.extend(_scan_files(chunks[0]) if chunks else [])

    findings.extend(scan_manifest(decompile_dir))

    # dedup: one finding per (rule, file) for source files; manifest findings
    # keep one per (rule, file, line) so every component is reported.
    seen: dict[str, dict] = {}
    for f in findings:
        if f["file"].endswith("AndroidManifest.xml"):
            key = f"{f['rule']}|{f['file']}|{f['line']}"
        else:
            key = f"{f['rule']}|{f['file']}"
        if key not in seen or f["line"] < seen[key]["line"]:
            seen[key] = f
    deduped = sorted(seen.values(),
                     key=lambda f: (-SEVERITY_ORDER.get(f["severity"], 0),
                                    f["file"], f["line"]))
    _annotate_reachability(deduped, load_exported_components(decompile_dir))
    reachable = sum(1 for f in deduped
                    if f.get("in_exported_component")
                    and not f["file"].endswith("AndroidManifest.xml"))
    logger.info("SAST: %d findings (%d in exported components)",
                len(deduped), reachable)
    return deduped


def summarize(findings: list[dict]) -> dict:
    by_sev: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_rule[f["rule"]] = by_rule.get(f["rule"], 0) + 1
    return {"total": len(findings), "by_severity": by_sev,
            "by_rule": dict(sorted(by_rule.items(),
                                   key=lambda kv: -kv[1])),
            "in_exported_component": sum(
                1 for f in findings
                if f.get("in_exported_component")
                and not f["file"].endswith("AndroidManifest.xml"))}


def write_sast_md(out_path: Path, findings: list[dict], summary: dict) -> None:
    """Grep-able SAST digest with file:line refs."""
    lines = [
        "# SAST Findings (decompiled source)",
        "",
        f"Total: **{summary['total']}** · by severity: "
        + ", ".join(f"{k}={v}" for k, v in summary["by_severity"].items()),
        "",
        "Refs are relative to `<jadx>/sources/` (open file, jump to line).",
        "",
    ]
    current_sev = None
    for f in findings:
        if f["severity"] != current_sev:
            current_sev = f["severity"]
            lines += ["", f"## {current_sev.upper()}", ""]
        lines.append(
            f"- **[{f['rule']}]** {f['title']} — `{f['file']}:{f['line']}`")
        if f.get("exported_component"):
            lines.append(f"  - in exported component: `{f['exported_component']}`")
        if f.get("note"):
            lines.append(f"  - ⚠ {f['note']}")
        snip = f.get("snippet", "").replace("\n", " ")[:140]
        if snip:
            lines.append(f"  - `{snip}`")
        lines.append(f"  - {f['description'][:300]}")
    if not findings:
        lines.append("_No findings._")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
