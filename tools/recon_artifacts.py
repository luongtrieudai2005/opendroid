"""Recon artifacts writer.

Turns ``workspace/scan.db`` + the jadx decompile tree into files that are
readable by an LLM agent (opencode Read/Grep) and by humans:

    workspace/targets/<package>_<id>/
    ├── INDEX.md              entry point: snapshot + TOC + next steps
    ├── recon.md              full human report (no truncation)
    ├── recon.json            full machine export (all tables)
    └── source/
        ├── MANIFEST.md       decompile map: tree, biggest files, grep hints
        ├── api_surface.md    endpoints grouped by host, with path:line refs
        ├── secrets.md        secrets with path:line refs
        ├── entrypoints.md    exported components + deep links + permissions
        └── interesting/      curated copy of app-relevant sources

Usage::

    from tools.recon_artifacts import write_target_artifacts
    paths = write_target_artifacts(1)
"""

import json
import logging
import re
import shutil
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from tools.storage import StorageManager

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Curation defaults (overridable via config/source_curation.yaml)
# ------------------------------------------------------------------

_SKIP_DIRS = {
    "androidx", "android", "com", "kotlin", "kotlinx", "java", "javax",
    "okhttp3", "okio", "retrofit2", "io", "org", "dagger", "lottie",
    "sun", "jdk",
}
# `com`/`org`/`io` are containers — only skip their known 3rd-party subtrees.
_SKIP_PREFIXES = (
    "com/google/", "com/facebook/", "com/squareup/", "com/bumptech/",
    "com/fasterxml/", "com/airbnb/", "com/android/", "com/unity3d/",
    "org/chromium/", "org/intellij/", "org/jetbrains/", "org/json/",
    "org/apache/", "org/bouncycastle/", "org/slf4j/", "io/reactivex/",
    "io/grpc/", "io/flutter/", "io/sentry/", "io/netty/",
    "androidx/", "kotlin/", "kotlinx/", "okhttp3/", "okio/", "retrofit2/",
    "dagger/", "lottie/",
)
_KEYWORD_DIRS = (
    "network", "api", "http", "client", "crypto", "auth", "session",
    "repository", "remote", "service", "data", "net", "socket", "ws",
    "request", "response", "endpoint", "rest", "grpc", "security",
    "sign", "token", "config", "constant", "model", "dto",
)
_DEFAULT_MAX_FILES = 800
_DEFAULT_MAX_BYTES = 20 * 1024 * 1024


def _load_curation(workspace: Path) -> dict:
    cfg_path = Path("config") / "source_curation.yaml"
    cfg: dict = {}
    if cfg_path.exists():
        try:
            import yaml
            cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            logger.warning("Bad source_curation.yaml: %s", exc)
    skip = list(_SKIP_PREFIXES) + list(cfg.get("skip_prefixes", []))
    keywords = list(_KEYWORD_DIRS) + list(cfg.get("keyword_dirs", []))
    return {
        "skip_prefixes": tuple(skip),
        "keyword_dirs": tuple(keywords),
        "max_files": int(cfg.get("max_files", _DEFAULT_MAX_FILES)),
        "max_bytes": int(cfg.get("max_bytes", _DEFAULT_MAX_BYTES)),
        "app_package": str(cfg.get("app_package", "")),
    }


# ------------------------------------------------------------------
# jadx discovery
# ------------------------------------------------------------------

def _find_jadx_dir(storage: StorageManager, target_id: int,
                   workspace: Path, explicit: str = "") -> Path | None:
    """Locate the jadx decompile tree for this target."""
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    try:
        saved = storage.get_jadx_path(target_id, "jadx")
        if saved:
            candidates.append(Path(saved))
    except Exception:
        pass
    pkg = ""
    t = storage.get_target(target_id)
    if t:
        pkg = t.get("package_name", "")
    if pkg:
        candidates.append(workspace / "jadx" / pkg)
        candidates.append(Path(f"{pkg}_jadx"))
    jadx_root = workspace / "jadx"
    if jadx_root.is_dir():
        candidates.extend(sorted(jadx_root.iterdir(), reverse=True))
    for c in candidates:
        if c.is_dir() and (c / "sources").is_dir():
            return c.resolve()
    return None


# ------------------------------------------------------------------
# Source curation
# ------------------------------------------------------------------

def _is_app_source(rel: str, rules: dict) -> bool:
    """True if a source file is app/business-logic rather than 3rd-party."""
    rel = rel.replace("\\", "/")
    if any(rel.startswith(p) for p in rules["skip_prefixes"]):
        return False
    if rules["app_package"]:
        pkg_path = rules["app_package"].replace(".", "/")
        if rel.startswith(pkg_path + "/"):
            return True
    parts = rel.split("/")
    if len(parts) > 1 and parts[0] in _SKIP_DIRS and parts[1] in (
            "google", "facebook", "squareup", "bumptech", "fasterxml",
            "android", "jetbrains", "chromium"):
        return False
    return any(kw in rel.lower() for kw in rules["keyword_dirs"])


def _curate_sources(jadx_dir: Path, out_dir: Path, rules: dict) -> dict:
    """Copy app-relevant sources into ``out_dir`` (capped)."""
    src = jadx_dir / "sources"
    if not src.is_dir():
        return {"copied": 0, "skipped": 0, "truncated": False}

    out_dir.mkdir(parents=True, exist_ok=True)
    copied = 0
    skipped = 0
    total_bytes = 0
    truncated = False

    for f in src.rglob("*.java"):
        rel = str(f.relative_to(src))
        if not _is_app_source(rel, rules):
            skipped += 1
            continue
        size = f.stat().st_size
        if copied >= rules["max_files"] or total_bytes + size > rules["max_bytes"]:
            truncated = True
            continue
        dest = out_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(f, dest)
        except OSError as exc:
            logger.debug("copy failed %s: %s", f, exc)
            continue
        copied += 1
        total_bytes += size

    return {"copied": copied, "skipped": skipped, "truncated": truncated}


# ------------------------------------------------------------------
# Digest writers
# ------------------------------------------------------------------

def _line_ref(source_file: str, line) -> str:
    if source_file and line:
        return f"{source_file}:{line}"
    return source_file or "?"


def _write_api_surface(out: Path, endpoints: list[dict],
                       have_source: bool) -> int:
    """Group endpoints by host with path:line refs. Returns count."""
    groups: dict[str, list] = {}
    for ep in endpoints:
        url = ep.get("url", "")
        host = urlparse(url).hostname or "(no-host)"
        params = ep.get("params")
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except Exception:
                params = {}
        params = params or {}
        groups.setdefault(host, []).append((ep, params))

    lines = [
        "# API Surface",
        "",
        "> Endpoints extracted from decompiled source. Refs are relative to",
        "> `<jadx>/sources/` — open the file and jump to the line.",
        "",
    ]
    total = 0
    for host in sorted(groups):
        items = groups[host]
        lines.append(f"## {host} ({len(items)})")
        lines.append("")
        for ep, params in sorted(items, key=lambda x: x[0].get("url", "")):
            sf = ep.get("source_file", "")
            line = params.get("line")
            ref = _line_ref(sf, line) if have_source else ""
            conf = params.get("confidence", "")
            bits = [b for b in (ref and f"`{ref}`", conf and f"[{conf}]",
                                ep.get("method") and f"method={ep['method']}") if b]
            suffix = (" — " + " ".join(bits)) if bits else ""
            lines.append(f"- {ep.get('url', '')}{suffix}")
            total += 1
        lines.append("")
    out.write_text("\n".join(lines), encoding="utf-8")
    return total


def _write_secrets_doc(out: Path, secrets: list[dict], have_source: bool) -> int:
    lines = [
        "# Secrets",
        "",
        "> Hardcoded secrets found in decompiled source.",
        "> Refs are relative to `<jadx>/sources/`.",
        "",
    ]
    for s in secrets:
        sf = s.get("source_file", "")
        ref = _line_ref(sf, s.get("line_number")) if have_source else ""
        ref_part = f" `{ref}`" if ref and ref != "?" else ""
        ctx = (s.get("context") or "").replace("\n", " ").strip()
        lines.append(
            f"- **{s.get('type', '?')}** [{s.get('confidence', '?')}] "
            f"`{s.get('value', '')}`{ref_part}"
            + (f"\n  - context: `{ctx[:160]}`" if ctx else "")
        )
    if not secrets:
        lines.append("_No secrets recorded._")
    out.write_text("\n".join(lines), encoding="utf-8")
    return len(secrets)


def _parse_deep_links(manifest_path: Path) -> list[dict]:
    """Extract intent-filter data URIs from AndroidManifest.xml."""
    if not manifest_path.exists():
        return []
    text = manifest_path.read_text(encoding="utf-8", errors="ignore")
    results: list[dict] = []
    comp_pat = re.compile(
        r'<(activity|service|receiver|provider)\b([^>]*?)>(.*?)</\1>',
        re.S)
    for m in comp_pat.finditer(text):
        tag, attrs, body = m.group(1), m.group(2), m.group(3)
        nm = re.search(r'android:name="([^"]+)"', attrs)
        if not nm:
            continue
        exported = 'android:exported="true"' in attrs
        for fm in re.finditer(r'<intent-filter>(.*?)</intent-filter>', body, re.S):
            fb = fm.group(1)
            actions = re.findall(r'<action android:name="([^"]+)"', fb)
            schemes = re.findall(r'<data[^>]*android:scheme="([^"]+)"', fb)
            hosts = re.findall(r'<data[^>]*android:host="([^"]+)"', fb)
            paths = (re.findall(r'<data[^>]*android:path(?:Prefix)?="([^"]+)"', fb)
                     or re.findall(r'<data[^>]*android:pathPattern="([^"]+)"', fb))
            uris = []
            if schemes:
                for sch in schemes:
                    for h in (hosts or [""]):
                        p = paths[0] if paths else ""
                        uris.append(f"{sch}://{h}{p}")
            results.append({
                "component": nm.group(1), "type": tag, "exported": exported,
                "actions": actions, "uris": uris,
            })
    return results


def _write_entrypoints(out: Path, storage: StorageManager, target_id: int,
                       jadx_dir: Path | None) -> int:
    comps = storage._fetchall(
        "SELECT type, name, exported, intent_filters FROM manifest_components "
        "WHERE target_id=? ORDER BY exported DESC, type, name", (target_id,))
    perms = storage._fetchall(
        "SELECT name, is_dangerous FROM permissions WHERE target_id=? "
        "ORDER BY is_dangerous DESC, name", (target_id,))

    deep_links: list[dict] = []
    if jadx_dir:
        for cand in (jadx_dir / "resources" / "AndroidManifest.xml",
                     jadx_dir / "AndroidManifest.xml"):
            if cand.exists():
                deep_links = _parse_deep_links(cand)
                break

    exported = [c for c in comps if c.get("exported")]
    lines = [
        "# Entrypoints (Attack Surface)",
        "",
        f"Exported components: **{len(exported)}** / {len(comps)} total",
        "",
        "## Exported components",
        "",
    ]
    for c in exported:
        lines.append(f"- `{c['type']}` {c['name']}")
    if not exported:
        lines.append("_None recorded (run manifest_parser first)._")

    lines += ["", "## Deep links / intent filters", ""]
    for d in deep_links:
        if not d["uris"] and not d["actions"]:
            continue
        flag = " (exported)" if d["exported"] else ""
        uris = ", ".join(f"`{u}`" for u in d["uris"]) or ""
        acts = ", ".join(d["actions"])
        lines.append(f"- {d['type']} {d['component']}{flag}: {uris} {acts}".rstrip())
    if not deep_links:
        lines.append("_No intent-filter data URIs parsed._")

    lines += ["", "## Permissions", ""]
    for p in perms:
        mark = " **[dangerous]**" if p.get("is_dangerous") else ""
        lines.append(f"- {p['name']}{mark}")
    if not perms:
        lines.append("_None recorded._")

    out.write_text("\n".join(lines), encoding="utf-8")
    return len(exported) + len(deep_links) + len(perms)


def _write_source_manifest(out: Path, jadx_dir: Path, rules: dict,
                           curation: dict) -> None:
    src = jadx_dir / "sources"
    lines = [
        "# Source Map (jadx)",
        "",
        f"- Root: `{jadx_dir}`",
        f"- Sources: `{src if src.is_dir() else 'N/A'}`",
        "",
        "## Directory tree (depth 2)",
        "",
        "```",
    ]
    if src.is_dir():
        top = sorted([d for d in src.iterdir() if d.is_dir()],
                     key=lambda p: p.name)
        for d in top[:40]:
            subs = sorted([s.name for s in d.iterdir() if s.is_dir()])[:15]
            count = sum(1 for _ in d.rglob("*.java"))
            label = f"{d.name}/  ({count} .java)"
            lines.append(label)
            for s in subs:
                sc = sum(1 for _ in (d / s).rglob("*.java"))
                lines.append(f"  {s}/  ({sc})")
        if len(top) > 40:
            lines.append(f"... and {len(top) - 40} more top dirs")
    lines.append("```")

    # Biggest files (likely app logic)
    if src.is_dir():
        files = sorted(
            (f for f in src.rglob("*.java")),
            key=lambda f: f.stat().st_size, reverse=True)[:30]
        lines += ["", "## Largest files (likely app logic)", ""]
        for f in files:
            rel = str(f.relative_to(src))
            try:
                n = sum(1 for _ in f.open(encoding="utf-8", errors="ignore"))
            except OSError:
                n = 0
            tag = "app" if _is_app_source(rel, rules) else "3rd-party"
            lines.append(f"- `{rel}` — {n} lines [{tag}]")

    lines += [
        "",
        "## Grep hints (run from repo root)",
        "",
        "```bash",
        "rg -n \"https?://\" workspace/targets/*/source/interesting/   # URLs in app code",
        "rg -n \"(apiKey|token|secret|password)\" workspace/targets/*/source/interesting/",
        "rg -n \"Base64|Cipher|MessageDigest\" workspace/targets/*/source/interesting/",
        "```",
        "",
        f"Curation: {curation['copied']} files copied "
        f"({curation['skipped']} skipped, truncated={curation['truncated']})",
    ]
    out.write_text("\n".join(lines), encoding="utf-8")


def _query_all(storage: StorageManager, target_id: int) -> dict:
    """Fetch every recon table for this target (full, untruncated)."""
    def q(sql: str) -> list[dict]:
        return storage._fetchall(sql, (target_id,))
    return {
        "target": storage.get_target(target_id),
        "apks": storage.list_apks(target_id),
        "runs": q("SELECT * FROM analysis_runs WHERE target_id=? ORDER BY id DESC"),
        "findings": storage.get_findings(target_id, limit=5000),
        "endpoints": q("SELECT * FROM endpoints WHERE target_id=? ORDER BY id"),
        "secrets": q("SELECT * FROM secrets WHERE target_id=? ORDER BY id"),
        "subdomains": q("SELECT * FROM subdomains WHERE target_id=? ORDER BY domain"),
        "manifest_components": q("SELECT * FROM manifest_components WHERE target_id=?"),
        "permissions": q("SELECT * FROM permissions WHERE target_id=?"),
        "firebase_instances": q("SELECT * FROM firebase_instances WHERE target_id=?"),
        "native_libraries": q("SELECT * FROM native_libraries WHERE target_id=?"),
        "http_requests": q("SELECT * FROM http_requests WHERE target_id=? ORDER BY id DESC LIMIT 500"),
        "fuzz_results": q("SELECT * FROM fuzz_results WHERE target_id=?"),
    }


def _write_recon_md(out: Path, data: dict) -> None:
    t = data.get("target") or {}
    lines = [
        f"# Recon Report: {t.get('package_name', '?')}",
        "",
        f"- **App**: {t.get('app_name', 'N/A')}",
        f"- **Generated**: {datetime.utcnow().isoformat(timespec='seconds')}Z",
        f"- **APKs**: {len(data['apks'])} | **Runs**: {len(data['runs'])}",
        "",
    ]

    findings = data["findings"]
    lines.append(f"## Findings ({len(findings)})")
    if findings:
        by_sev: dict[str, list] = {}
        for f in findings:
            by_sev.setdefault(str(f.get("severity", "info")), []).append(f)
        for sev in ("critical", "high", "medium", "low", "info"):
            lst = by_sev.get(sev, [])
            if not lst:
                continue
            lines += ["", f"### {sev.upper()} ({len(lst)})", ""]
            for f in lst:
                lines.append(f"#### {f.get('title') or f.get('type', 'finding')}")
                if f.get("description"):
                    lines.append(f"{f['description']}")
                if f.get("url"):
                    lines.append(f"- url: {f['url']}")
                if f.get("evidence"):
                    ev = str(f["evidence"]).replace("\n", "\n  ")
                    lines.append(f"- evidence: `{ev[:1500]}`")
                lines.append(f"- source: {f.get('source', '?')}")
                lines.append("")
    else:
        lines.append("_No findings recorded._")

    endpoints = data["endpoints"]
    lines += ["", f"## Endpoints ({len(endpoints)})", ""]
    for ep in endpoints:
        params = ep.get("params", "")
        line = ""
        if params:
            try:
                pj = json.loads(params) if isinstance(params, str) else params
                if pj.get("line"):
                    line = f" ({ep.get('source_file', '')}:{pj['line']})"
            except Exception:
                pass
        cat = ep.get("category", "unknown")
        src = ep.get("source", "?")
        lines.append(f"- [{cat}/{src}] {ep.get('method') or 'GET'} {ep.get('url', '')}{line}")
    if not endpoints:
        lines.append("_No endpoints recorded._")

    secrets = data["secrets"]
    lines += ["", f"## Secrets ({len(secrets)})", ""]
    for s in secrets:
        ref = ""
        if s.get("source_file"):
            ref = f" — `{s['source_file']}`"
            if s.get("line_number"):
                ref += f":{s['line_number']}"
        lines.append(f"- [{s.get('confidence', '?')}] **{s.get('type', '?')}**: "
                     f"`{s.get('value', '')}`{ref}")
    if not secrets:
        lines.append("_No secrets recorded._")

    subs = data["subdomains"]
    if subs:
        live = sum(1 for s in subs if s.get("resolved"))
        lines += ["", f"## Subdomains ({live} live / {len(subs)} total)", ""]
        for sd in subs:
            flag = "LIVE" if sd.get("resolved") else "?"
            ip = f" ({sd['ip_address']})" if sd.get("ip_address") else ""
            lines.append(f"- [{flag}] {sd['domain']}{ip} — {sd.get('source', '?')}")

    comps = data["manifest_components"]
    exported = [c for c in comps if c.get("exported")]
    lines += ["", f"## Components: {len(exported)} exported / {len(comps)} total", ""]
    for c in exported:
        lines.append(f"- `{c['type']}` {c['name']}")

    perms = data["permissions"]
    dangerous = [p for p in perms if p.get("is_dangerous")]
    lines += ["", f"## Permissions: {len(dangerous)} dangerous / {len(perms)} total", ""]
    for p in dangerous:
        lines.append(f"- {p['name']}")

    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_index(out: Path, data: dict, files: dict,
                 target_dir: Path, have_source: bool) -> None:
    t = data.get("target") or {}
    pkg = t.get("package_name", "?")
    lines = [
        f"# {t.get('app_name') or pkg} — Recon INDEX",
        "",
        f"Package `{pkg}` (target id {t.get('id')}) · generated "
        f"{datetime.utcnow().isoformat(timespec='seconds')}Z",
        "",
        "## Snapshot",
        "",
        "| what | count |",
        "|---|---|",
        f"| findings | {len(data['findings'])} |",
        f"| endpoints | {len(data['endpoints'])} |",
        f"| secrets | {len(data['secrets'])} |",
        f"| subdomains | {len(data['subdomains'])} |",
        f"| exported components | {sum(1 for c in data['manifest_components'] if c.get('exported'))} |",
        f"| dangerous permissions | {sum(1 for p in data['permissions'] if p.get('is_dangerous'))} |",
        "",
        "## Artifacts",
        "",
        "| file | purpose |",
        "|---|---|",
        "| `recon.md` | full human report (no truncation) |",
        "| `recon.json` | full machine export of every recon table |",
    ]
    if have_source:
        lines += [
            "| `source/MANIFEST.md` | decompile map: tree, biggest files, grep hints |",
            "| `source/api_surface.md` | endpoints grouped by host with `file:line` refs |",
            "| `source/secrets.md` | secrets with `file:line` refs |",
            "| `source/entrypoints.md` | exported components, deep links, permissions |",
            f"| `source/interesting/` | curated app sources ({files.get('copied', 0)} files) |",
        ]
    else:
        lines.append("| _(no jadx tree found)_ | run the static-analysis phase first |")

    lines += [
        "",
        "## How to consume (opencode / agent)",
        "",
        "1. `Read` this file (you are here) → pick a target area.",
        "2. Findings & endpoints: `Read` `recon.md`.",
        "3. Grep app code: `Grep` in `source/interesting/` (paths relative to",
        "   the jadx `sources/` dir), then `Read(file, offset=<line>)` on the",
        "   original file under the jadx root listed in `source/MANIFEST.md`.",
        "4. Machine consumers: `recon.json` (full fidelity).",
        "",
        "```bash",
        f"# quick greps",
        f"rg -n \"https?://\" \"{target_dir}/source/interesting/\"",
        f"rg -n \"(apiKey|token|secret)\" \"{target_dir}/source/interesting/\"",
        "```",
        "",
        "## Index of numbers",
        "",
        f"- findings: {len(data['findings'])} "
        f"(crit/high: {sum(1 for f in data['findings'] if str(f.get('severity')) in ('critical', 'high'))})",
        f"- endpoints: {len(data['endpoints'])}",
        f"- secrets: {len(data['secrets'])}",
        f"- subdomains: {len(data['subdomains'])}",
        f"- apks: {len(data['apks'])} · runs: {len(data['runs'])}",
    ]
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def write_target_artifacts(target_id: int,
                           storage: StorageManager | None = None,
                           workspace: str = "workspace",
                           jadx_dir: str = "",
                           include_source: bool = True) -> dict:
    """Write INDEX/recon/source artifacts for a target.

    Returns dict of artifact paths (str) + counts. Existing files are
    overwritten (idempotent).
    """
    own_storage = storage is None
    if own_storage:
        storage = StorageManager(workspace).init()

    written: dict = {}
    try:
        target = storage.get_target(target_id)
        if not target:
            raise ValueError(f"Target {target_id} not found")

        ws_root = Path(getattr(storage, "root", Path(workspace)))
        target_dir = storage._tdir(target_id)
        target_dir.mkdir(parents=True, exist_ok=True)

        data = _query_all(storage, target_id)

        # --- recon.json (full export) ---
        recon_json = target_dir / "recon.json"
        recon_json.write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8")
        written["recon_json"] = str(recon_json)

        # --- recon.md (full report) ---
        recon_md = target_dir / "recon.md"
        _write_recon_md(recon_md, data)
        written["recon_md"] = str(recon_md)

        # --- source digests ---
        rules = _load_curation(ws_root)
        pkg = target.get("package_name", "")
        rules["app_package"] = rules["app_package"] or pkg
        jadx = _find_jadx_dir(storage, target_id, ws_root, jadx_dir)
        have_source = jadx is not None
        curation = {"copied": 0, "skipped": 0, "truncated": False}

        if have_source:
            src_out = target_dir / "source"
            src_out.mkdir(parents=True, exist_ok=True)

            if include_source:
                curation = _curate_sources(jadx, src_out / "interesting", rules)
                written["interesting_dir"] = str(src_out / "interesting")

            n_ep = _write_api_surface(src_out / "api_surface.md",
                                      data["endpoints"], have_source)
            n_sc = _write_secrets_doc(src_out / "secrets.md",
                                      data["secrets"], have_source)
            n_ep_pts = _write_entrypoints(src_out / "entrypoints.md",
                                          storage, target_id, jadx)
            _write_source_manifest(src_out / "MANIFEST.md", jadx,
                                   rules, curation)
            written.update({
                "source_manifest": str(src_out / "MANIFEST.md"),
                "api_surface": str(src_out / "api_surface.md"),
                "secrets_doc": str(src_out / "secrets.md"),
                "entrypoints": str(src_out / "entrypoints.md"),
                "endpoints_indexed": n_ep,
                "secrets_indexed": n_sc,
                "entrypoints_indexed": n_ep_pts,
                "jadx_dir": str(jadx),
            })

        # --- INDEX.md (last: references everything) ---
        index_md = target_dir / "INDEX.md"
        _write_index(index_md, data, curation, target_dir, have_source)
        written["index_md"] = str(index_md)

        written["target_dir"] = str(target_dir)
        written["target_id"] = target_id
        written["have_source"] = have_source
        logger.info("Artifacts written for target %d -> %s", target_id,
                    target_dir)
        return written
    finally:
        if own_storage:
            storage.close()


def write_all_artifacts(workspace: str = "workspace") -> list[dict]:
    """Write artifacts for every target. Returns list of per-target results."""
    storage = StorageManager(workspace).init()
    try:
        results = []
        for t in storage.list_targets():
            try:
                results.append(write_target_artifacts(
                    t["id"], storage=storage, workspace=workspace))
            except Exception as exc:
                logger.warning("artifacts failed for target %s: %s",
                               t["id"], exc)
        return results
    finally:
        storage.close()
