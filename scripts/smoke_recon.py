"""Smoke test: engine resolve + recon_artifacts writer (no WSL/adb needed).

Run: python scripts/smoke_recon.py
"""
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import os
os.chdir(ROOT)

from tools.workflow import resolve_vars, WorkflowEngine
from tools.storage import StorageManager
from tools.recon_artifacts import write_target_artifacts

WS = Path(tempfile.gettempdir()) / "opencode" / "recon_smoke_ws"
if WS.exists():
    shutil.rmtree(WS)
WS.mkdir(parents=True)

failures = []

def check(name, cond, detail=""):
    status = "OK " if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)

# ---------------- 1. resolver behavior ----------------
ctx = {
    "target": {"id": 1, "package": "com.example.app", "app_name": "Example", "apk": "x.apk"},
    "vars": {"nuclei_severity": "critical,high"},
    "tools": {"decompiler": "jadx"},
    "workspace": str(WS),
    "target_domains": {"result": ["api.example.com", "cdn.example.com"]},
    "flutter_detect": {"is_flutter": False},
    "endpoints": {"result": [{"value": "https://api.example.com/v1"}, {"value": "https://x.io"}]},
    "httpx": {"result": [{"url": "https://api.example.com"}, {"url": "https://cdn.example.com"}]},
    "subdomains": {"result": ["api.example.com", "www.example.com"]},
}

check("pure list preserved", resolve_vars("{target_domains.result}", ctx) == ["api.example.com", "cdn.example.com"])
check("map works", resolve_vars("{httpx.result | map(.url)}", ctx) == ["https://api.example.com", "https://cdn.example.com"])
check("first pipe", resolve_vars("{target_domains.result | first}", ctx) == "api.example.com")
check("when length>0 true", resolve_vars("{endpoints.result | length > 0}", ctx) is True)
check("when flutter==True false", resolve_vars("{flutter_detect.is_flutter} == True", ctx) is False)
ctx2 = dict(ctx, flutter_detect={"is_flutter": True})
check("when flutter==True true", resolve_vars("{flutter_detect.is_flutter} == True", ctx2) is True)
check("workspace path", resolve_vars("{workspace}/report.md", ctx).endswith("report.md"))
check("mixed list join", resolve_vars("ids:{target_domains.result}", ctx) == "ids:api.example.com,cdn.example.com")

# tool alias resolve
check("tool alias", resolve_vars("{tools.decompiler}", ctx) == "jadx")

# ---------------- 2. storage + fake data ----------------
storage = StorageManager(str(WS)).init()
tid = storage.create_target("com.example.app", app_name="Example App")
storage.save_apk(tid, r"D:\AndroidPentest\README.md")  # any file as stand-in
storage.add_endpoints_bulk(tid, [
    {"url": "https://api.example.com/v1/login", "category": "external", "source": "jadx",
     "source_file": "com/example/app/net/ApiClient.java", "params": {"line": 42, "confidence": "high"}},
    {"url": "https://firestore.googleapis.com/v1/x", "category": "cloud", "source": "jadx",
     "source_file": "com/example/app/data/Repo.java", "params": {"line": 7, "confidence": "medium"}},
])
storage.add_secrets_bulk(tid, [
    {"type": "api_key", "value": "AIzaXYZ123", "confidence": "high",
     "source_file": "com/example/app/net/ApiClient.java", "line_number": 15, "context": "apiKey = ..."},
])
storage.add_subdomains(tid, ["api.example.com", "www.example.com"], source="subfinder")
storage.add_finding(tid, type="nuclei", severity="high", title="Open redirect",
                    description="Redirect param not validated at https://api.example.com/redir",
                    url="https://api.example.com/redir?u=", source="nuclei")
storage.save_manifest(tid, [
    {"type": "activity", "name": "com.example.app.MainActivity", "exported": True},
    {"type": "provider", "name": "com.example.app.MyProvider", "exported": True},
    {"type": "activity", "name": "com.example.app.Internal", "exported": False},
], ["android.permission.INTERNET", "android.permission.READ_SMS"])
storage.close()

# ---------------- 3. fake jadx tree ----------------
jadx = WS / "jadx" / "com.example.app"
(jadx / "sources" / "com" / "example" / "app" / "net").mkdir(parents=True)
(jadx / "sources" / "com" / "example" / "app" / "data").mkdir(parents=True)
(jadx / "sources" / "androidx" / "core").mkdir(parents=True)
(jadx / "resources").mkdir(parents=True)

(jadx / "sources" / "com" / "example" / "app" / "net" / "ApiClient.java").write_text(
    "package com.example.app.net;\n"
    "class ApiClient {\n"
    "  String base = \"https://api.example.com/v1\";\n"
    "  String apiKey = \"AIzaXYZ123\";\n"
    "  void login() { /* ... */ }\n"
    "}\n", encoding="utf-8")
(jadx / "sources" / "com" / "example" / "app" / "data" / "Repo.java").write_text(
    "package com.example.app.data;\n"
    "class Repo {\n"
    "  String fb = \"https://myproj.firebaseio.com\";\n"
    "}\n", encoding="utf-8")
(jadx / "sources" / "androidx" / "core" / "Unrelated.java").write_text(
    "package androidx.core;\n" + "// filler\n" * 200, encoding="utf-8")
(jadx / "resources" / "AndroidManifest.xml").write_text(
    '<manifest package="com.example.app">\n'
    '  <uses-permission android:name="android.permission.INTERNET"/>\n'
    '  <activity android:name=".MainActivity" android:exported="true">\n'
    '    <intent-filter>\n'
    '      <action android:name="android.intent.action.VIEW"/>\n'
    '      <data android:scheme="example" android:host="open" android:pathPrefix="/pay"/>\n'
    '    </intent-filter>\n'
    '  </activity>\n'
    '</manifest>\n', encoding="utf-8")

# ---------------- 4. write artifacts ----------------
res = write_target_artifacts(tid, workspace=str(WS))
tdir = Path(res["target_dir"])

for fname in ("INDEX.md", "recon.md", "recon.json"):
    p = tdir / fname
    check(f"{fname} exists", p.exists() and p.stat().st_size > 100, f"size={p.stat().st_size if p.exists() else 0}")

check("have_source", res.get("have_source") is True, str(res))
for fname in ("source/MANIFEST.md", "source/api_surface.md", "source/secrets.md", "source/entrypoints.md"):
    p = tdir / fname
    check(f"{fname} exists", p.exists() and p.stat().st_size > 50, str(p))

idx = (tdir / "INDEX.md").read_text(encoding="utf-8")
check("INDEX has counts", "| findings | 1 |" in idx)
check("INDEX has artifacts table", "recon.md" in idx and "api_surface.md" in idx)

api = (tdir / "source" / "api_surface.md").read_text(encoding="utf-8")
check("api_surface has line ref", "ApiClient.java:42" in api, api[:300])
check("api_surface groups host", "## api.example.com" in api)

sec = (tdir / "source" / "secrets.md").read_text(encoding="utf-8")
check("secrets has line ref", "ApiClient.java:15" in sec)

ep = (tdir / "source" / "entrypoints.md").read_text(encoding="utf-8")
check("entrypoints exported", "MainActivity" in ep)
check("entrypoints deeplink", "example://open/pay" in ep, ep[:500])
check("entrypoints dangerous perm", "READ_SMS" in ep and "[dangerous]" in ep)

sm = (tdir / "source" / "MANIFEST.md").read_text(encoding="utf-8")
check("MANIFEST tree", "com/  (" in sm and "androidx/  (" in sm, sm[:600])
check("MANIFEST largest", "ApiClient.java" in sm)

recon = (tdir / "recon.md").read_text(encoding="utf-8")
check("recon.md finding", "Open redirect" in recon)
check("recon.md endpoint", "https://api.example.com/v1/login" in recon)
check("recon.md no trunc marker", "... and" not in recon)

rj = json.loads((tdir / "recon.json").read_text(encoding="utf-8"))
check("recon.json tables", all(k in rj for k in ("endpoints", "secrets", "subdomains", "manifest_components", "permissions", "findings")))
check("recon.json endpoint count", len(rj["endpoints"]) == 2)

# curated sources
interesting = tdir / "source" / "interesting"
copied = list(interesting.rglob("*.java"))
check("curated copied app src", any("ApiClient.java" in str(p) for p in copied), str(copied))
check("curated skipped androidx", not any("androidx" in str(p) for p in copied))

# ---------------- 5. report_generator integration ----------------
from tools.workflow_tools import report_generator
out_md = WS / "reports" / "report.md"
_st = StorageManager(str(WS)).init()
r = report_generator(target_id=tid, format="markdown", output=str(out_md), _storage=_st)
check("report file written", out_md.exists())
check("report_generator returns artifacts", r.get("artifacts", {}).get("index_md", "").endswith("INDEX.md"))
_st.close()

# ---------------- 6. foreach binding + signature filter ----------------
class FakeEntry:
    def __init__(self, fn): self.func = fn
from tools.workflow import ToolRegistry
reg = ToolRegistry()
class FakeEngine:
    _ctx = ctx
    _workflow = {"tools": {}}
    registry = reg
def f_batch(domains=None, **kw): return list(domains)
reg.register("f_batch", f_batch)
check("accepted kwargs detection", __import__("tools.workflow", fromlist=["_accepts_var_keyword"])._accepts_var_keyword(f_batch) is True)
def f_strict(domain=""): return domain
check("strict sig detection", __import__("tools.workflow", fromlist=["_accepts_var_keyword"])._accepts_var_keyword(f_strict) is False)

# ---------------- summary ----------------
print()
if failures:
    print(f"RESULT: {len(failures)} FAILURES: {failures}")
    sys.exit(1)
print("RESULT: ALL PASS")
