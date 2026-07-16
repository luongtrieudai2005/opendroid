"""Frida Script Manager — quản lý, generate, và thực thi Frida hooks.

Provides:
  - Script catalog management (list/get/save/delete by category)
  - Template engine for parametric JS generation
  - Script execution (spawn + attach mode, combined scripts)
  - Runtime class/method discovery from live process
  - Auto-hook generation from decompiled source
"""

import json
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.workflow import tool_meta

logger = logging.getLogger(__name__)

_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "config" / "frida-scripts"


# ------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------

@dataclass
class FridaScript:
    name: str
    category: str
    path: str
    description: str = ""
    is_template: bool = False
    params: list[str] = field(default_factory=list)
    size: int = 0


# ------------------------------------------------------------------
# FRIDA TEMPLATES — parametric hook generators
# ------------------------------------------------------------------

FRIDA_TEMPLATES: dict[str, dict[str, Any]] = {
    "hook_method": {
        "description": "Hook any Java method, log args + return value",
        "params": ["class_name", "method_name", "overloads", "pre_hook", "post_hook", "label"],
        "template": """
Java.perform(function() {
    try {
        var Cls = Java.use("{class_name}");
        var overloads = {overloads};
        Cls.{method_name}.overload.apply(Cls, overloads).implementation = function() {
            console.log("[{label}] {class_name}.{method_name} called");
            var args = Array.prototype.slice.call(arguments);
            for (var i = 0; i < args.length; i++) {
                console.log("[{label}]  arg[" + i + "]: " + args[i]);
            }
            {pre_hook}
            var ret = this.{method_name}.apply(this, arguments);
            console.log("[{label}] return: " + ret);
            {post_hook}
            return ret;
        };
        console.log("[+] {class_name}.{method_name} hooked");
    } catch(e) {
        console.log("[-] hook_method error: " + e);
    }
});
""",
    },
    "hook_method_return": {
        "description": "Hook a method and replace its return value",
        "params": ["class_name", "method_name", "return_value", "label"],
        "template": """
Java.perform(function() {
    try {
        var Cls = Java.use("{class_name}");
        Cls.{method_name}.overload().implementation = function() {
            console.log("[{label}] {class_name}.{method_name} -> {return_value}");
            return {return_value};
        };
        console.log("[+] {class_name}.{method_name} -> {return_value}");
    } catch(e) { console.log("[-] hook_return error: " + e); }
});
""",
    },
    "hook_constructor": {
        "description": "Hook class constructor to log instantiation",
        "params": ["class_name", "label"],
        "template": """
Java.perform(function() {
    try {
        var Cls = Java.use("{class_name}");
        Cls.$init.overload().implementation = function() {
            console.log("[{label}] new {class_name}()");
            {pre_hook}
            this.$init();
            {post_hook}
        };
        console.log("[+] {class_name} constructor hooked");
    } catch(e) { console.log("[-] hook_constructor error: " + e); }
});
""",
    },
    "trace_all_methods": {
        "description": "Trace all calls to methods of a class",
        "params": ["class_name", "label", "filter_regex"],
        "template": """
Java.perform(function() {
    try {
        var Cls = Java.use("{class_name}");
        var methods = Object.getOwnPropertyNames(Cls.__proto__);
        methods.forEach(function(m) {
            if (typeof Cls[m] === 'function' && m.indexOf('$') === -1) {
                {filter_code}
                try {
                    Cls[m].overloads.forEach(function(o) {
                        o.implementation = function() {
                            console.log("[{label}] " + m + " called");
                            return o.apply(this, arguments);
                        };
                    });
                } catch(e) {}
            }
        });
        console.log("[+] {class_name} all methods traced");
    } catch(e) { console.log("[-] trace_all error: " + e); }
});
""",
    },
    "dump_class_fields": {
        "description": "Dump all field values of a class instance",
        "params": ["class_name", "method_name", "label"],
        "template": """
Java.perform(function() {
    try {
        var Cls = Java.use("{class_name}");
        Cls.{method_name}.overload().implementation = function() {
            var ret = this.{method_name}();
            console.log("[{label}] {class_name}.{method_name} fields:");
            var fields = Object.getOwnPropertyNames(Cls);
            fields.forEach(function(f) {
                try { console.log("[{label}]  ." + f + " = " + ret.field(f)); } catch(e) {}
            });
            return ret;
        };
        console.log("[+] {class_name} field dump hooked");
    } catch(e) { console.log("[-] dump_fields error: " + e); }
});
""",
    },
    "bypass_ssl_universal": {
        "description": "Universal SSL pinning bypass (TrustManager + OkHttp + WebView)",
        "params": [],
        "template": """
Java.perform(function() {
    // SSL unpin: TrustManager
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var TrustManager = Java.registerClass({
            name: 'com.example.TrustAllManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(kms, tms, sr) {
            this.init.call(this, kms, [TrustManager.$new()], sr);
        };
        console.log('[+] SSL TrustManager bypassed');
    } catch(e) { console.log('[-] TrustManager: ' + e); }
    // OkHttp CertificatePinner
    try { Java.use('okhttp3.CertificatePinner').check.overload('java.lang.String', 'java.util.List').implementation = function() {}; console.log('[+] OkHttp pinner bypassed'); } catch(e) {}
    // WebView
    try { Java.use('android.webkit.WebViewClient').onReceivedSslError.implementation = function(v, h, e) { h.proceed(); }; console.log('[+] WebView SSL bypassed'); } catch(e) {}
    console.log('[+] SSL pinning bypassed');
});
""",
    },
    "bypass_rootbeer": {
        "description": "Bypass RootBeer root detection",
        "params": [],
        "template": """
Java.perform(function() {
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() { console.log('[RootBeer] isRooted -> false'); return false; };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() { console.log('[RootBeer] isRootedWBC -> false'); return false; };
        RootBeer.checkForRootNative.implementation = function() { console.log('[RootBeer] checkForRootNative -> false'); return false; };
        console.log('[+] RootBeer bypassed');
    } catch(e) { console.log('[-] RootBeer: ' + e); }
    try {
        var DeviceData = Java.use('com.bugsnag.android.DeviceData');
        DeviceData.isRooted.implementation = function() { console.log('[Bugsnag] isRooted -> false'); return false; };
    } catch(e) {}
    console.log('[+] Root detection bypassed');
});
""",
    },
    "force_proxy": {
        "description": "Force OkHttp proxy to Burp (127.0.0.1:8080)",
        "params": ["proxy_host", "proxy_port"],
        "template": """
Java.perform(function() {
    var proxyHost = '{proxy_host}';
    var proxyPort = {proxy_port};
    try {
        var OkHttpBuilder = Java.use('okhttp3.OkHttpClient$Builder');
        var Proxy = Java.use('java.net.Proxy');
        var InetSocket = Java.use('java.net.InetSocketAddress');
        var myProxy = Proxy.$new(Proxy.Type.HTTP, InetSocket.$new(proxyHost, proxyPort));
        OkHttpBuilder.build.implementation = function() {
            this.proxy(myProxy);
            console.log('[Proxy] OkHttp proxy forced to ' + proxyHost + ':' + proxyPort);
            return this.build();
        };
        console.log('[+] OkHttp proxy forced');
    } catch(e) { console.log('[-] OkHttp proxy: ' + e); }
});
""",
    },
    "log_shared_prefs": {
        "description": "Log all SharedPreferences reads/writes",
        "params": ["label"],
        "template": """
Java.perform(function() {
    try {
        var SharedPreferences = Java.use('android.content.SharedPreferences');
        SharedPreferences.getString.overload('java.lang.String', 'java.lang.String').implementation = function(key, defVal) {
            var val = this.getString(key, defVal);
            console.log('[SP] getString(' + key + ') = ' + val);
            return val;
        };
        var Editor = Java.use('android.content.SharedPreferences$Editor');
        Editor.putString.overload('java.lang.String', 'java.lang.String').implementation = function(key, val) {
            console.log('[SP] putString(' + key + ', ' + val + ')');
            return this.putString(key, val);
        };
        console.log('[+] SharedPreferences hooked');
    } catch(e) { console.log('[-] SP hook: ' + e); }
});
""",
    },
}

# Known class patterns for auto-hook generation
_INTERESTING_CLASS_PATTERNS = [
    (r"okhttp3\.(OkHttpClient|OkHttp3|CertificatePinner)", "okhttp"),
    (r"retrofit2?\.", "retrofit"),
    (r"javax\.crypto\.(Cipher|SecretKey|Mac)", "crypto"),
    (r"android\.security\.", "android_security"),
    (r"android\.content\.SharedPreferences", "shared_prefs"),
    (r"android\.database\.sqlite\.(SQLiteDatabase|SQLiteOpenHelper)", "sqlite"),
    (r"java\.net\.(HttpURLConnection|URL|Socket)", "network"),
    (r"com\.(squareup|google\.firebase|facebook|adjust|amplitude)", "third_party_sdk"),
    (r"org\.json\.(JSONObject|JSONArray)", "json"),
    (r"android\.webkit\.(WebView|WebChromeClient)", "webview"),
]

# x-ref setup from AGENTS.md: Frida port 27043, `-H 127.0.0.1:27043`
_FRIDA_HOST = "127.0.0.1"
_FRIDA_PORT = 27043


# ------------------------------------------------------------------
# Script Catalog Management
# ------------------------------------------------------------------

def _ensure_scripts_dir():
    _SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    for cat in ("ssl_bypass", "root_bypass", "crypto", "traffic", "runtime", "custom", "combined"):
        (_SCRIPTS_DIR / cat).mkdir(exist_ok=True)


@tool_meta(
    name="frida_list_scripts",
    description="List available Frida scripts by category",
    params={"category": "Filter by category (optional)"},
    outputs=["scripts", "categories", "result"],
)
def frida_list_scripts(category: str = "", **kwargs) -> dict:
    """List all Frida scripts in the catalog, optionally filtered by category.

    Args:
        category: Optional filter (ssl_bypass, root_bypass, crypto, traffic, runtime, custom)

    Returns:
        Dict with scripts list, categories, result.
    """
    _ensure_scripts_dir()
    cat_filter = category or kwargs.get("category", "")
    scripts: list[dict] = []
    categories: set[str] = set()

    for cat_dir in sorted(_SCRIPTS_DIR.iterdir()):
        if not cat_dir.is_dir() or cat_dir.name.startswith("."):
            continue
        categories.add(cat_dir.name)
        if cat_filter and cat_dir.name != cat_filter:
            continue
        for js_file in sorted(cat_dir.glob("*.js")):
            size = js_file.stat().st_size
            is_template = js_file.name.startswith("_template_")
            scripts.append({
                "name": js_file.stem,
                "category": cat_dir.name,
                "path": str(js_file),
                "size": size,
                "is_template": is_template,
                "description": _guess_description(js_file),
            })

    return {
        "scripts": scripts,
        "categories": sorted(categories),
        "count": len(scripts),
        "result": scripts,
    }


def _guess_description(js_path: Path) -> str:
    """Read first comment line from a JS file as description."""
    try:
        text = js_path.read_text(encoding="utf-8", errors="ignore")
        for line in text.split("\n")[:5]:
            line = line.strip()
            if line.startswith("//") and len(line) > 5:
                return line[2:].strip()
            if line.startswith("/*") and len(line) > 5:
                end = line.find("*/")
                if end > 0:
                    return line[2:end].strip()
                return line[2:].strip()
    except Exception:
        pass
    return ""


@tool_meta(
    name="frida_get_script",
    description="Read the content of a specific Frida script",
    params={"name": "Script name (without .js)", "category": "Script category"},
    outputs=["content", "path", "result"],
)
def frida_get_script(name: str = "", category: str = "", **kwargs) -> dict:
    """Read a Frida script source code.

    Args:
        name: Script name (without .js extension)
        category: Script category folder

    Returns:
        Dict with content, path, result.
    """
    n = name or kwargs.get("name", "")
    cat = category or kwargs.get("category", "")
    if not n or not cat:
        return {"error": "name and category required", "content": "", "result": {}}

    path = _SCRIPTS_DIR / cat / f"{n}.js"
    if not path.exists():
        return {"error": f"Script not found: {path}", "content": "", "result": {}}

    return {
        "name": n,
        "category": cat,
        "path": str(path),
        "content": path.read_text(encoding="utf-8", errors="ignore"),
        "size": path.stat().st_size,
        "result": {"content": path.read_text(encoding="utf-8", errors="ignore")},
    }


@tool_meta(
    name="frida_save_script",
    description="Save a new or update existing Frida script",
    params={
        "name": "Script name (without .js)",
        "category": "Category folder",
        "content": "JavaScript source code",
    },
    outputs=["path", "result"],
)
def frida_save_script(name: str = "", category: str = "",
                      content: str = "", **kwargs) -> dict:
    """Save a Frida script to the catalog.

    Args:
        name: Script name (without .js)
        category: Category folder (ssl_bypass, root_bypass, etc.)
        content: JavaScript source code

    Returns:
        Dict with path, result.
    """
    n = name or kwargs.get("name", "")
    cat = category or kwargs.get("category", "")
    c = content or kwargs.get("content", "")

    if not n or not cat or not c:
        return {"error": "name, category, and content required", "result": {}}

    _ensure_scripts_dir()
    cat_dir = _SCRIPTS_DIR / cat
    cat_dir.mkdir(exist_ok=True)

    path = cat_dir / f"{n}.js"
    path.write_text(c, encoding="utf-8")
    logger.info("Frida script saved: %s", path)
    return {"path": str(path), "size": path.stat().st_size, "result": {"path": str(path)}}


@tool_meta(
    name="frida_delete_script",
    description="Delete a Frida script from the catalog",
    params={"name": "Script name", "category": "Category folder"},
    outputs=["deleted", "result"],
)
def frida_delete_script(name: str = "", category: str = "", **kwargs) -> dict:
    """Delete a Frida script.

    Args:
        name: Script name
        category: Category folder

    Returns:
        Dict with deleted status, result.
    """
    n = name or kwargs.get("name", "")
    cat = category or kwargs.get("category", "")
    path = _SCRIPTS_DIR / cat / f"{n}.js"
    if path.exists():
        path.unlink()
        logger.info("Frida script deleted: %s", path)
        return {"deleted": True, "result": {"path": str(path)}}
    return {"deleted": False, "error": "not found", "result": {}}


# ------------------------------------------------------------------
# Template Engine
# ------------------------------------------------------------------

@tool_meta(
    name="frida_generate_script",
    description="Generate a Frida hook script from a template with custom params",
    params={
        "template_name": "Template name (hook_method, hook_method_return, bypass_ssl_universal, etc.)",
        "params": "Dict of template parameters",
    },
    outputs=["content", "template_used", "result"],
)
def frida_generate_script(template_name: str = "", params: dict | None = None, **kwargs) -> dict:
    """Generate a Frida JavaScript hook from a parametric template.

    Args:
        template_name: Name of the template (see FRIDA_TEMPLATES keys)
        params: Dict of template parameters

    Returns:
        Dict with generated content, template_used, result.
    """
    tpl_name = template_name or kwargs.get("template_name", "")
    tpl_params = params or kwargs.get("params", {}) or {}

    if tpl_name not in FRIDA_TEMPLATES:
        return {"error": f"Unknown template: {tpl_name}. Available: {list(FRIDA_TEMPLATES.keys())}",
                "content": "", "template_used": tpl_name, "result": {}}

    tpl_info = FRIDA_TEMPLATES[tpl_name]
    tpl = tpl_info["template"]

    # Check required params
    missing = [p for p in tpl_info["params"] if "{" + p + "}" in tpl and p not in tpl_params]
    if missing:
        return {"error": f"Missing params: {missing}", "content": "",
                "template_used": tpl_name, "result": {}}

    # Fill template
    content = tpl
    for k, v in tpl_params.items():
        # Convert lists to JS array string
        if isinstance(v, list):
            v_str = json.dumps(v)
        elif isinstance(v, bool):
            v_str = "true" if v else "false"
        elif isinstance(v, int):
            v_str = str(v)
        else:
            v_str = str(v)
        content = content.replace("{" + k + "}", v_str)

    return {"content": content, "template_used": tpl_name, "length": len(content),
            "result": {"content": content}}


@tool_meta(
    name="frida_list_templates",
    description="List available Frida hook templates with descriptions and params",
    params={},
    outputs=["templates", "result"],
)
def frida_list_templates(**kwargs) -> dict:
    """List all available hook templates.

    Returns:
        Dict with templates list, result.
    """
    templates = []
    for name, info in FRIDA_TEMPLATES.items():
        templates.append({
            "name": name,
            "description": info["description"],
            "params": info["params"],
        })
    return {"templates": templates, "count": len(templates), "result": templates}


# ------------------------------------------------------------------
# Script Combinator
# ------------------------------------------------------------------

@tool_meta(
    name="frida_combine_scripts",
    description="Combine multiple Frida scripts into one file for simultaneous execution",
    params={
        "script_refs": "List of 'category.name' references to combine",
        "output_name": "Output file name (without .js)",
    },
    outputs=["combined_path", "scripts_combined", "result"],
)
def frida_combine_scripts(script_refs: list | None = None,
                          output_name: str = "", **kwargs) -> dict:
    """Merge multiple Frida scripts into a single combined script.

    Args:
        script_refs: List of "category.name" refs (e.g. ["ssl_bypass.universal_unpin", "traffic.traffic_dump"])
        output_name: Output file name

    Returns:
        Dict with combined_path, scripts_combined, result.
    """
    refs = script_refs or kwargs.get("script_refs", []) or []
    out_name = output_name or kwargs.get("output_name", "combined")

    _ensure_scripts_dir()
    sources: list[str] = []
    labels: list[str] = []

    for ref in refs:
        if "." not in ref:
            continue
        cat, name = ref.split(".", 1)
        path = _SCRIPTS_DIR / cat / f"{name}.js"

        if not path.exists():
            # Try as template-generated
            logger.warning("Script not found, skipping: %s", path)
            continue

        source = path.read_text(encoding="utf-8", errors="ignore")
        sources.append(f"// === [{cat}/{name}] ===\n{source}")
        labels.append(f"{cat}/{name}")

    if not sources:
        return {"error": "No valid script references provided", "combined_path": "",
                "scripts_combined": 0, "result": {}}

    combined = (
        "// Combined Frida script — auto-generated\n"
        f"// Includes: {', '.join(labels)}\n"
        "// =============================================\n\n"
    )
    combined += "\n\n".join(sources)

    out_path = _SCRIPTS_DIR / "combined" / f"{out_name}.js"
    out_path.parent.mkdir(exist_ok=True)
    out_path.write_text(combined, encoding="utf-8")

    logger.info("Combined script saved: %s (%d scripts)", out_path, len(sources))
    return {
        "combined_path": str(out_path),
        "scripts_combined": len(sources),
        "labels": labels,
        "result": {"path": str(out_path), "size": out_path.stat().st_size},
    }


# ------------------------------------------------------------------
# Script Execution
# ------------------------------------------------------------------


def _frida_available() -> bool:
    """Check if frida CLI is available."""
    try:
        subprocess.run(["frida", "--version"], capture_output=True, text=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


@tool_meta(
    name="frida_run_script",
    description="Run a Frida script against a target Android app (spawn or attach mode)",
    params={
        "package": "Android package name",
        "script_ref": "Script reference 'category.name' or full path",
        "mode": "spawn (default) or attach",
        "device": "usb (default) or network host:port",
        "timeout": "Execution timeout in seconds (default 60)",
        "output_log": "Path to save output log",
    },
    outputs=["output", "log_path", "result"],
)
def frida_run_script(package: str = "", script_ref: str = "",
                     mode: str = "spawn", device: str = "usb",
                     timeout: int = 60, output_log: str = "", **kwargs) -> dict:
    """Run a Frida script against a target Android app.

    Supports:
      - Spawn mode: launch app and inject
      - Attach mode: hook into running process

    Args:
        package: Android package name (e.g. com.target.app)
        script_ref: 'category.name' or full file path to .js script
        mode: 'spawn' (launch app) or 'attach' (running app)
        device: 'usb' or 'host:port' for remote device
        timeout: Execution timeout in seconds
        output_log: Optional file path to save output

    Returns:
        Dict with output, log_path, result.
    """
    pkg = package or kwargs.get("package", "")
    ref = script_ref or kwargs.get("script_ref", "")
    mod = mode or kwargs.get("mode", "spawn")
    dev = device or kwargs.get("device", "usb")
    to = timeout or kwargs.get("timeout", 60)
    log = output_log or kwargs.get("output_log", "")

    if not pkg or not ref:
        return {"error": "package and script_ref required", "output": "",
                "result": {}}
    if not _frida_available():
        return {"error": "frida CLI not found. Install: pip install frida-tools",
                "output": "", "result": {}}

    # Resolve script path
    script_path = _resolve_script_path(ref)
    if not script_path or not Path(script_path).exists():
        return {"error": f"Script not found: {ref}", "output": "", "result": {}}

    # Build frida command
    cmd = []

    if dev == "usb":
        cmd.extend(["frida", "-U"])
    elif ":" in dev:
        # Remote device via AGENTS.md convention: -H 127.0.0.1:27043
        cmd.extend(["frida", "-H", dev])
    else:
        cmd.extend(["frida", "-U"])

    if mod == "spawn":
        cmd.extend(["-f", pkg, "--no-pause"])
    else:
        cmd.extend(["-n", pkg])

    cmd.extend(["-l", script_path])

    if log:
        cmd.extend(["-o", log])

    logger.info("Running Frida: %s", " ".join(cmd[:8]) + " ...")

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=to,
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "TIMEOUT: Frida process did not complete within " + str(to) + "s"
    except Exception as e:
        output = f"ERROR: {e}"

    if log:
        Path(log).write_text(output, encoding="utf-8")

    return {
        "output": output[:3000],
        "log_path": log or "",
        "full_output_length": len(output),
        "result": {"output": output[:3000]},
    }


def _resolve_script_path(ref: str) -> str:
    """Resolve 'category.name' to full path, or return as-is if already a path."""
    if Path(ref).exists():
        return ref
    if "." in ref:
        cat, name = ref.split(".", 1)
        path = _SCRIPTS_DIR / cat / f"{name}.js"
        if path.exists():
            return str(path)
    return ref


# ------------------------------------------------------------------
# Auto-hook Generation from Decompiled Source
# ------------------------------------------------------------------

@tool_meta(
    name="frida_auto_hook",
    description="Scan decompiled source and auto-generate Frida hooks for interesting classes",
    params={
        "input": "Decompiled source directory (jadx output)",
        "target_package": "Target app package name (optional)",
        "max_hooks": "Maximum number of hooks to generate (default 20)",
    },
    outputs=["generated_scripts", "classes_found", "result"],
)
def frida_auto_hook(input: str = "", target_package: str = "",
                    max_hooks: int = 20, **kwargs) -> dict:
    """Automatically generate Frida hooks from decompiled Java source.

    Scans source for interesting classes (crypto, network, storage, okhttp,
    SharedPreferences, WebView, JSON, SQLite) and generates hook scripts.

    Args:
        input: Decompiled source directory
        target_package: Target package name (to filter)
        max_hooks: Maximum number of hooks

    Returns:
        Dict with generated scripts, classes found, result.
    """
    decompile_dir = input or kwargs.get("input", "")
    tgt_pkg = target_package or kwargs.get("target_package", "")

    src_dirs = [
        Path(decompile_dir) / "sources",
        Path(decompile_dir) / "resources",
    ]

    java_files: list[Path] = []
    for d in src_dirs:
        if d.exists():
            java_files.extend(d.rglob("*.java"))

    if not java_files:
        return {"error": "No Java source files found in " + decompile_dir,
                "generated_scripts": [], "classes_found": [], "result": {}}

    interesting_classes: dict[str, list[str]] = {}
    for f in java_files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rel = str(f.relative_to(Path(decompile_dir)))
        for pattern, category in _INTERESTING_CLASS_PATTERNS:
            for m in re.finditer(pattern, text):
                cls = m.group(0)
                if cls not in interesting_classes:
                    interesting_classes[cls] = []
                if category not in interesting_classes[cls]:
                    interesting_classes[cls].append(category)

    # Apply package filter
    if tgt_pkg:
        filtered = {k: v for k, v in interesting_classes.items() if tgt_pkg.replace(".", "/") in k.lower() or tgt_pkg.split(".")[-1].lower() in k.lower()}
        if filtered:
            interesting_classes = filtered

    if not interesting_classes:
        return {"info": "No interesting classes found. Try without target_package filter.",
                "generated_scripts": [], "classes_found": [], "result": {}}

    # Generate hook scripts
    generated: list[dict] = []
    count = 0
    for cls, categories in sorted(interesting_classes.items(), key=lambda x: -len(x[1])):
        if count >= max_hooks:
            break

        label = cls.split(".")[-1]
        gen = frida_generate_script(template_name="hook_method", params={
            "class_name": cls,
            "method_name": "toString",
            "overloads": "[]",
            "pre_hook": "",
            "post_hook": "",
            "label": label,
        })
        if "content" in gen and gen["content"]:
            name = f"auto_hook_{label.lower()}_{count}"
            frida_save_script(name=name, category="custom", content=gen["content"])
            generated.append({
                "class": cls,
                "categories": categories,
                "script_name": name,
                "hint": _hook_hint(categories),
            })
            count += 1

    return {
        "generated_scripts": generated,
        "classes_found": list(interesting_classes.keys()),
        "total_classes": len(interesting_classes),
        "hooks_generated": len(generated),
        "result": {"generated": generated, "classes": list(interesting_classes.keys())},
    }


def _hook_hint(categories: list[str]) -> str:
    """Suggest what to hook based on category."""
    hints = {
        "okhttp": "Hook OkHttpClient.newCall() to intercept network requests",
        "retrofit": "Hook Retrofit.create() to trace API calls",
        "crypto": "Hook Cipher.init() to log encryption keys",
        "shared_prefs": "Hook SharedPreferences.getString() to log data access",
        "sqlite": "Hook SQLiteDatabase.rawQuery() to capture SQL queries",
        "network": "Hook URL.openConnection() to trace HTTP traffic",
        "webview": "Hook WebView.loadUrl() and addJavascriptInterface() for RCE vectors",
        "json": "Hook JSONObject.toString() to capture serialised data",
        "third_party_sdk": "Check SDK docs for known hook points",
    }
    return "; ".join(hints.get(c, f"Hook {c} methods") for c in categories)


# ------------------------------------------------------------------
# Runtime Discovery
# ------------------------------------------------------------------

@tool_meta(
    name="frida_enumerate_classes",
    description="List loaded Java classes from a running Android app via Frida",
    params={
        "package": "Android package name",
        "filter": "Optional substring filter for class names",
        "device": "usb (default) or host:port",
    },
    outputs=["classes", "count", "result"],
)
def frida_enumerate_classes(package: str = "", filter_str: str = "",
                            device: str = "usb", **kwargs) -> dict:
    """Enumerate loaded Java classes from a running process via Frida.

    Runs a Frida script that dumps all loaded classes matching the optional filter.

    Args:
        package: Android package name
        filter_str: Optional filter (class name contains this string)
        device: usb or host:port

    Returns:
        Dict with classes, count, result.
    """
    pkg = package or kwargs.get("package", "")
    flt = filter_str or kwargs.get("filter_str", "")
    dev = device or kwargs.get("device", "usb")

    if not pkg:
        return {"error": "package required", "classes": [], "count": 0, "result": {}}
    if not _frida_available():
        return {"error": "frida CLI not found", "classes": [], "count": 0, "result": {}}

    # Build a script that dumps classes
    script = """
Java.perform(function() {
    var classes = Java.enumerateLoadedClassesSync();
    classes.forEach(function(cls) {
        if (cls.indexOf('FILTER_PLACEHOLDER') !== -1) {
            send(cls);
        }
    });
});
""".replace("FILTER_PLACEHOLDER", flt or "")

    tmp_script = _SCRIPTS_DIR / "custom" / "_tmp_enum.js"
    tmp_script.parent.mkdir(exist_ok=True)
    tmp_script.write_text(script, encoding="utf-8")

    cmd = ["frida", "-U", "-n", pkg, "-l", str(tmp_script), "-q"]
    if ":" in dev:
        cmd = ["frida", "-H", dev, "-n", pkg, "-l", str(tmp_script), "-q"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

        # Parse send() messages from Frida output
        classes = []
        for line in result.stdout.split("\n"):
            line = line.strip()
            if line and not line.startswith("[") and not line.startswith("("):
                if flt and flt.lower() in line.lower():
                    classes.append(line)
                elif not flt:
                    classes.append(line)

    except subprocess.TimeoutExpired:
        return {"error": "Frida timed out", "classes": [], "count": 0, "result": {}}
    except Exception as e:
        return {"error": str(e), "classes": [], "count": 0, "result": {}}
    finally:
        if tmp_script.exists():
            tmp_script.unlink()

    return {
        "classes": classes,
        "count": len(classes),
        "result": {"classes": classes},
    }


# ------------------------------------------------------------------
# High-level workflow tools
# ------------------------------------------------------------------

@tool_meta(
    name="frida_bypass_all",
    description="Run combined SSL unpin + root bypass + proxy force on target app",
    params={
        "package": "Android package name",
        "proxy_host": "Proxy host (default 127.0.0.1)",
        "proxy_port": "Proxy port (default 8080)",
        "mode": "spawn or attach",
    },
    outputs=["output", "result"],
)
def frida_bypass_all(package: str = "", proxy_host: str = "127.0.0.1",
                     proxy_port: int = 8080, mode: str = "spawn", **kwargs) -> dict:
    """Run combined bypass: SSL unpin + root bypass + proxy force in one shot.

    Uses the combined script pipeline for simultaneous instrumentation.

    Args:
        package: Android package name
        proxy_host: Proxy hostname
        proxy_port: Proxy port
        mode: spawn or attach

    Returns:
        Dict with output, result.
    """
    pkg = package or kwargs.get("package", "")
    ph = proxy_host or kwargs.get("proxy_host", "127.0.0.1")
    pp = proxy_port or kwargs.get("proxy_port", 8080)
    mod = mode or kwargs.get("mode", "spawn")

    if not pkg:
        return {"error": "package required", "output": "", "result": {}}

    if not _frida_available():
        return {"error": "frida CLI not found", "output": "", "result": {}}

    # Build combined script
    parts = [
        frida_generate_script(template_name="bypass_ssl_universal")["content"],
        frida_generate_script(template_name="bypass_rootbeer")["content"],
        frida_generate_script(template_name="force_proxy",
                              params={"proxy_host": ph, "proxy_port": str(pp)})["content"],
    ]

    combined = (
        "// frida_bypass_all — combined SSL unpin + root bypass + proxy force\n"
        "// Generated by opendroid Frida Manager\n"
        "// =============================================\n\n"
    )
    combined += "\n\n".join(parts)

    tmp_path = _SCRIPTS_DIR / "combined" / "_bypass_all.js"
    tmp_path.parent.mkdir(exist_ok=True)
    tmp_path.write_text(combined, encoding="utf-8")

    cmd = ["frida", "-U"]
    if ":" in str(kwargs.get("device", "usb")):
        cmd = ["frida", "-H", str(kwargs.get("device", "usb"))]
    if mod == "spawn":
        cmd.extend(["-f", pkg, "--no-pause"])
    else:
        cmd.extend(["-n", pkg])
    cmd.extend(["-l", str(tmp_path)])
    cmd.extend(["-o", str(_SCRIPTS_DIR / "combined" / f"bypass_all_{pkg}.log")])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "Bypass completed (timeout after 120s — hooks likely active)"
    except Exception as e:
        output = f"ERROR: {e}"
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

    return {
        "output": output[:2000],
        "result": {"output": output[:2000]},
    }


# ------------------------------------------------------------------
# Environment
# ------------------------------------------------------------------

@tool_meta(
    name="frida_check_env",
    description="Check Frida environment: CLI, device, server",
    params={},
    outputs=["frida_available", "device_connected", "result"],
)
def frida_check_env(**kwargs) -> dict:
    """Check if Frida environment is ready.

    Returns:
        Dict with status of CLI, device connection, server.
    """
    result = {"frida_available": False, "frida_version": "", "device_connected": False}

    # Check frida CLI
    try:
        r = subprocess.run(["frida", "--version"], capture_output=True, text=True, timeout=5)
        result["frida_available"] = r.returncode == 0
        result["frida_version"] = r.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        result["frida_available"] = False

    # Check devices
    if result["frida_available"]:
        try:
            r = subprocess.run(["frida-ls-devices"], capture_output=True, text=True, timeout=10)
            devices = [l for l in r.stdout.strip().split("\n") if l and ":" in l]
            result["device_connected"] = len(devices) > 0
            result["devices"] = [d.strip() for d in devices[:5]]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            result["device_connected"] = False

    return {
        "frida_available": result["frida_available"],
        "frida_version": result.get("frida_version", ""),
        "device_connected": result["device_connected"],
        "devices": result.get("devices", []),
        "result": result,
    }
