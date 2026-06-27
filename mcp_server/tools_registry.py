"""Tool registry for Bug Bounty MCP Server.

All tools are registered against the FastMCP instance from server.py.
"""

import json
import logging
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.session import ServerSession

from mcp_server.server import mcp, get_burp

from burp_mcp.client import BurpClient
from burp_mcp.errors import BurpConnectionError

from tools.http_tools import send_http, parse_http_response, extract_urls, extract_forms
from tools.analysis import analyze_response, analyze_proxy_item, AnalysisResult
from tools.fuzzing import (
    fuzz_get_param, fuzz_post_param, fuzz_path, fuzz_headers,
    get_payloads, analyze_fuzz_results, FuzzResult,
)
from tools.recon import (
    run_subfinder, run_httpx, run_nuclei, run_ffuf,
    run_katana, run_gau, run_full_recon, ensure_tools,
)
from tools.apk_analyzer import analyze_apk, generate_apk_report
from tools.intercept import InterceptSession, MitmproxyController, InterceptRule
from tools.android_tools import (
    set_proxy, remove_proxy, decompile_apk, extract_manifest,
    extract_endpoints, extract_secrets, unpin_certificate,
    frida_list_devices, frida_list_processes, list_packages,
)

logger = logging.getLogger(__name__)

# ============================================================================
# Burp Suite Tools
# ============================================================================


@mcp.tool()
def burp_connect() -> str:
    """Test connection to BurpSuite MCP server."""
    try:
        client = BurpClient()
        client.connect()
        client.initialize()
        tools = client.list_tools()
        client.close()
        tool_names = [t["name"] for t in (tools or [])]
        return json.dumps({
            "status": "ok",
            "session": client.session_id,
            "tools_available": len(tool_names),
            "tools": tool_names,
        }, indent=2)
    except BurpConnectionError as e:
        return json.dumps({"status": "error", "message": str(e)}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, indent=2)


@mcp.tool()
def burp_status() -> str:
    """Get BurpSuite MCP connection status."""
    try:
        client = get_burp()
        return json.dumps({
            "connected": client.session_id is not None,
            "session_id": client.session_id,
        }, indent=2)
    except Exception as e:
        return json.dumps({"connected": False, "error": str(e)}, indent=2)


@mcp.tool()
def send_http_request(
    method: str = "GET",
    url: str = "",
    headers: str = "{}",
    body: str = "",
    use_burp: bool = True,
) -> str:
    """Send an HTTP request through Burp Suite or directly.

    Args:
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        url: Full URL including scheme, host, path, query
        headers: JSON string of headers dict
        body: Request body for POST/PUT requests
        use_burp: True to send through Burp, False for direct

    Returns:
        JSON response with status_code, headers, body
    """
    try:
        hdrs = json.loads(headers) if headers else {}
    except json.JSONDecodeError:
        hdrs = {}

    burp_client = get_burp() if use_burp else None
    resp = send_http(method, url, hdrs, body, use_burp, burp_client)
    if resp is None:
        return json.dumps({"error": "No response received"}, indent=2)

    return json.dumps({
        "status_code": resp.get("status_code", 0),
        "reason": resp.get("reason", ""),
        "headers": resp.get("headers", {}),
        "body_preview": resp.get("body", "")[:2000],
        "body_length": len(resp.get("body", "") or ""),
    }, indent=2)


@mcp.tool()
def proxy_history(count: int = 5, regex: str = "") -> str:
    """Read Burp Suite proxy HTTP history.

    Args:
        count: Number of history entries to retrieve (default: 5)
        regex: Optional regex filter for URLs

    Returns:
        JSON list of request/response pairs
    """
    try:
        client = get_burp()
        if regex:
            result = client.get_proxy_history_regex(regex, offset=0, count=count)
        else:
            result = client.get_proxy_history(offset=0, count=count)
        if result is None:
            return json.dumps({"error": "No history data returned"}, indent=2)
        return json.dumps(result, indent=2, default=str)[:5000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def intercept(action: str = "status") -> str:
    """Control Burp Suite proxy intercept.

    Args:
        action: "enable" to turn on intercept,
                "disable" to forward all requests,
                "status" to check current state

    Returns:
        Status message
    """
    try:
        client = get_burp()
        if action == "enable":
            client.set_intercept(True)
            return json.dumps({"status": "intercept enabled"}, indent=2)
        elif action == "disable":
            client.set_intercept(False)
            return json.dumps({"status": "intercept disabled (forwarding)"}, indent=2)
        else:
            return json.dumps({"status": "check Burp GUI for current state"}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def burp_list_tools() -> str:
    """List all available Burp MCP tools."""
    try:
        client = get_burp()
        tools = client.list_tools()
        if tools is None:
            return json.dumps({"error": "Could not list tools"}, indent=2)
        return json.dumps({"tools": tools}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


# ============================================================================
# Analysis Tools
# ============================================================================


@mcp.tool()
def analyze_http_response(
    status_code: int = 0,
    headers: str = "{}",
    body: str = "",
) -> str:
    """Analyze an HTTP response for security vulnerabilities.

    Detects: SQL injection errors, XSS reflection, debug pages,
    information disclosure, CORS misconfig, directory listing, etc.

    Args:
        status_code: HTTP status code
        headers: JSON string of response headers
        body: Response body text

    Returns:
        JSON analysis result with findings and tech stack
    """
    try:
        hdrs = json.loads(headers) if headers else {}
    except json.JSONDecodeError:
        hdrs = {}

    result = analyze_response(status_code, hdrs, body)
    return json.dumps(result.to_dict(), indent=2)


@mcp.tool()
def analyze_last_request(count: int = 1) -> str:
    """Analyze the most recent request/response from proxy history.

    Args:
        count: Number of recent entries to analyze

    Returns:
        JSON analysis results
    """
    try:
        client = get_burp()
        history = client.get_proxy_history(offset=0, count=count)
        if not history:
            return json.dumps({"error": "No history entries"}, indent=2)

        results = []
        items = history.get("content") if isinstance(history, dict) else history
        if isinstance(items, list):
            for i, item in enumerate(items):
                analysis = analyze_proxy_item(item, request_id=i)
                results.append(analysis.to_dict())

        return json.dumps(results, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


# ============================================================================
# Recon Tools
# ============================================================================


@mcp.tool()
def recon_subdomains(domain: str = "") -> str:
    """Run passive subdomain enumeration via subfinder in WSL2.

    Args:
        domain: Target domain (e.g. "example.com")

    Returns:
        JSON list of discovered subdomains
    """
    if not domain:
        return json.dumps({"error": "domain is required"}, indent=2)
    try:
        subs = run_subfinder(domain)
        return json.dumps({"domain": domain, "count": len(subs), "subdomains": subs}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def recon_check_tools() -> str:
    """Check which recon tools are available in WSL2.

    Returns:
        JSON dict of tool availability
    """
    return json.dumps(ensure_tools(), indent=2)


@mcp.tool()
def run_nuclei_scan(
    targets: str = "",
    templates: str = "",
    severity: str = "",
) -> str:
    """Run nuclei vulnerability scanner against targets.

    Args:
        targets: Comma-separated list of target URLs
        templates: Template filter (e.g. "cves/", "misconfiguration/")
        severity: Severity filter (e.g. "critical,high")

    Returns:
        JSON list of vulnerability findings
    """
    if not targets:
        return json.dumps({"error": "targets required (comma-separated)"}, indent=2)
    try:
        target_list = [t.strip() for t in targets.split(",") if t.strip()]
        findings = run_nuclei(target_list, templates, severity)
        return json.dumps({"count": len(findings), "findings": findings}, indent=2, default=str)[:10000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def run_full_recon_pipeline(domain: str = "") -> str:
    """Run complete recon pipeline: subfinder -> httpx -> nuclei.

    Args:
        domain: Target domain

    Returns:
        JSON with subdomains, live hosts, and vulnerabilities
    """
    if not domain:
        return json.dumps({"error": "domain is required"}, indent=2)
    try:
        results = run_full_recon(domain)
        return json.dumps(results, indent=2, default=str)[:10000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


# ============================================================================
# Fuzzing Tools
# ============================================================================


@mcp.tool()
def fuzz_parameter(
    url: str = "",
    param: str = "",
    payload_type: str = "xss",
    method: str = "GET",
) -> str:
    """Fuzz a URL parameter with payloads.

    Args:
        url: Target URL
        param: Parameter name to fuzz
        payload_type: "xss", "sqli", "dirs", or "params"
        method: HTTP method ("GET" or "POST")

    Returns:
        JSON list of interesting results
    """
    if not url or not param:
        return json.dumps({"error": "url and param are required"}, indent=2)

    try:
        burp_client = get_burp()
        if method.upper() == "POST":
            results = fuzz_post_param(url, param, payload_type=payload_type,
                                      use_burp=True, burp_client=burp_client)
        else:
            results = fuzz_get_param(url, param, payload_type=payload_type,
                                     use_burp=True, burp_client=burp_client)

        findings = analyze_fuzz_results(results)
        return json.dumps({
            "param": param,
            "payload_type": payload_type,
            "total_tested": len(get_payloads(payload_type)),
            "interesting": len(results),
            "results": [
                {"payload": r.payload[:50], "status": r.status_code,
                 "reason": r.reason, "response_time": round(r.response_time, 2)}
                for r in results
            ],
            "findings": findings,
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def fuzz_url_path(
    base_url: str = "",
    wordlist_type: str = "dirs",
) -> str:
    """Fuzz URL paths to discover hidden endpoints.

    Args:
        base_url: Base URL (e.g. "https://example.com")
        wordlist_type: "dirs" for common paths, "params" for parameter names

    Returns:
        JSON list of discovered paths
    """
    if not base_url:
        return json.dumps({"error": "base_url is required"}, indent=2)

    try:
        burp_client = get_burp()
        results = fuzz_path(base_url, wordlist_type, use_burp=True, burp_client=burp_client)
        return json.dumps({
            "base_url": base_url,
            "discovered": len(results),
            "results": [
                {"path": r.payload, "status": r.status_code,
                 "size": r.body_length, "reason": r.reason}
                for r in results
            ],
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


# ============================================================================
# Android Tools
# ============================================================================


@mcp.tool()
def android_proxy(action: str = "status", port: int = 8080) -> str:
    """Set or remove HTTP proxy on Android emulator/device.

    Args:
        action: "set" to configure proxy (10.0.2.2),
                "remove" to clear proxy,
                "status" to check
        port: Burp proxy port (default: 8080)

    Returns:
        Status message
    """
    try:
        if action == "set":
            result = set_proxy(port=port)
            return json.dumps({"status": "proxy set", "proxy": f"10.0.2.2:{port}"}, indent=2)
        elif action == "remove":
            remove_proxy()
            return json.dumps({"status": "proxy removed"}, indent=2)
        else:
            return json.dumps({"status": "use 'set' or 'remove' actions"}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def decompile_android_apk(apk_path: str = "", output_dir: str = "decompiled") -> str:
    """Decompile an APK file and analyze its contents.

    Args:
        apk_path: Path to APK file on Windows
        output_dir: Output directory for decompiled code

    Returns:
        JSON analysis result with manifest, endpoints, secrets
    """
    if not apk_path:
        return json.dumps({"error": "apk_path is required"}, indent=2)

    try:
        analysis = analyze_apk(apk_path, output_dir)
        return json.dumps(analysis.to_dict(), indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def bypass_ssl_pinning(
    package: str = "",
    method: str = "frida",
) -> str:
    """Bypass SSL certificate pinning on Android app.

    Args:
        package: Android package name (e.g. "com.target.app")
        method: "frida" (default) or "objection"

    Returns:
        Status message
    """
    if not package:
        return json.dumps({"error": "package is required"}, indent=2)

    try:
        output = unpin_certificate(package, method=method)
        return json.dumps({
            "status": "started",
            "package": package,
            "method": method,
            "output_preview": output[:500],
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def android_list_packages(filter_str: str = "") -> str:
    """List installed packages on Android device/emulator.

    Args:
        filter_str: Optional filter string

    Returns:
        JSON list of package names
    """
    try:
        packages = list_packages(filter_str if filter_str else None)
        return json.dumps({"count": len(packages), "packages": packages}, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


# ============================================================================
# Report Generation
# ============================================================================


@mcp.tool()
def generate_vulnerability_report(findings: str = "[]") -> str:
    """Generate a bug bounty report from findings.

    Args:
        findings: JSON string of findings list.
            Each finding should have: type, severity, description, evidence, url

    Returns:
        Markdown formatted bug bounty report
    """
    try:
        data = json.loads(findings) if isinstance(findings, str) else findings
    except json.JSONDecodeError:
        data = []

    lines = [
        "# Bug Bounty Report",
        "",
    ]

    # Summary
    severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in data:
        sev = f.get("severity", "info").lower()
        if sev in severity_count:
            severity_count[sev] += 1

    lines.extend(["## Summary", ""])
    lines.append(f"- **Critical**: {severity_count['critical']}")
    lines.append(f"- **High**: {severity_count['high']}")
    lines.append(f"- **Medium**: {severity_count['medium']}")
    lines.append(f"- **Low**: {severity_count['low']}")
    lines.append(f"- **Info**: {severity_count['info']}")
    lines.append(f"- **Total**: {len(data)}")
    lines.append("")

    # Findings
    if data:
        lines.extend(["## Findings", ""])
        for i, f in enumerate(data, 1):
            sev = f.get("severity", "info").upper()
            desc = f.get("description", "No description")
            url = f.get("url", "")
            evidence = f.get("evidence", "")
            vuln_type = f.get("type", "")

            lines.append(f"### {i}. [{sev}] {desc}")
            if url:
                lines.append(f"- **URL**: `{url}`")
            if vuln_type:
                lines.append(f"- **Type**: `{vuln_type}`")
            if evidence:
                lines.append(f"- **Evidence**: `{evidence[:200]}`")
            lines.append("")

    lines.append("---")
    lines.append("*Generated by Bug Bounty Hunter MCP*")

    return "\n".join(lines)


# ============================================================================
# Workflow Tools
# ============================================================================

from tools.workflow import WorkflowEngine, ToolRegistry, WorkflowError as WFError
from tools.storage import StorageManager

_WORKFLOW_DIR = Path(__file__).resolve().parent.parent / "workflows"
_storage_instance: StorageManager | None = None


def _get_storage() -> StorageManager:
    global _storage_instance
    if _storage_instance is None:
        _storage_instance = StorageManager("workspace").init()
    return _storage_instance


@mcp.tool()
def workflow_run(workflow_name: str = "default", apk_path: str = "",
                 package_name: str = "", version_name: str = "") -> str:
    """Execute a workflow for an Android target.

    Loads the workflow YAML from workflows/, creates/gets the target,
    and executes all phases. All results are stored in the workspace DB.

    Args:
        workflow_name: Workflow file name (without .yaml), default: "default"
        apk_path: Path to APK file
        package_name: Android package name (e.g. "com.target.app")
        version_name: App version string (optional)

    Returns:
        JSON with workflow execution status and summary
    """
    if not apk_path and not package_name:
        return json.dumps({"error": "apk_path or package_name required"}, indent=2)

    try:
        storage = _get_storage()
        wf_path = _WORKFLOW_DIR / f"{workflow_name}.yaml"
        if not wf_path.exists():
            return json.dumps({"error": f"Workflow '{workflow_name}' not found at {wf_path}"}, indent=2)

        if not package_name:
            from pathlib import Path as PPath
            package_name = PPath(apk_path).stem

        target_id = storage.create_target(package_name, version_name=version_name)
        if apk_path:
            storage.save_apk(target_id, apk_path, version_name=version_name)

        engine = WorkflowEngine(storage)
        engine.load(str(wf_path))
        results = engine.execute(target_id, apk_path)

        # Summary
        findings = storage.get_findings(target_id)
        endpoints = storage._fetchall(
            "SELECT COUNT(*) AS c FROM endpoints WHERE target_id=?", (target_id,)
        )[0]["c"]
        secrets = storage._fetchall(
            "SELECT COUNT(*) AS c FROM secrets WHERE target_id=?", (target_id,)
        )[0]["c"]

        return json.dumps({
            "status": "completed",
            "target_id": target_id,
            "package": package_name,
            "workflow": workflow_name,
            "findings": len(findings),
            "endpoints": endpoints,
            "secrets": secrets,
            "summary": {
                "critical": sum(1 for f in findings if f.get("severity") == "critical"),
                "high": sum(1 for f in findings if f.get("severity") == "high"),
                "medium": sum(1 for f in findings if f.get("severity") == "medium"),
                "low": sum(1 for f in findings if f.get("severity") == "low"),
            },
        }, indent=2)

    except WFError as e:
        return json.dumps({"status": "failed", "error": str(e)}, indent=2)
    except Exception as e:
        return json.dumps({"status": "failed", "error": str(e)}, indent=2)


@mcp.tool()
def workflow_list() -> str:
    """List available workflow definitions.

    Returns:
        JSON list of available workflows with metadata
    """
    workflows = []
    for f in sorted(_WORKFLOW_DIR.glob("*.yaml")):
        try:
            import yaml
            with open(f) as fh:
                data = yaml.safe_load(fh)
            workflows.append({
                "name": f.stem,
                "title": data.get("name", f.stem),
                "version": data.get("version", "?"),
                "author": data.get("author", "?"),
                "description": data.get("description", "")[:120],
                "phases": len(data.get("phases", [])),
            })
        except Exception:
            workflows.append({"name": f.stem, "error": "parse failed"})

    return json.dumps({"workflows": workflows}, indent=2)


@mcp.tool()
def workflow_status(target_id: int = 0) -> str:
    """Check workflow execution status and results for a target.

    Args:
        target_id: Target ID from workflow_run result

    Returns:
        JSON with analysis runs, findings, and statistics
    """
    if not target_id:
        return json.dumps({"error": "target_id is required"}, indent=2)

    try:
        storage = _get_storage()
        target = storage.get_target(target_id)
        if not target:
            return json.dumps({"error": f"Target {target_id} not found"}, indent=2)

        runs = storage.list_runs(target_id)
        findings = storage.get_findings(target_id)
        report = storage.generate_report(target_id)

        return json.dumps({
            "target": target,
            "runs": runs,
            "findings_count": len(findings),
            "findings_by_severity": {
                "critical": sum(1 for f in findings if f.get("severity") == "critical"),
                "high": sum(1 for f in findings if f.get("severity") == "high"),
                "medium": sum(1 for f in findings if f.get("severity") == "medium"),
                "low": sum(1 for f in findings if f.get("severity") == "low"),
            },
            "report": report[:3000],
        }, indent=2, default=str)

    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def storage_summary() -> str:
    """Get workspace storage summary across all targets.

    Returns:
        JSON with all targets, totals, and statistics
    """
    try:
        storage = _get_storage()
        targets = storage.list_targets()
        summary = storage.get_all_summary()
        totals = {
            "targets": len(targets),
            "findings": sum(t.get("findings", 0) for t in summary),
            "endpoints": sum(t.get("endpoints", 0) for t in summary),
            "secrets": sum(t.get("secrets", 0) for t in summary),
            "apks": sum(t.get("apks", 0) for t in summary),
            "subdomains": sum(t.get("subdomains", 0) for t in summary),
        }
        return json.dumps({"totals": totals, "targets": summary}, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)
