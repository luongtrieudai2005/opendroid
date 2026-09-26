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
from tools.osint_tools import (
    github_dorker, crtsh_enum, shodan_lookup, tech_intel,
)
from tools.business_logic import (
    fare_check, gps_spoofing_check, promo_validator,
    referral_check, race_tester, otp_tester,
)
from tools.mobsf_integration import mobsf_upload, mobsf_scan, mobsf_analyze, mobsf_apk_diff
from tools.dynamic_sandbox import (
    sandbox_dump_databases, sandbox_dump_preferences, sandbox_dump_logs,
    sandbox_dump_filesystem, sandbox_full_dump, sandbox_analyze_sqlite,
)
from tools.flutter_tools import (
    flutter_detect_apk, flutter_extract_lib, flutter_reflutter_patch,
    flutter_sign_apk, flutter_deploy_patched, flutter_pull_dump,
    flutter_parse_dump, flutter_blutter_analyze, flutter_blutter_parse_pp,
    flutter_blutter_parse_frida, flutter_tls_bypass_frida,
    flutter_tls_bypass_reflutter, flutter_full_analyze,
)
from tools.android_intent_tools import (
    intent_redirection_finder, deep_link_fuzzer,
    component_fuzzer, content_provider_scanner,
)
from tools.api_scanner import graphql_scanner, idor_scanner, param_tamper_scanner, jwt_analyzer
from tools.workflow import tool_meta

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
        payload = json.dumps({"count": len(findings), "findings": findings},
                             indent=2, default=str)
        truncated = len(payload) > 100000
        return payload[:100000] + ('\n{"truncated": true}' if truncated else "")
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def recon_httpx(targets: str = "", max_hosts: int = 200) -> str:
    """Probe hosts with httpx (status codes, tech detection).

    Args:
        targets: Comma-separated hosts or URLs
        max_hosts: Cap on number of hosts probed (default 200)

    Returns:
        JSON list of live-host records (url, status_code, tech, ...)
    """
    if not targets:
        return json.dumps({"error": "targets required (comma-separated)"}, indent=2)
    try:
        t_list = [t.strip() for t in targets.split(",") if t.strip()][:max_hosts]
        hosts = run_httpx(t_list)
        return json.dumps({"count": len(hosts), "hosts": hosts},
                          indent=2, default=str)[:100000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def recon_katana(url: str = "", depth: int = 3) -> str:
    """Crawl a site with katana and return discovered endpoints.

    Args:
        url: Starting URL
        depth: Crawl depth (default 3)

    Returns:
        JSON list of crawled URLs (also written to workspace/recon/ artifacts by run_full_recon_pipeline)
    """
    if not url:
        return json.dumps({"error": "url is required"}, indent=2)
    try:
        urls = run_katana(url, depth=depth)
        return json.dumps({"count": len(urls), "urls": urls}, indent=2)[:100000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def recon_gau(domain: str = "") -> str:
    """Fetch historical URLs for a domain via gau (wayback/otx/commoncrawl).

    Args:
        domain: Target domain (e.g. "example.com")

    Returns:
        JSON list of historical URLs
    """
    if not domain:
        return json.dumps({"error": "domain is required"}, indent=2)
    try:
        urls = run_gau(domain)
        return json.dumps({"count": len(urls), "urls": urls}, indent=2)[:100000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def run_full_recon_pipeline(domain: str = "", max_hosts: int = 200) -> str:
    """Run complete recon pipeline: subfinder -> httpx -> nuclei -> katana.

    Args:
        domain: Target domain
        max_hosts: Cap for httpx probing (default 200)

    Returns:
        JSON with subdomains, live hosts, vulnerabilities, crawled endpoints
        and ``artifact_dir`` (workspace/recon/<domain>/ with subdomains.txt,
        live_hosts.json, nuclei.md, crawled.txt — readable by Read/Grep).
    """
    if not domain:
        return json.dumps({"error": "domain is required"}, indent=2)
    try:
        results = run_full_recon(domain, max_hosts=max_hosts)
        payload = json.dumps(results, indent=2, default=str)
        truncated = len(payload) > 100000
        return payload[:100000] + ('\n{"truncated": true}' if truncated else "")
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
# OSINT & Infrastructure Tools
# ============================================================================


@mcp.tool()
def github_search(query: str = "", max_results: int = 30) -> str:
    """Search GitHub for exposed secrets related to target.

    Args:
        query: Search query (e.g. 'com.grabtaxi.passenger' or 'grabtaxi api key')
        max_results: Maximum results to process (default: 30)

    Returns:
        JSON with findings from GitHub code search
    """
    if not query:
        return json.dumps({"error": "query is required"}, indent=2)
    try:
        result = github_dorker(query=query, max_results=max_results)
        return json.dumps(result, indent=2, default=str)[:8000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def crtsh_search(domain: str = "") -> str:
    """Enumerate subdomains via Certificate Transparency logs (crt.sh).

    Args:
        domain: Target domain (e.g. 'grabtaxi.com')

    Returns:
        JSON list of discovered subdomains
    """
    if not domain:
        return json.dumps({"error": "domain is required"}, indent=2)
    try:
        result = crtsh_enum(domain=domain)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def shodan_infra(query: str = "") -> str:
    """Query Shodan for target infrastructure.

    Args:
        query: Shodan search query (e.g. 'org:Grab' or 'hostname:grabtaxi.com')

    Returns:
        JSON with exposed hosts, ports, and services
    """
    if not query:
        return json.dumps({"error": "query is required"}, indent=2)
    try:
        result = shodan_lookup(query=query)
        return json.dumps(result, indent=2, default=str)[:8000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def tech_intel_gather(company_name: str = "") -> str:
    """Gather tech intelligence from company engineering blog and public resources.

    Args:
        company_name: Company name (e.g. 'Grab')

    Returns:
        JSON with inferred services, technologies, naming patterns
    """
    if not company_name:
        return json.dumps({"error": "company_name is required"}, indent=2)
    try:
        result = tech_intel(company_name=company_name)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


# ============================================================================
# Business Logic Testing Tools
# ============================================================================


@mcp.tool()
def fare_manipulation_test(endpoints: str = "[]", traffic: str = "[]") -> str:
    """Test ride-hailing fare manipulation vectors.

    Args:
        endpoints: JSON array of endpoint dicts with url, method
        traffic: JSON array of captured traffic samples

    Returns:
        JSON findings for fare manipulation
    """
    try:
        ep = json.loads(endpoints) if isinstance(endpoints, str) else endpoints
        tr = json.loads(traffic) if isinstance(traffic, str) else traffic
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON input"}, indent=2)
    try:
        result = fare_check(endpoints=ep, traffic=tr)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def gps_spoof_test(endpoints: str = "[]", traffic: str = "[]") -> str:
    """Test GPS coordinate manipulation on ride-hailing API.

    Args:
        endpoints: JSON array of endpoint dicts
        traffic: JSON array of captured traffic

    Returns:
        JSON findings for GPS spoofing
    """
    try:
        ep = json.loads(endpoints) if isinstance(endpoints, str) else endpoints
        tr = json.loads(traffic) if isinstance(traffic, str) else traffic
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON input"}, indent=2)
    try:
        result = gps_spoofing_check(endpoints=ep, traffic=tr)
        return json.dumps(result, indent=2, default=str)
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


@mcp.tool()
def export_recon_artifacts(target_id: int = 0) -> str:
    """Write opencode/human-readable recon artifacts for a target.

    Creates (under workspace/targets/<package>_<id>/):
      INDEX.md          — entry point: snapshot, TOC, next steps
      recon.md          — full report (no truncation)
      recon.json        — full machine export
      source/MANIFEST.md, api_surface.md, secrets.md, entrypoints.md
      source/interesting/ — curated app sources

    Args:
        target_id: Target ID (see storage_summary)

    Returns:
        JSON dict of written artifact paths + counts
    """
    if not target_id:
        return json.dumps({"error": "target_id required (see storage_summary)"},
                          indent=2)
    try:
        from tools.recon_artifacts import write_target_artifacts
        paths = write_target_artifacts(target_id, storage=_get_storage())
        return json.dumps(paths, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def report_generate(target_id: int = 0, format: str = "markdown",
                    output: str = "") -> str:
    """(Re)render the target report and refresh all recon artifacts.

    Args:
        target_id: Target ID
        format: "markdown" (default) or "json"
        output: Optional file path to write the report to
                (e.g. "workspace/report.md"; parent dirs are created)

    Returns:
        JSON with report text, report_path and artifact paths
    """
    if not target_id:
        return json.dumps({"error": "target_id required"}, indent=2)
    try:
        from tools.workflow_tools import report_generator
        result = report_generator(target_id=target_id, format=format,
                                  output=output, _storage=_get_storage())
        payload = dict(result)
        payload.pop("_storage", None)
        return json.dumps(payload, indent=2, default=str)[:100000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def sast_scan(decompile_dir: str = "", target_id: int = 0) -> str:
    """Rule-based SAST over decompiled Android sources.

    Scans TLS/crypto, WebView, IPC (intent redirection, exported/unguarded,
    deep-link hijack), injection (SQL/cmd/path), secrets-in-code, storage and
    logging. Findings are persisted (source='sast') and included in the
    target's `source/sast.md` digest on the next artifact export.

    Args:
        decompile_dir: jadx output dir (must contain sources/ + manifest),
                       e.g. "workspace/jadx/com.linkedin.android"
        target_id: Target ID to persist findings against (see storage_summary)

    Returns:
        JSON: summary by severity/rule + top findings with file:line refs
    """
    if not decompile_dir:
        return json.dumps({"error": "decompile_dir required"}, indent=2)
    try:
        from tools.sast import scan_source, summarize
        from tools.workflow_tools import sast_scan as _wf_sast
        storage = _get_storage() if target_id else None
        result = _wf_sast(input=decompile_dir, _storage=storage,
                          _target_id=target_id or None)
        payload = {"summary": result["summary"],
                   "top": result["findings"][:100]}
        return json.dumps(payload, indent=2, default=str)[:100000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


# ============================================================================
# MobSF Tools
# ============================================================================


@mcp.tool()
def mobsf_analyze_endpoint(apk_path: str = "", target_id: int = 0) -> str:
    """Full MobSF APK analysis pipeline: upload → scan → findings.

    Args:
        apk_path: Path to APK file
        target_id: Target ID in storage (optional)

    Returns:
        JSON with MobSF analysis results and findings
    """
    if not apk_path:
        return json.dumps({"error": "apk_path is required"}, indent=2)
    try:
        from tools.mobsf_integration import mobsf_analyze
        result = mobsf_analyze(apk_path=apk_path, target_id=target_id)
        return json.dumps(result, indent=2, default=str)[:10000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def mobsf_check() -> str:
    """Check if MobSF server is running and available.

    Returns:
        JSON status of MobSF connection
    """
    try:
        from tools.mobsf_integration import check_mobsf_available
        result = check_mobsf_available()
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def mobsf_apk_diff(
    apk_old: str = "",
    apk_new: str = "",
) -> str:
    """Compare two APK versions via MobSF for new endpoints and removed security.

    Args:
        apk_old: Path to older APK version
        apk_new: Path to newer APK version

    Returns:
        JSON diff between the two APKs
    """
    if not apk_old or not apk_new:
        return json.dumps({"error": "apk_old and apk_new are required"}, indent=2)
    try:
        from tools.mobsf_integration import mobsf_apk_diff
        result = mobsf_apk_diff(apk_old=apk_old, apk_new=apk_new)
        return json.dumps(result, indent=2, default=str)[:10000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


# ============================================================================
# Android Intent & Deep Link Tools
# ============================================================================


@mcp.tool()
def analyze_deep_links(
    decompile_dir: str = "",
    package: str = "",
    test_device: bool = False,
) -> str:
    """Extract deep links from decompiled APK and optionally fuzz on device.

    Args:
        decompile_dir: Decompiled source directory (jadx output)
        package: Android package name for device testing
        test_device: If true, send ADB intents to test deep links

    Returns:
        JSON with deep links, schemes, and fuzzable URIs
    """
    if not decompile_dir:
        return json.dumps({"error": "decompile_dir is required"}, indent=2)
    try:
        result = deep_link_fuzzer(
            input=decompile_dir,
            package=package,
            test_on_device=test_device,
        )
        return json.dumps(result, indent=2, default=str)[:8000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def find_intent_redirection(decompile_dir: str = "") -> str:
    """Find intent redirection vulnerabilities in decompiled source.

    Args:
        decompile_dir: Decompiled source directory

    Returns:
        JSON with vulnerable components and patterns
    """
    if not decompile_dir:
        return json.dumps({"error": "decompile_dir is required"}, indent=2)
    try:
        result = intent_redirection_finder(input=decompile_dir)
        return json.dumps(result, indent=2, default=str)[:8000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def fuzz_exported_components(package: str = "", decompile_dir: str = "") -> str:
    """Fuzz exported Android components on device via ADB.

    Args:
        package: Android package name
        decompile_dir: Decompiled source directory

    Returns:
        JSON with component fuzzing results
    """
    if not package:
        return json.dumps({"error": "package is required"}, indent=2)
    try:
        result = component_fuzzer(package=package, input=decompile_dir)
        return json.dumps(result, indent=2, default=str)[:8000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def scan_content_providers(decompile_dir: str = "") -> str:
    """Scan decompiled source for Content Provider vulnerabilities.

    Args:
        decompile_dir: Decompiled source directory

    Returns:
        JSON with vulnerable providers
    """
    if not decompile_dir:
        return json.dumps({"error": "decompile_dir is required"}, indent=2)
    try:
        result = content_provider_scanner(input=decompile_dir)
        return json.dumps(result, indent=2, default=str)[:8000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


# ============================================================================
# API Security Scanner Tools
# ============================================================================


@mcp.tool()
def graphql_scan(endpoints: str = "[]", token: str = "") -> str:
    """Scan GraphQL endpoints for security vulnerabilities.

    Args:
        endpoints: JSON array of endpoint URLs or dicts
        token: Auth token for authenticated testing

    Returns:
        JSON with GraphQL scan findings
    """
    try:
        eps = json.loads(endpoints) if isinstance(endpoints, str) else endpoints
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON endpoints"}, indent=2)
    try:
        result = graphql_scanner(endpoints=eps, token=token)
        return json.dumps(result, indent=2, default=str)[:10000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def idor_test(
    endpoints: str = "[]",
    traffic: str = "[]",
    token_a: str = "",
    token_b: str = "",
) -> str:
    """Test for IDOR/BOLA vulnerabilities on API endpoints.

    Args:
        endpoints: JSON array of endpoint dicts
        traffic: JSON array of captured traffic
        token_a: Auth token for user A
        token_b: Auth token for user B

    Returns:
        JSON IDOR scan findings
    """
    try:
        eps = json.loads(endpoints) if isinstance(endpoints, str) else endpoints
        tr = json.loads(traffic) if isinstance(traffic, str) else traffic
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON input"}, indent=2)
    try:
        result = idor_scanner(endpoints=eps, traffic=tr, token_a=token_a, token_b=token_b)
        return json.dumps(result, indent=2, default=str)[:10000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def jwt_scan(traffic: str = "[]") -> str:
    """Analyze JWT tokens from traffic for security weaknesses.

    Args:
        traffic: JSON array of captured traffic items

    Returns:
        JSON JWT analysis findings
    """
    try:
        tr = json.loads(traffic) if isinstance(traffic, str) else traffic
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON traffic"}, indent=2)
    try:
        result = jwt_analyzer(traffic=tr)
        return json.dumps(result, indent=2, default=str)[:8000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


# ============================================================================
# Frida Script Manager Tools
# ============================================================================


@mcp.tool()
def frida_list_scripts_tool(category: str = "") -> str:
    """List available Frida scripts by category.

    Args:
        category: Optional filter (ssl_bypass, root_bypass, crypto, traffic, runtime, custom)

    Returns:
        JSON list of Frida scripts
    """
    try:
        from tools.frida_manager import frida_list_scripts
        result = frida_list_scripts(category=category)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def frida_run_script_tool(package: str = "", script_ref: str = "",
                          mode: str = "spawn", timeout: int = 60) -> str:
    """Run a Frida script against a target Android app.

    Args:
        package: Android package name (e.g. com.target.app)
        script_ref: 'category.name' reference (e.g. 'ssl_bypass.universal_unpin')
        mode: 'spawn' to launch app, 'attach' to hook running process
        timeout: Execution timeout in seconds

    Returns:
        JSON with script output
    """
    if not package or not script_ref:
        return json.dumps({"error": "package and script_ref are required"}, indent=2)
    try:
        from tools.frida_manager import frida_run_script
        result = frida_run_script(package=package, script_ref=script_ref,
                                   mode=mode, timeout=timeout)
        return json.dumps(result, indent=2, default=str)[:5000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def frida_generate_hook(template_name: str = "", params: str = "{}") -> str:
    """Generate a Frida hook script from a template.

    Args:
        template_name: Template name (hook_method, hook_method_return, bypass_ssl_universal, etc.)
        params: JSON dict of template parameters

    Returns:
        JSON with generated hook script
    """
    if not template_name:
        return json.dumps({"error": "template_name is required"}, indent=2)
    try:
        from tools.frida_manager import frida_generate_script, frida_list_templates
        tpl_params = json.loads(params) if isinstance(params, str) else params
        result = frida_generate_script(template_name=template_name, params=tpl_params)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def frida_list_templates_tool() -> str:
    """List available Frida hook templates.

    Returns:
        JSON list of available templates
    """
    try:
        from tools.frida_manager import frida_list_templates
        result = frida_list_templates()
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def frida_combine_scripts_tool(script_refs: str = "[]", output_name: str = "combined") -> str:
    """Combine multiple Frida scripts into one.

    Args:
        script_refs: JSON array of 'category.name' refs
        output_name: Output file name (without .js)

    Returns:
        JSON with combined script path
    """
    try:
        refs = json.loads(script_refs) if isinstance(script_refs, str) else script_refs
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON script_refs"}, indent=2)
    try:
        from tools.frida_manager import frida_combine_scripts
        result = frida_combine_scripts(script_refs=refs, output_name=output_name)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def frida_bypass_all_tool(package: str = "",
                          proxy_host: str = "127.0.0.1",
                          proxy_port: int = 8080,
                          mode: str = "spawn") -> str:
    """Run combined bypass: SSL unpin + root bypass + proxy force.

    Args:
        package: Android package name
        proxy_host: Proxy host (default 127.0.0.1)
        proxy_port: Proxy port (default 8080)
        mode: spawn or attach

    Returns:
        JSON with execution output
    """
    if not package:
        return json.dumps({"error": "package is required"}, indent=2)
    try:
        from tools.frida_manager import frida_bypass_all
        result = frida_bypass_all(package=package, proxy_host=proxy_host,
                                   proxy_port=proxy_port, mode=mode)
        return json.dumps(result, indent=2, default=str)[:5000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def frida_auto_hook_tool(decompile_dir: str = "",
                         target_package: str = "",
                         max_hooks: int = 20) -> str:
    """Auto-generate Frida hooks from decompiled source.

    Args:
        decompile_dir: Decompiled source directory (jadx output)
        target_package: Target app package name (optional filter)
        max_hooks: Maximum hooks to generate

    Returns:
        JSON with generated hooks
    """
    if not decompile_dir:
        return json.dumps({"error": "decompile_dir is required"}, indent=2)
    try:
        from tools.frida_manager import frida_auto_hook
        result = frida_auto_hook(input=decompile_dir, target_package=target_package,
                                  max_hooks=max_hooks)
        return json.dumps(result, indent=2, default=str)[:8000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


# ============================================================================
# Dynamic Analysis Sandbox Tools
# ============================================================================


@mcp.tool()
def sandbox_dump_all(package: str = "", log_duration: int = 15) -> str:
    """Full dynamic sandbox dump: databases + prefs + logs + filesystem + screenshot.

    Args:
        package: Android package name
        log_duration: Seconds to capture logs

    Returns:
        JSON with all dumped data and findings
    """
    if not package:
        return json.dumps({"error": "package is required"}, indent=2)
    try:
        result = sandbox_full_dump(package=package, log_duration=log_duration)
        return json.dumps(result, indent=2, default=str)[:10000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def sandbox_analyze_db(db_path: str = "") -> str:
    """Analyze a pulled SQLite database for sensitive content.

    Args:
        db_path: Local path to .db file

    Returns:
        JSON with table schema and sensitive data samples
    """
    if not db_path:
        return json.dumps({"error": "db_path is required"}, indent=2)
    try:
        result = sandbox_analyze_sqlite(db_path=db_path)
        return json.dumps(result, indent=2, default=str)[:8000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def frida_check_env_tool() -> str:
    """Check Frida environment readiness.

    Returns:
        JSON with CLI, device, and server status
    """
    try:
        from tools.frida_manager import frida_check_env
        result = frida_check_env()
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


# ============================================================================
# Flutter App Pentest Tools
# ============================================================================


@mcp.tool()
def flutter_detect(apk_path: str = "") -> str:
    """Detect if an APK is a Flutter app and extract engine metadata.

    Args:
        apk_path: Path to APK file

    Returns:
        JSON with detection results
    """
    if not apk_path:
        return json.dumps({"error": "apk_path is required"}, indent=2)
    try:
        result = flutter_detect_apk(apk_path=apk_path)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def flutter_reflutter(
    apk_path: str = "",
    proxy_ip: str = "192.168.1.100",
) -> str:
    """Patch a Flutter APK with reFlutter for traffic interception.

    Args:
        apk_path: Path to original APK
        proxy_ip: Burp Suite IP address

    Returns:
        JSON with patched APK path and status
    """
    if not apk_path:
        return json.dumps({"error": "apk_path is required"}, indent=2)
    try:
        result = flutter_reflutter_patch(apk_path=apk_path, proxy_ip=proxy_ip)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def flutter_pull_parse_dump(package: str = "") -> str:
    """Pull reFlutter dump.dart from device and parse it.

    Args:
        package: Android package name

    Returns:
        JSON with parsed classes, functions, libraries
    """
    if not package:
        return json.dumps({"error": "package is required"}, indent=2)
    try:
        dump = flutter_pull_dump(package=package)
        if "error" in dump:
            return json.dumps(dump, indent=2)
        parsed = flutter_parse_dump(dump_path=dump["dump_path"])
        return json.dumps(parsed, indent=2, default=str)[:10000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def flutter_blutter(lib_dir: str = "") -> str:
    """Run Blutter analysis on Flutter lib via WSL2.

    Args:
        lib_dir: Directory containing libflutter.so + libapp.so

    Returns:
        JSON with Blutter output files
    """
    if not lib_dir:
        return json.dumps({"error": "lib_dir is required"}, indent=2)
    try:
        result = flutter_blutter_analyze(lib_dir=lib_dir)
        return json.dumps(result, indent=2, default=str)[:8000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def flutter_parse_pp(pp_path: str = "") -> str:
    """Parse Blutter pp.txt to extract URLs, secrets, class names.

    Args:
        pp_path: Path to pp.txt from Blutter

    Returns:
        JSON with extracted URLs, secrets, classes
    """
    if not pp_path:
        return json.dumps({"error": "pp_path is required"}, indent=2)
    try:
        result = flutter_blutter_parse_pp(pp_path=pp_path)
        return json.dumps(result, indent=2, default=str)[:10000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def flutter_tls_bypass(
    package: str = "",
    mode: str = "spawn",
    method: str = "frida",
) -> str:
    """Bypass Flutter TLS verification.

    Args:
        package: Android package name
        mode: spawn or attach (for Frida method)
        method: 'frida' (NVISO script) or 'reflutter' (APK patching)

    Returns:
        JSON with bypass status
    """
    if not package:
        return json.dumps({"error": "package is required"}, indent=2)
    try:
        if method == "reflutter":
            result = flutter_tls_bypass_reflutter(package=package)
        else:
            result = flutter_tls_bypass_frida(package=package, mode=mode)
        return json.dumps(result, indent=2, default=str)[:5000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def flutter_full_scan(
    apk_path: str = "",
    package: str = "",
    proxy_ip: str = "192.168.1.100",
) -> str:
    """Full Flutter security scan: detect + blutter + reflutter + tls bypass.

    Args:
        apk_path: Path to APK
        package: Android package name
        proxy_ip: Proxy IP for reFlutter

    Returns:
        JSON with complete analysis results
    """
    if not apk_path:
        return json.dumps({"error": "apk_path is required"}, indent=2)
    try:
        result = flutter_full_analyze(
            apk_path=apk_path, package=package, proxy_ip=proxy_ip,
        )
        return json.dumps(result, indent=2, default=str)[:10000]
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)
