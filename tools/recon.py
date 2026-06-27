"""Reconnaissance tools via WSL2 bridge.

Calls Linux-native bug bounty tools (subfinder, httpx, nuclei, ffuf, etc.)
through wsl.exe subprocess.
"""

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Full paths to Go tools in WSL2 Ubuntu
_GO_BIN = "/home/trieudai/go/bin"
_TOOL_PATHS = {
    "subfinder": f"{_GO_BIN}/subfinder",
    "httpx": f"{_GO_BIN}/httpx",
    "nuclei": f"{_GO_BIN}/nuclei",
    "ffuf": f"{_GO_BIN}/ffuf",
    "katana": f"{_GO_BIN}/katana",
    "gau": f"{_GO_BIN}/gau",
    "bbscope": f"{_GO_BIN}/bbscope",
}

# Alternative locations (in case user has tools in different paths)
_ALT_PATHS = [
    "/usr/local/bin",
    "/usr/bin",
    "/home/trieudai/.local/bin",
]


def _wsl_run(command: str, input_data: str | None = None,
             timeout: int = 120) -> subprocess.CompletedProcess:
    """Run a command in WSL2 and return the result.

    Uses explicit tool paths to avoid Windows PATH interop issues.
    """
    full_cmd = ["wsl.exe", "bash", "-c", command]
    logger.debug("wsl: %s", command[:200])

    try:
        result = subprocess.run(
            full_cmd,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result
    except subprocess.TimeoutExpired:
        logger.warning("WSL command timed out (> %ds): %s", timeout, command[:100])
        raise
    except FileNotFoundError:
        logger.error("wsl.exe not found. Is WSL installed?")
        raise


def check_tool(name: str) -> bool:
    """Check if a recon tool is available in WSL2.

    Args:
        name: Tool name (subfinder, httpx, nuclei, ffuf, katana, gau)

    Returns:
        True if tool is found and executable.
    """
    tool_path = _TOOL_PATHS.get(name)
    if not tool_path:
        return False

    try:
        result = subprocess.run(
            ["wsl.exe", "bash", "-c", f"test -x {tool_path} && echo ok"],
            capture_output=True, text=True, timeout=5,
        )
        return "ok" in result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def ensure_tools() -> dict[str, bool]:
    """Check availability of all recon tools.

    Returns:
        Dict mapping tool name to bool (available / not available).
    """
    return {name: check_tool(name) for name in _TOOL_PATHS}


def run_subfinder(domain: str, silent: bool = True) -> list[str]:
    """Run subfinder for passive subdomain enumeration.

    Args:
        domain: Target domain (e.g. "example.com")
        silent: If True, output only subdomains (no banners)

    Returns:
        List of discovered subdomains.
    """
    tool = _TOOL_PATHS["subfinder"]
    flags = "-silent " if silent else ""
    cmd = f"{tool} -d {domain} {flags}"

    result = _wsl_run(cmd, timeout=120)
    subs = [s.strip() for s in result.stdout.strip().split("\n") if s.strip()]
    logger.info("subfinder: found %d subdomains for %s", len(subs), domain)
    return subs


def run_httpx(hosts: list[str]) -> list[dict[str, Any]]:
    """Run httpx for HTTP probing and technology detection.

    Args:
        hosts: List of hostnames/URLs to probe

    Returns:
        List of dicts with probe results (url, status_code, tech, etc.)
    """
    if not hosts:
        return []

    tool = _TOOL_PATHS["httpx"]
    cmd = f"{tool} -json -tech-detect -silent -status-code"
    input_data = "\n".join(hosts)

    result = _wsl_run(cmd, input_data=input_data, timeout=300)
    items = []
    for line in result.stdout.strip().split("\n"):
        line = line.strip()
        if line:
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    logger.info("httpx: %d/%d hosts are live", len(items), len(hosts))
    return items


def run_nuclei(targets: list[str], templates: str = "",
               severity: str = "") -> list[dict[str, Any]]:
    """Run nuclei template-based vulnerability scanner.

    Args:
        targets: List of target URLs/hosts
        templates: Template filter (e.g. "cves/", "misconfiguration/")
                   Empty string = all templates
        severity: Severity filter (e.g. "critical,high")

    Returns:
        List of finding dicts from nuclei.
    """
    if not targets:
        return []

    tool = _TOOL_PATHS["nuclei"]
    cmd = f"{tool} -json -silent"
    if templates:
        cmd += f" -t {templates}"
    if severity:
        cmd += f" -severity {severity}"
    input_data = "\n".join(targets)

    result = _wsl_run(cmd, input_data=input_data, timeout=600)
    findings = []
    for line in result.stdout.strip().split("\n"):
        line = line.strip()
        if line:
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    logger.info("nuclei: found %d findings", len(findings))
    return findings


def run_ffuf(target_url: str, wordlist: list[str],
             extensions: str = "", opts: str = "") -> list[dict[str, Any]]:
    """Run ffuf for directory/file fuzzing.

    Args:
        target_url: URL with FUZZ placeholder (e.g. "https://example.com/FUZZ")
        wordlist: List of words to fuzz
        extensions: Comma-separated extensions (e.g. ".php,.asp")
        opts: Additional ffuf options

    Returns:
        List of discovered results.
    """
    tool = _TOOL_PATHS["ffuf"]
    input_data = "\n".join(wordlist)

    cmd = f"{tool} -u {target_url} -w - -json -silent"
    if extensions:
        cmd += f" -e {extensions}"
    if opts:
        cmd += f" {opts}"

    result = _wsl_run(cmd, input_data=input_data, timeout=300)
    items = []
    for line in result.stdout.strip().split("\n"):
        line = line.strip()
        if line:
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    logger.info("ffuf: found %d results", len(items))
    return items


def run_katana(url: str, depth: int = 3) -> list[str]:
    """Run katana crawler for endpoint discovery.

    Args:
        url: Starting URL to crawl
        depth: Crawl depth

    Returns:
        List of discovered URLs/endpoints.
    """
    tool = _TOOL_PATHS["katana"]
    cmd = f"{tool} -u {url} -d {depth} -silent -jc"

    result = _wsl_run(cmd, timeout=300)
    urls = [u.strip() for u in result.stdout.strip().split("\n") if u.strip()]
    logger.info("katana: found %d endpoints from %s", len(urls), url)
    return urls


def run_gau(domain: str) -> list[str]:
    """Run gau (GetAllURLs) for Wayback Machine URL collection.

    Args:
        domain: Target domain

    Returns:
        List of historical URLs.
    """
    tool = _TOOL_PATHS["gau"]
    cmd = f"{tool} {domain}"

    result = _wsl_run(cmd, timeout=120)
    urls = [u.strip() for u in result.stdout.strip().split("\n") if u.strip()]
    logger.info("gau: found %d historical URLs for %s", len(urls), domain)
    return urls


def run_full_recon(domain: str) -> dict[str, Any]:
    """Run full reconnaissance pipeline against a domain.

    Pipeline: subfinder -> httpx -> nuclei (critical/high)

    Args:
        domain: Target domain

    Returns:
        Dict with all recon results.
    """
    results: dict[str, Any] = {"domain": domain}

    # Step 1: Subdomain enumeration
    try:
        subs = run_subfinder(domain)
        results["subdomains"] = subs
    except Exception as e:
        logger.warning("subfinder failed: %s", e)
        results["subdomains"] = []
        subs = []

    # Step 2: HTTP probing
    try:
        if subs:
            live = run_httpx(subs[:50])  # Limit to 50
            results["live_hosts"] = live
            live_urls = [h.get("url", "") for h in live if h.get("url")]
        else:
            live_urls = [f"https://{domain}"]
            results["live_hosts"] = []
    except Exception as e:
        logger.warning("httpx failed: %s", e)
        results["live_hosts"] = []
        live_urls = [f"https://{domain}"]

    # Step 3: Vulnerability scanning
    try:
        vulns = run_nuclei(live_urls, severity="critical,high")
        results["vulnerabilities"] = vulns
    except Exception as e:
        logger.warning("nuclei failed: %s", e)
        results["vulnerabilities"] = []

    # Step 4: Crawl (optional enhancement)
    try:
        if domain:
            crawled = run_katana(f"https://{domain}", depth=2)
            results["crawled_endpoints"] = crawled[:100]
    except Exception as e:
        logger.warning("katana failed: %s", e)
        results["crawled_endpoints"] = []

    results["tools_available"] = ensure_tools()
    return results
