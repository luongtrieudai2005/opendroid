"""OSINT infrastructure recon tools: GitHub dorking, crt.sh, Shodan, tech blog analysis.

All functions are decorated with @tool_meta for automatic discovery by WorkflowEngine.
"""

import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Any

from tools.workflow import tool_meta

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# GitHub dorking
# ------------------------------------------------------------------

_GITHUB_DORK_PATTERNS = [
    ('api_key', r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([^"\']{8,})["\']'),
    ('aws_key', r'AKIA[0-9A-Z]{16}'),
    ('firebase_url', r'https://[a-z0-9-]+\.firebaseio\.com'),
    ('jwt_token', r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'),
    ('slack_token', r'xox[baprs]-[0-9a-zA-Z-]+'),
    ('github_token', r'gh[ps]_[0-9a-zA-Z]{36}'),
    ('private_key', r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),
    ('password', r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']'),
]


@tool_meta(
    name="github_dorker",
    description="Search GitHub for exposed secrets/config related to target (uses WSL2 grep or direct API)",
    params={
        "query": "GitHub search query (e.g. 'grabtaxi' or 'com.grabtaxi')",
        "patterns": "List of regex patterns (default: API keys, tokens, Firebase, AWS, JWT)",
        "max_results": "Maximum number of results to process",
    },
    outputs=["findings", "count", "result"],
)
def github_dorker(query: str = "", patterns: list | None = None,
                  max_results: int = 50, **kwargs) -> dict:
    """Search GitHub for exposed secrets related to the target.

    Uses GitHub's code search API via curl/WSL2. For each result,
    checks content against secret patterns.

    Args:
        query: GitHub search query (e.g. 'com.grabtaxi.passenger' or 'grabtaxi api key')
        patterns: Custom regex patterns (default: built-in secret patterns)
        max_results: Maximum results to process

    Returns:
        Dict with findings, count, result list.
    """
    q = query or kwargs.get("query", "")
    if not q:
        return {"findings": [], "count": 0, "result": []}

    search_patterns = patterns or _GITHUB_DORK_PATTERNS
    findings = []

    # Use curl + GitHub API (unauthenticated, rate-limited)
    api_url = f"https://api.github.com/search/code?q={q}&per_page={min(max_results, 100)}"
    try:
        result = subprocess.run(
            ["curl.exe", "-s", "-H", "Accept: application/vnd.github.v3+json", api_url],
            capture_output=True, text=True, timeout=15,
        )
        data = json.loads(result.stdout) if result.stdout else {}
        items = data.get("items", [])
        logger.info("GitHub dork: %d results for '%s'", len(items), q)

        for item in items[:max_results]:
            name = item.get("name", "")
            repo = item.get("repository", {}).get("full_name", "")
            html_url = item.get("html_url", "")
            raw_url = item.get("git_url", "")

            # Fetch raw content for pattern matching
            if raw_url:
                try:
                    raw = subprocess.run(
                        ["curl.exe", "-s", "--max-time", "5", raw_url.replace("git:", "raw:")],
                        capture_output=True, text=True, timeout=6,
                    )
                    content = raw.stdout
                except Exception:
                    content = ""
            else:
                content = ""

            if content:
                for ptype, pattern in search_patterns:
                    for m in re.finditer(pattern, content):
                        val = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                        findings.append({
                            "type": ptype,
                            "value": val[:80],
                            "file": name,
                            "repo": repo,
                            "url": html_url,
                            "confidence": "high",
                        })

    except subprocess.TimeoutExpired:
        logger.warning("GitHub API timeout for query '%s'", q)
    except json.JSONDecodeError:
        logger.warning("GitHub API returned non-JSON for '%s'", q)
    except FileNotFoundError:
        logger.warning("curl.exe not found — skipping github_dorker")
    except Exception as e:
        logger.warning("GitHub dork failed: %s", e)

    return {"findings": findings, "count": len(findings), "result": findings}


# ------------------------------------------------------------------
# Certificate Transparency (crt.sh)
# ------------------------------------------------------------------


@tool_meta(
    name="crtsh_enum",
    description="Enumerate subdomains via Certificate Transparency logs (crt.sh)",
    params={
        "domain": "Target domain (e.g. grabtaxi.com)",
        "wildcard": "Include wildcard results (default: true)",
        "deduplicate": "Deduplicate subdomains (default: true)",
    },
    outputs=["subdomains", "count", "result"],
)
def crtsh_enum(domain: str = "", wildcard: bool = True,
               deduplicate: bool = True, **kwargs) -> dict:
    """Query crt.sh for SSL certificate transparency logs to discover subdomains.

    Args:
        domain: Target domain
        wildcard: Include wildcard certificate entries
        deduplicate: Remove duplicate subdomains

    Returns:
        Dict with subdomains list.
    """
    d = domain or kwargs.get("domain", "")
    if not d:
        return {"subdomains": [], "count": 0, "result": []}

    url = f"https://crt.sh/?q=%25.{d}&output=json"
    subs = set()

    try:
        result = subprocess.run(
            ["curl.exe", "-s", "--max-time", "20", url],
            capture_output=True, text=True, timeout=25,
        )
        if result.stdout:
            entries = json.loads(result.stdout)
            for entry in entries:
                name_value = entry.get("name_value", "")
                for s in name_value.split("\n"):
                    s = s.strip().lower()
                    if not s:
                        continue
                    if not wildcard and s.startswith("*."):
                        continue
                    if s.endswith(f".{d}") or s == d:
                        subs.add(s)
    except subprocess.TimeoutExpired:
        logger.warning("crt.sh timeout for '%s'", d)
    except json.JSONDecodeError:
        logger.warning("crt.sh returned non-JSON for '%s'", d)
    except FileNotFoundError:
        logger.warning("curl.exe not found — skipping crtsh_enum")
    except Exception as e:
        logger.warning("crt.sh failed: %s", e)

    sorted_subs = sorted(subs)

    storage = kwargs.get("_storage")
    target_id = kwargs.get("_target_id")
    if storage and target_id and sorted_subs:
        try:
            storage.add_subdomains(target_id, sorted_subs, source="crtsh",
                                   run_id=kwargs.get("_run_id"))
        except Exception as exc:
            logger.warning("crtsh persist failed: %s", exc)

    return {"subdomains": sorted_subs, "count": len(sorted_subs), "result": sorted_subs}


# ------------------------------------------------------------------
# Shodan lookup (via shodan.io API)
# ------------------------------------------------------------------


@tool_meta(
    name="shodan_lookup",
    description="Query Shodan for target infrastructure (org search, port scan, services)",
    params={
        "query": "Shodan search query (e.g. 'org:Grab' or 'hostname:grabtaxi.com')",
        "max_results": "Maximum results (default: 20)",
    },
    outputs=["hosts", "services", "count", "result"],
)
def shodan_lookup(query: str = "", max_results: int = 20, **kwargs) -> dict:
    """Query Shodan API for exposed infrastructure.

    Uses the free Shodan API (no key required for basic search).
    For full results, set SHODAN_API_KEY env var.

    Args:
        query: Shodan search query
        max_results: Maximum results to return

    Returns:
        Dict with hosts, services, and raw data.
    """
    q = query or kwargs.get("query", "")
    if not q:
        return {"hosts": [], "services": [], "count": 0, "result": []}

    import os as _os
    api_key = _os.environ.get("SHODAN_API_KEY", "")
    hosts = []
    services = set()

    try:
        if api_key:
            url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={q}"
        else:
            url = f"https://api.shodan.io/shodan/host/search?key=SHODAN_API_KEY&query={q}"

        result = subprocess.run(
            ["curl.exe", "-s", "--max-time", "15", url],
            capture_output=True, text=True, timeout=20,
        )
        if result.stdout:
            data = json.loads(result.stdout)
            for match in data.get("matches", [])[:max_results]:
                ip = match.get("ip_str", "?")
                port = match.get("port", 0)
                hostname = ", ".join(match.get("hostnames", []))
                product = match.get("product", "")
                org = match.get("org", "")
                hosts.append({
                    "ip": ip,
                    "port": port,
                    "hostname": hostname or "?",
                    "product": product,
                    "org": org,
                })
                if product:
                    services.add(product)
    except subprocess.TimeoutExpired:
        logger.warning("Shodan timeout for '%s'", q)
    except json.JSONDecodeError:
        logger.warning("Shodan returned non-JSON for '%s'", q)
    except FileNotFoundError:
        logger.warning("curl.exe not found — skipping shodan_lookup")
    except Exception as e:
        logger.warning("Shodan lookup failed: %s", e)

    return {
        "hosts": hosts,
        "services": sorted(services),
        "count": len(hosts),
        "result": hosts,
    }


# ------------------------------------------------------------------
# Tech blog / job posting intelligence
# ------------------------------------------------------------------


@tool_meta(
    name="tech_intel",
    description="Gather tech intelligence from company's engineering blog, job postings, and public docs",
    params={
        "company_name": "Company name (e.g. Grab)",
        "blog_url": "Engineering blog URL if known",
    },
    outputs=["services", "technologies", "patterns", "result"],
)
def tech_intel(company_name: str = "", blog_url: str = "", **kwargs) -> dict:
    """Analyze company engineering blog and public resources for tech stack intel.

    Helps infer internal service names, naming conventions, and tech stack
    for more targeted subdomain bruteforce and API testing.

    Args:
        company_name: Company name
        blog_url: Known engineering blog URL

    Returns:
        Dict with detected services, technologies, and naming patterns.
    """
    name = company_name or kwargs.get("company_name", "")
    blog = blog_url or kwargs.get("blog_url", "")
    services = []
    techs = set()
    patterns = []

    # Infer naming patterns from company name
    if name:
        base = name.lower().strip()
        common_patterns = [
            f"{base}-api",
            f"api.{base}.com",
            f"{base}pay",
            f"{base}food",
            f"{base}express",
            f"{base}id",
            f"merchant.{base}.com",
            f"partner.{base}.com",
            f"driver.{base}.com",
            f"web.{base}.com",
            f"m.{base}.com",
            f"admin.{base}.com",
        ]
        patterns.extend(common_patterns)

        # Infer from company's product lines
        services.append(f"{name} API (core)")
        services.append(f"{name} Pay / Wallet")
        services.append(f"{name} Food / Delivery")
        services.append(f"{name} Express / Courier")
        services.append(f"{name} Merchant Portal")
        services.append(f"{name} Driver App")
        services.append(f"{name} Partner Portal")

    # Fetch engineering blog for tech stack mentions
    if not blog:
        blog = f"https://engineering.{name}.com" if name else ""

    content = ""
    if blog:
        try:
            result = subprocess.run(
                ["curl.exe", "-s", "-L", "--max-time", "10", blog],
                capture_output=True, text=True, timeout=12,
            )
            content = result.stdout
        except Exception:
            pass

    if content:
        tech_keywords = [
            "kubernetes", "docker", "kafka", "redis", "postgresql",
            "mysql", "mongodb", "graphql", "grpc", "protobuf",
            "react", "kotlin", "swift", "go", "golang", "rust",
            "aws", "gcp", "azure", "terraform", "ansible",
            "microservice", "event-driven", "serverless",
            "spring", "ktor", "ktor", "rabbitmq", "elasticsearch",
        ]
        for kw in tech_keywords:
            if kw in content.lower():
                techs.add(kw)

    return {
        "services": services,
        "technologies": sorted(techs),
        "patterns": patterns,
        "blog_analyzed": bool(content),
        "result": {
            "services": services,
            "technologies": sorted(techs),
            "naming_conventions": patterns,
        },
    }
