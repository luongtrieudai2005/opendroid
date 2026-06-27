"""Parameter fuzzing engine for bug bounty."""

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from burp_mcp.client import BurpClient
from tools.http_tools import send_http, build_url, parse_http_response
from tools.analysis import analyze_response

logger = logging.getLogger(__name__)

# Default wordlist directory
_WORDLIST_DIR = Path(__file__).parent.parent / "config" / "wordlists"


@dataclass
class FuzzResult:
    param: str = ""
    payload: str = ""
    status_code: int = 0
    body_length: int = 0
    response_time: float = 0.0
    is_interesting: bool = False
    reason: str = ""
    evidence: str = ""


# ---------------------------------------------------------------------------
# Wordlist management
# ---------------------------------------------------------------------------

def _load_wordlist(name: str) -> list[str]:
    """Load a wordlist from config/wordlists/.

    Args:
        name: Wordlist file name (e.g. "xss.txt", "sqli.txt")

    Returns:
        List of payload strings, or empty list if file not found.
    """
    path = _WORDLIST_DIR / name
    if not path.exists():
        logger.warning("Wordlist not found: %s", path)
        return []
    text = path.read_text(encoding="utf-8", errors="ignore")
    return [l.strip() for l in text.split("\n") if l.strip() and not l.startswith("#")]


# Built-in payloads (fallback when wordlist files are missing)
_BUILTIN_XSS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "'-alert(1)-'",
    "\"><svg onload=alert(1)>",
]

_BUILTIN_SQLI = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "admin' --",
    "1' ORDER BY 1--",
    "1 UNION SELECT 1",
    "' UNION SELECT NULL--",
    "'; DROP TABLE users--",
    "' WAITFOR DELAY '0:0:5'--",
    "1 AND SLEEP(5)",
]

_BUILTIN_PATHS = [
    "admin", "login", "api", "wp-admin", "backup",
    ".git", ".env", "config", "dashboard", "debug",
]

_BUILTIN_PARAMS = [
    "id", "page", "file", "path", "url",
    "redirect", "return", "next", "target",
    "debug", "token", "auth", "password",
    "email", "user", "search", "q",
]


def get_payloads(payload_type: str) -> list[str]:
    """Get payloads by type.

    Args:
        payload_type: "xss", "sqli", "dirs", or "params"

    Returns:
        List of payload strings.
    """
    mapping = {
        "xss": ("xss.txt", _BUILTIN_XSS),
        "sqli": ("sqli.txt", _BUILTIN_SQLI),
        "dirs": ("dirs.txt", _BUILTIN_PATHS),
        "params": ("params.txt", _BUILTIN_PARAMS),
    }
    if payload_type not in mapping:
        logger.warning("Unknown payload type: %s", payload_type)
        return []

    filename, fallback = mapping[payload_type]
    wordlist = _load_wordlist(filename)
    return wordlist if wordlist else fallback


# ---------------------------------------------------------------------------
# Fuzzing functions
# ---------------------------------------------------------------------------

def _is_interesting(
    baseline_code: int,
    baseline_size: int,
    result: FuzzResult,
) -> tuple[bool, str]:
    """Determine if a fuzz result is interesting based on status and size changes.

    Returns (is_interesting, reason).
    """
    if result.status_code != baseline_code:
        if result.status_code in (200, 201, 302, 403, 500):
            return True, f"Status changed: {baseline_code} -> {result.status_code}"
    if abs(result.body_length - baseline_size) > 100:
        direction = "+" if result.body_length > baseline_size else "-"
        return True, f"Size changed: {baseline_size} -> {baseline_size + (result.body_length - baseline_size)} ({direction}{abs(result.body_length - baseline_size)} bytes)"
    if result.response_time > 5.0:
        return True, f"Delay detected: {result.response_time:.1f}s"
    return False, ""


def _send_and_fuzz(
    method: str,
    url: str,
    param: str,
    payload: str,
    headers: dict[str, str] | None,
    body: str,
    use_burp: bool,
    burp_client: BurpClient | None,
) -> FuzzResult:
    """Send a fuzzed request and return the result."""
    import time

    if method == "GET":
        fuzzed_url = build_url(url, {param: payload})
        req_body = ""
    else:
        fuzzed_url = url
        # Replace param in body
        req_body = re.sub(
            rf'{re.escape(param)}=[^&]*',
            f"{param}={payload}",
            body,
        ) if body else f"{param}={payload}"

    start = time.time()
    resp = send_http(
        method=method,
        url=fuzzed_url,
        headers=headers,
        body=req_body,
        use_burp=use_burp,
        burp_client=burp_client,
    )
    elapsed = time.time() - start

    status_code = resp.get("status_code", 0) if resp else 0
    body_text = resp.get("body", "") if resp else ""
    body_length = len(body_text)

    return FuzzResult(
        param=param,
        payload=payload,
        status_code=status_code,
        body_length=body_length,
        response_time=elapsed,
    )


def fuzz_get_param(
    url: str,
    param: str,
    payload_type: str = "xss",
    payloads: list[str] | None = None,
    headers: dict[str, str] | None = None,
    use_burp: bool = True,
    burp_client: BurpClient | None = None,
) -> list[FuzzResult]:
    """Fuzz a GET parameter with payloads.

    Args:
        url: Target URL
        param: Parameter name to fuzz
        payload_type: Built-in payload type ("xss", "sqli")
        payloads: Custom payload list (overrides payload_type)
        headers: Custom headers
        use_burp: Send through Burp Suite
        burp_client: Existing BurpClient instance

    Returns:
        List of interesting FuzzResults.
    """
    pl = payloads if payloads is not None else get_payloads(payload_type)

    # Baseline request
    baseline = _send_and_fuzz("GET", url, param, "FUZZ_BASELINE",
                              headers, "", use_burp, burp_client)
    baseline_code = baseline.status_code
    baseline_size = baseline.body_length
    logger.info("Baseline: %s %d bytes", url, baseline_size)

    results: list[FuzzResult] = []
    for payload in pl:
        result = _send_and_fuzz("GET", url, param, payload,
                                headers, "", use_burp, burp_client)
        interesting, reason = _is_interesting(baseline_code, baseline_size, result)
        if interesting:
            result.is_interesting = True
            result.reason = reason
            results.append(result)
            logger.info("  [%s] %s=%s -> %d %s",
                       reason, param, payload[:30], result.status_code, reason)

    return results


def fuzz_post_param(
    url: str,
    param: str,
    data: dict[str, str] | None = None,
    payload_type: str = "xss",
    payloads: list[str] | None = None,
    headers: dict[str, str] | None = None,
    use_burp: bool = True,
    burp_client: BurpClient | None = None,
) -> list[FuzzResult]:
    """Fuzz a POST parameter with payloads.

    Args:
        url: Target URL
        param: Parameter name to fuzz
        data: Other POST data (dict of key-value pairs)
        payload_type: Built-in payload type
        payloads: Custom payload list
        headers: Custom headers
        use_burp: Send through Burp Suite
        burp_client: Existing BurpClient instance

    Returns:
        List of interesting FuzzResults.
    """
    pl = payloads if payloads is not None else get_payloads(payload_type)
    body_data = "&".join(f"{k}={v}" for k, v in (data or {}).items())
    hdrs = dict(headers or {})
    if "Content-Type" not in hdrs:
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"

    # Baseline
    baseline = _send_and_fuzz("POST", url, param, "FUZZ_BASELINE",
                              hdrs, body_data, use_burp, burp_client)
    baseline_code = baseline.status_code
    baseline_size = baseline.body_length

    results: list[FuzzResult] = []
    for payload in pl:
        result = _send_and_fuzz("POST", url, param, payload,
                                hdrs, body_data, use_burp, burp_client)
        interesting, reason = _is_interesting(baseline_code, baseline_size, result)
        if interesting:
            result.is_interesting = True
            result.reason = reason
            results.append(result)

    return results


def fuzz_path(
    base_url: str,
    wordlist_type: str = "dirs",
    wordlist: list[str] | None = None,
    extensions: str = "",
    use_burp: bool = True,
    burp_client: BurpClient | None = None,
) -> list[FuzzResult]:
    """Fuzz URL paths for hidden endpoints.

    Args:
        base_url: Base URL (e.g. "https://example.com")
        wordlist_type: Built-in wordlist type
        wordlist: Custom wordlist
        extensions: File extensions to try (e.g. ".php,.asp")
        use_burp: Send through Burp Suite
        burp_client: Existing BurpClient instance

    Returns:
        List of discovered paths with interesting responses.
    """
    wl = wordlist if wordlist is not None else get_payloads(wordlist_type)
    exts = [e.strip() for e in extensions.split(",") if e.strip()] if extensions else [""]

    results: list[FuzzResult] = []
    for word in wl:
        for ext in exts:
            path_url = f"{base_url.rstrip('/')}/{word}{ext}"
            resp = send_http("GET", path_url, use_burp=use_burp,
                             burp_client=burp_client)
            if resp:
                sc = resp.get("status_code", 0)
                if sc in (200, 201, 302, 403, 401):
                    results.append(FuzzResult(
                        param="path",
                        payload=word + ext,
                        status_code=sc,
                        body_length=len(resp.get("body", "")),
                        is_interesting=True,
                        reason=f"Path found: {sc}",
                    ))
                    logger.info("  [%d] %s/%s", sc, base_url.rstrip("/"), word + ext)

    return results


def fuzz_headers(
    url: str,
    header_payloads: dict[str, list[str]] | None = None,
    use_burp: bool = True,
    burp_client: BurpClient | None = None,
) -> list[FuzzResult]:
    """Fuzz HTTP headers for injection points.

    Common header fuzzing:
    - X-Forwarded-For: bypass IP restrictions
    - X-Forwarded-Host: host header injection
    - X-Real-IP: IP spoofing

    Args:
        url: Target URL
        header_payloads: Dict mapping header name to list of payload values
        use_burp: Send through Burp Suite
        burp_client: Existing BurpClient instance

    Returns:
        List of interesting results.
    """
    default = {
        "X-Forwarded-For": ["127.0.0.1", "localhost", "10.0.0.1"],
        "X-Forwarded-Host": ["localhost", "evil.com"],
        "X-Real-IP": ["127.0.0.1", "localhost"],
        "X-Originating-IP": ["127.0.0.1"],
        "X-Remote-IP": ["127.0.0.1"],
    }
    hdrs_payloads = header_payloads or default

    results: list[FuzzResult] = []
    for header, values in hdrs_payloads.items():
        for val in values:
            custom_headers = {header: val}
            resp = send_http("GET", url, headers=custom_headers,
                             use_burp=use_burp, burp_client=burp_client)
            if resp:
                sc = resp.get("status_code", 0)
                if sc in (200, 201, 302):
                    results.append(FuzzResult(
                        param=header,
                        payload=val,
                        status_code=sc,
                        is_interesting=True,
                        reason=f"Header bypass: {header}: {val} -> {sc}",
                    ))
                    logger.info("  [%d] %s: %s", sc, header, val)

    return results


def detect_waf_bypass(response_headers: dict[str, str]) -> str | None:
    """Detect WAF presence from response headers.

    Args:
        response_headers: Response headers dict

    Returns:
        WAF name if detected, None otherwise.
    """
    joined = json_headers = str(response_headers).lower() if response_headers else ""
    patterns = [
        ("Cloudflare", "cf-ray"),
        ("AWS WAF", "x-amzn-requestid"),
        ("Akamai", "akamai"),
        ("F5 BIG-IP", "big-ip"),
        ("ModSecurity", "mod_security"),
        ("Sucuri", "sucuri"),
        ("Incapsula", "incapsula"),
    ]
    for name, sig in patterns:
        if sig in joined:
            return name
    return None


def analyze_fuzz_results(results: list[FuzzResult]) -> list[dict[str, Any]]:
    """Analyze fuzz results for security issues.

    Args:
        results: List of FuzzResult from fuzzing

    Returns:
        List of finding dicts with analysis.
    """
    findings: list[dict[str, Any]] = []
    for r in results:
        if not r.is_interesting:
            continue

        finding: dict[str, Any] = {
            "param": r.param,
            "payload": r.payload[:100],
            "status": r.status_code,
            "reason": r.reason,
        }

        if r.response_time > 5:
            finding["type"] = "time_based"
            finding["severity"] = "high"
        elif r.status_code == 500:
            finding["type"] = "internal_error"
            finding["severity"] = "high"
        elif r.status_code == 302:
            finding["type"] = "redirect"
            finding["severity"] = "medium"
        elif r.status_code == 200 and "size changed" in r.reason.lower():
            finding["type"] = "reflection"
            finding["severity"] = "medium"
        else:
            finding["type"] = "anomaly"
            finding["severity"] = "low"

        findings.append(finding)

    return findings
