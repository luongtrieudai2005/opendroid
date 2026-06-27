"""HTTP request/response utilities for Burp Suite integration."""

import re
import json
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Any

from burp_mcp.client import BurpClient


def build_raw_request(
    method: str = "GET",
    host: str = "",
    path: str = "/",
    headers: dict[str, str] | None = None,
    body: str = "",
    http_version: str = "HTTP/1.1",
) -> str:
    """Build a raw HTTP/1.1 request string.

    Args:
        method: HTTP method (GET, POST, etc.)
        host: Hostname (used for Host header)
        path: URL path with query string
        headers: Additional headers
        body: Request body (for POST/PUT etc.)
        http_version: HTTP version string

    Returns:
        Raw HTTP request string with CRLF line endings.
    """
    hdrs = headers or {}
    if "Host" not in hdrs:
        hdrs["Host"] = host

    lines = [f"{method} {path} {http_version}"]
    for k, v in hdrs.items():
        lines.append(f"{k}: {v}")
    lines.append("")

    if body:
        lines.append(body)

    return "\r\n".join(lines)


def parse_http_response(raw: str) -> dict[str, Any]:
    """Parse a raw HTTP response string into a structured dict.

    Args:
        raw: Raw HTTP response (with CRLF or LF line endings)

    Returns:
        Dict with keys: status_line, status_code, reason, headers, body
    """
    # Normalize line endings
    raw = raw.replace("\r\n", "\n")

    # Split headers and body
    parts = raw.split("\n\n", 1)
    header_section = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    lines = header_section.split("\n")

    # Parse status line
    status_line = lines[0] if lines else ""
    status_code = 0
    reason = ""
    m = re.match(r"HTTP/\d+\.\d+\s+(\d+)\s*(.*)", status_line)
    if m:
        status_code = int(m.group(1))
        reason = m.group(2).strip()

    # Parse headers
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    return {
        "status_line": status_line,
        "status_code": status_code,
        "reason": reason,
        "headers": headers,
        "body": body,
    }


def send_http(
    method: str = "GET",
    url: str = "",
    headers: dict[str, str] | None = None,
    body: str = "",
    use_burp: bool = True,
    burp_client: BurpClient | None = None,
) -> dict[str, Any] | None:
    """Send an HTTP request, optionally through Burp Suite.

    Args:
        method: HTTP method
        url: Full URL (including scheme, host, path, query)
        headers: Custom headers
        body: Request body
        use_burp: If True, send through Burp MCP; otherwise use requests library
        burp_client: Existing BurpClient instance (creates one if None and use_burp=True)

    Returns:
        Parsed response dict, or None on failure.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    https = parsed.scheme == "https"
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    hdrs = dict(headers or {})
    raw = build_raw_request(method, hostname, path, hdrs, body)

    if use_burp:
        close_client = False
        if burp_client is None:
            burp_client = BurpClient()
            burp_client.connect()
            close_client = True

        try:
            result = burp_client.send_http1_request(
                content=raw,
                hostname=hostname,
                port=port,
                https=https,
            )
            if result and "content" in result:
                texts = [c["text"] for c in result["content"] if c.get("type") == "text"]
                if texts:
                    raw_resp = texts[0]
                    return parse_http_response(raw_resp)
            return result
        finally:
            if close_client:
                burp_client.close()
    else:
        import requests as req_lib
        resp = req_lib.request(method, url, headers=hdrs, data=body, timeout=30)
        return {
            "status_code": resp.status_code,
            "reason": resp.reason,
            "headers": dict(resp.headers),
            "body": resp.text,
        }


def extract_urls(html: str, base_url: str = "") -> list[str]:
    """Extract all URLs from HTML content.

    Args:
        html: HTML text
        base_url: Base URL for resolving relative URLs

    Returns:
        List of absolute URLs.
    """
    urls: list[str] = []
    # href attributes
    for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
        urls.append(m.group(1))
    # src attributes
    for m in re.finditer(r'src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        urls.append(m.group(1))
    # action attributes (forms)
    for m in re.finditer(r'action=["\']([^"\']+)["\']', html, re.IGNORECASE):
        urls.append(m.group(1))

    if base_url:
        urls = [urljoin(base_url, u) for u in urls]
    return list(set(urls))


def extract_forms(html: str, base_url: str = "") -> list[dict[str, Any]]:
    """Extract HTML forms from content.

    Args:
        html: HTML text
        base_url: Base URL for resolving action URLs

    Returns:
        List of form dicts with keys: action, method, inputs
    """
    forms: list[dict[str, Any]] = []
    pattern = re.compile(r"<form\s[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)

    for fm in pattern.finditer(html):
        form_html = fm.group(0)
        action = ""
        method = "GET"
        ma = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        if ma:
            action = ma.group(1)
        mm = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        if mm:
            method = mm.group(1).upper()
        if base_url and action:
            action = urljoin(base_url, action)

        inputs: list[dict[str, str]] = []
        for inp in re.finditer(
            r'<input\s[^>]*>', form_html, re.IGNORECASE
        ):
            attrs = {}
            for a in re.finditer(r'(\w+)=["\']([^"\']*)["\']', inp.group(0)):
                attrs[a.group(1).lower()] = a.group(2)
            inputs.append(attrs)

        forms.append({
            "action": action,
            "method": method,
            "inputs": inputs,
        })

    return forms


def build_url(base: str, params: dict[str, str]) -> str:
    """Build URL with query parameters.

    Args:
        base: Base URL (with or without existing query)
        params: Dict of query parameters

    Returns:
        Full URL with encoded query string.
    """
    parsed = urlparse(base)
    existing = parse_qs(parsed.query, keep_blank_values=True)
    existing.update(params)
    new_query = urlencode(existing, doseq=True)
    return parsed._replace(query=new_query).geturl()
