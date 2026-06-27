"""HTTP response analysis and vulnerability detection."""

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    type: str
    severity: str  # critical, high, medium, low, info
    description: str
    evidence: str = ""
    request_id: int = 0


@dataclass
class AnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)
    status_code: int = 0

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    def to_dict(self) -> dict:
        return {
            "status_code": self.status_code,
            "tech_stack": self.tech_stack,
            "findings": [
                {"type": f.type, "severity": f.severity,
                 "description": f.description, "evidence": f.evidence[:200]}
                for f in self.findings
            ],
        }


# Detection patterns
_PATTERNS: list[tuple[str, str, list[tuple[str, str]]]] = [
    ("sql_injection", "critical", [
        (r"SQL syntax.*MySQL", "MySQL error"),
        (r"ORA-[0-9]{5}", "Oracle error"),
        (r"Driver.*SQL", "SQL driver error"),
        (r"PostgreSQL.*ERROR", "PostgreSQL error"),
        (r"SQLite3::SQLException", "SQLite error"),
        (r"Unclosed quotation mark", "MSSQL error"),
        (r"Microsoft.*ODBC.*Driver", "MSSQL ODBC error"),
    ]),
    ("xss_reflected", "high", [
        (r"<script>alert\(.*?\)</script>", "Reflected XSS"),
    ]),
    ("debug_page", "high", [
        (r"Debug mode", "Debug mode enabled"),
        (r"Traceback \(most recent call last\)", "Python traceback"),
        (r"Stack trace:", "Stack trace exposed"),
        (r"laravel\.log", "Laravel debug log"),
        (r"drupal.*error|warning.*drupal", "Drupal debug info"),
        (r"cfc\[", "ColdFusion error"),
        (r"ASP\.NET.*Error", "ASP.NET error page"),
    ]),
    ("info_disclosure", "medium", [
        (r"(?:^|[^\d])(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.[\d.]+",
         "Internal IP address disclosed"),
        (r"com\.\w+\.\w+\.\w+", "Java package name disclosed"),
        (r"/etc/passwd", "Unix file path disclosed"),
        (r"C:\\Users\\", "Windows file path disclosed"),
        (r"Server: .*", "Server header disclosed"),
        (r"X-Powered-By: .*", "Tech stack disclosed"),
    ]),
    ("path_traversal", "high", [
        (r"root:.*:0:0:", "Passwd file content leaked"),
        (r"\[boot loader\]", "boot.ini leaked"),
        (r"\[fonts\]", "win.ini leaked"),
        (r"localhost|127\.0\.0\.1", "Local file inclusion possible"),
    ]),
    ("open_redirect", "medium", [
        (r"window\.location\s*=", "Open redirect via JavaScript"),
        (r"document\.location\s*=", "Open redirect via JavaScript"),
        (r"top\.location\s*=", "Open redirect via JavaScript"),
    ]),
    ("cors_misconfig", "medium", [
        (r"Access-Control-Allow-Origin:\s*\*", "CORS wildcard origin"),
        (r"Access-Control-Allow-Credentials:\s*true", "CORS with credentials"),
    ]),
    ("default_creds", "high", [
        (r"admin.*admin|password.*password", "Default credentials detected"),
        (r"root.*toor|admin.*1234", "Common default credentials"),
    ]),
    ("directory_listing", "medium", [
        (r"Index of /", "Directory listing enabled"),
        (r"Directory listing for", "Directory listing enabled"),
        (r"<title>Index of</title>", "Directory listing enabled"),
    ]),
    ("waf_detection", "info", [
        (r"CloudFlare|cloudflare", "CloudFlare detected"),
        (r"CloudFront", "AWS CloudFront detected"),
        (r"ModSecurity", "ModSecurity WAF detected"),
        (r"<title>403 Forbidden</title>", "Generic WAF block"),
    ]),
]

# Technology fingerprinting
_TECH_PATTERNS: list[tuple[str, str, str]] = [
    ("php", "header", r"X-Powered-By:\s*PHP"),
    ("asp.net", "header", r"X-AspNet-Version:"),
    ("asp.net_mvc", "header", r"X-AspNetMvc-Version:"),
    ("nginx", "header", r"Server:\s*nginx"),
    ("apache", "header", r"Server:\s*Apache"),
    ("iis", "header", r"Server:\s*Microsoft-IIS"),
    ("cloudflare", "header", r"CF-RAY:"),
    ("java", "header", r"Server:\s*Java|X-Application-Context:"),
    ("node.js", "header", r"X-Powered-By:\s*Express"),
    ("python", "header", r"Server:\s*Python|Server:\s*WSGIServer|Server:\s*Werkzeug"),
    ("wordpress", "body", r"wp-content|wp-includes|WordPress"),
    ("drupal", "body", r"Drupal\.settings|drupal\.js"),
    ("laravel", "body", r"Laravel|CSRF-TOKEN"),
    ("ruby_rails", "header", r"X-Runtime:\s*Ruby|Server:\s*Phusion|Server:\s*WEBrick"),
    ("docker", "header", r"Server:\s*Docker|Docker-Distribution-Api-Version:"),
]


def analyze_response(
    status_code: int = 0,
    headers: dict[str, str] | None = None,
    body: str = "",
    request_id: int = 0,
) -> AnalysisResult:
    """Analyze an HTTP response for security vulnerabilities.

    Checks for:
    - SQL injection errors
    - Reflected XSS
    - Debug pages / stack traces
    - Information disclosure
    - Path traversal
    - Open redirect
    - CORS misconfiguration
    - Default credentials
    - Directory listing
    - WAF detection

    Args:
        status_code: HTTP status code
        headers: Response headers dict
        body: Response body text
        request_id: Optional identifier for the request

    Returns:
        AnalysisResult with findings and tech stack.
    """
    result = AnalysisResult(status_code=status_code)
    hdrs = headers or {}
    body_text = body or ""

    # Combine headers + body for pattern matching
    header_text = "\n".join(f"{k}: {v}" for k, v in hdrs.items())
    combined = header_text + "\n" + body_text

    # Run vulnerability checks
    for vuln_type, severity, patterns in _PATTERNS:
        for pattern, description in patterns:
            if isinstance(pattern, re.Pattern):
                m = pattern.search(combined)
            else:
                m = re.search(pattern, combined, re.IGNORECASE | re.MULTILINE)
            if m:
                evidence = m.group(0)[:150]
                if vuln_type == "sql_injection" or severity == "high":
                    result.findings.insert(0, Finding(
                        type=vuln_type, severity=severity,
                        description=description, evidence=evidence,
                        request_id=request_id,
                    ))
                else:
                    result.findings.append(Finding(
                        type=vuln_type, severity=severity,
                        description=description, evidence=evidence,
                        request_id=request_id,
                    ))

    # Technology fingerprinting
    for tech_name, target, pattern in _TECH_PATTERNS:
        text = header_text if target == "header" else combined
        if re.search(pattern, text, re.IGNORECASE):
            result.tech_stack.append(tech_name)

    # Deduplicate tech stack
    result.tech_stack = list(set(result.tech_stack))

    return result


def analyze_proxy_item(
    item: dict[str, Any],
    request_id: int = 0,
) -> AnalysisResult:
    """Analyze a proxy history item from Burp Suite.

    Args:
        item: Proxy history item dict (from BurpClient.get_proxy_history)
        request_id: Optional identifier

    Returns:
        AnalysisResult
    """
    response = item.get("response") or {}
    raw = response.get("raw", "") or ""
    status_code = response.get("status_code", 0)

    # Parse headers if raw response available
    headers = {}
    body = ""
    if raw:
        parsed = _parse_response_basic(raw)
        headers = parsed.get("headers", {})
        body = parsed.get("body", "")
    else:
        headers = response.get("headers", {})
        body = response.get("body", "")

    return analyze_response(
        status_code=status_code,
        headers=headers,
        body=body,
        request_id=request_id,
    )


def _parse_response_basic(raw: str) -> dict[str, Any]:
    """Minimal HTTP response parser for analysis context."""
    text = raw.replace("\r\n", "\n")
    parts = text.split("\n\n", 1)
    header_section = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    headers = {}
    for line in header_section.split("\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {"headers": headers, "body": body}


def tech_fingerprint(
    headers: dict[str, str] | None = None,
    body: str = "",
) -> list[str]:
    """Fingerprint technology stack from response.

    Args:
        headers: Response headers
        body: Response body

    Returns:
        List of detected technologies.
    """
    result = analyze_response(headers=headers or {}, body=body or "")
    return result.tech_stack
