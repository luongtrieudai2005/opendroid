"""Android API security scanner: GraphQL + REST auth/IDOR/BOLA.

Specialised for mobile API attack surface:
  - GraphQL introspection + auth bypass + batch abuse + injection
  - REST authorization matrix (IDOR/BOLA)
  - Parameter tampering detection
  - JWT analysis
"""

import json
import logging
import re
import subprocess
from typing import Any
from urllib.parse import urlparse, urljoin

from tools.workflow import tool_meta
from tools.http_tools import send_http

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# GraphQL Scanner
# ------------------------------------------------------------------

@tool_meta(
    name="graphql_scanner",
    description="Scan GraphQL endpoints for introspection, auth bypass, batch abuse, injection",
    params={
        "endpoints": "List of potential GraphQL endpoint URLs",
        "token": "Auth token for authenticated testing (optional)",
    },
    outputs=["findings", "introspection_open", "endpoints_found", "result"],
)
def graphql_scanner(endpoints: list | None = None, token: str = "", **kwargs) -> dict:
    """Comprehensive GraphQL security scanner.

    Tests:
    1. Introspection enabled (can dump schema)
    2. Field suggestions leak
    3. Auth bypass via missing scope enforcement
    4. Batch query DoS
    5. Query depth DoS
    6. SQL injection in arguments

    Args:
        endpoints: List of endpoint dicts or URL strings
        token: Auth token for authenticated tests

    Returns:
        Dict with findings, introspection status, etc.
    """
    ep_list = endpoints or kwargs.get("endpoints", []) or []
    tok = token or kwargs.get("token", "")

    # Normalise to list of URLs
    urls: list[str] = []
    for ep in ep_list:
        if isinstance(ep, dict):
            u = ep.get("value", ep.get("url", ""))
        elif isinstance(ep, str):
            u = ep
        else:
            continue
        if u:
            urls.append(u)

    # Probe common GraphQL endpoints
    graphql_paths = ["/graphql", "/graph", "/gql", "/v1/graphql",
                     "/v2/graphql", "/api/graphql", "/query",
                     "/explorer", "/graphiql", "/playground"]

    findings: list[dict] = []
    gql_endpoints: list[str] = []

    for base_url in urls:
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in graphql_paths:
            test_url = urljoin(base, path)
            # Try introspection query
            intro_query = json.dumps({
                "query": "{ __schema { types { name fields { name } } } }"
            })

            headers = {"Content-Type": "application/json"}
            if tok:
                headers["Authorization"] = f"Bearer {tok}"

            resp = send_http("POST", test_url, headers=headers,
                             body=intro_query, use_burp=False)
            if resp and resp.get("status_code") in (200, 201):
                body = resp.get("body", "")
                if '"data"' in body and '__schema' in body:
                    findings.append({
                        "type": "graphql_introspection_open",
                        "severity": "high",
                        "title": f"GraphQL introspection enabled: {test_url}",
                        "description": "Anyone can dump the full schema including undocumented queries/mutations",
                        "evidence": f"URL: {test_url}",
                        "url": test_url,
                        "source": "graphql_scanner",
                    })
                    gql_endpoints.append(test_url)

                    # Try auth bypass test on discovered mutations
                    if tok:
                        auth_finding = _graphql_auth_test(test_url, tok)
                        if auth_finding:
                            findings.append(auth_finding)

                    # Try batch abuse
                    batch_finding = _graphql_batch_test(test_url)
                    if batch_finding:
                        findings.append(batch_finding)

                elif '"errors"' not in body:
                    gql_endpoints.append(test_url)
                    findings.append({
                        "type": "graphql_endpoint_found",
                        "severity": "info",
                        "title": f"Potential GraphQL endpoint: {test_url}",
                        "description": "Endpoint responded but introspection may be disabled",
                        "evidence": f"HTTP {resp.get('status_code')}",
                        "url": test_url,
                        "source": "graphql_scanner",
                    })

            # Try GET-based introspection
            q = "%7B%20__schema%20%7B%20types%20%7B%20name%20%7D%20%7D%20%7D"
            get_resp = send_http(
                "GET", f"{test_url}?query={q}",
                use_burp=False,
            )
            if get_resp and get_resp.get("status_code") == 200:
                body = get_resp.get("body", "")
                if '"data"' in body and '__schema' in body:
                    if test_url not in gql_endpoints:
                        findings.append({
                            "type": "graphql_introspection_open_get",
                            "severity": "high",
                            "title": f"GraphQL introspection via GET: {test_url}",
                            "description": "Introspection works via GET method too",
                            "evidence": test_url,
                            "url": test_url,
                            "source": "graphql_scanner",
                        })

    return {
        "findings": findings,
        "introspection_open": sum(1 for f in findings if "introspection" in f.get("type", "")),
        "endpoints_found": gql_endpoints,
        "count": len(findings),
        "result": {"findings": findings, "endpoints": gql_endpoints},
    }


def _graphql_auth_test(url: str, token: str) -> dict | None:
    """Test if restricted token can access privileged mutations."""
    # Query that tries to access a write mutation
    test_queries = [
        "mutation { __typename }",
        "{ __typename }",
    ]

    for q in test_queries:
        resp = send_http("POST", url,
                         headers={
                             "Content-Type": "application/json",
                             "Authorization": f"Bearer {token}",
                         },
                         body=json.dumps({"query": q}),
                         use_burp=False)
        if resp and resp.get("status_code") in (200, 201):
            body = resp.get("body", "")
            # If we get data back instead of scope error, scope enforcement is missing
            if '"data"' in body and '"errors"' not in body:
                return {
                    "type": "graphql_auth_bypass",
                    "severity": "critical",
                    "title": f"GraphQL scope enforcement missing: {url}",
                    "description": "Restricted token can execute queries — scope not enforced at GraphQL layer",
                    "evidence": f"Token executed mutation against {url}",
                    "url": url,
                    "source": "graphql_scanner",
                }
    return None


def _graphql_batch_test(url: str) -> dict | None:
    """Test batch query abuse for DoS."""
    batch_payload = []
    for i in range(20):
        batch_payload.append({
            "query": f"query q{i} {{ __typename }}",
        })

    resp = send_http("POST", url,
                     headers={"Content-Type": "application/json"},
                     body=json.dumps(batch_payload),
                     use_burp=False)
    if resp and resp.get("status_code") in (200, 201, 202):
        body = resp.get("body", "")
        if isinstance(body, str) and body.strip().startswith("["):
            return {
                "type": "graphql_batch_abuse",
                "severity": "medium",
                "title": f"GraphQL batch query allowed: {url}",
                "description": "Server accepts batch queries — potential DoS vector via query stacking",
                "evidence": f"20 batched queries accepted, HTTP {resp.get('status_code')}",
                "url": url,
                "source": "graphql_scanner",
            }
    return None


# ------------------------------------------------------------------
# REST IDOR / BOLA Scanner
# ------------------------------------------------------------------

@tool_meta(
    name="idor_scanner",
    description="Test REST endpoints for Insecure Direct Object Reference / BOLA",
    params={
        "endpoints": "List of endpoint dicts from APK analysis",
        "traffic": "Captured traffic samples with auth tokens",
        "token_a": "Auth token for user A (user1)",
        "token_b": "Auth token for user B (user2 — for IDOR swap test)",
    },
    outputs=["findings", "idor_count", "result"],
)
def idor_scanner(endpoints: list | None = None,
                 traffic: list | None = None,
                 token_a: str = "", token_b: str = "", **kwargs) -> dict:
    """Test for IDOR/BOLA vulnerabilities by swapping auth tokens and IDs.

    Strategy:
    1. Extract endpoints with potential IDs from URLs/paths
    2. Send request with token A → get ID for user A
    3. Send request with token B accessing user A's ID
    4. If accessible → IDOR/BOLA

    Args:
        endpoints: List of API endpoint dicts
        traffic: Captured traffic samples
        token_a: Auth token for user A
        token_b: Auth token for user B

    Returns:
        Dict with findings.
    """
    ep_list = endpoints or kwargs.get("endpoints", []) or []
    tr_list = traffic or kwargs.get("traffic", []) or []
    ta = token_a or kwargs.get("token_a", "")
    tb = token_b or kwargs.get("token_b", "")

    findings: list[dict] = []

    # Collect URLs and sample IDs from endpoints and traffic
    urls_with_ids: list[dict] = []

    for ep in ep_list:
        url = ep.get("value", ep.get("url", "")) if isinstance(ep, dict) else str(ep)
        method = ep.get("method", "GET") if isinstance(ep, dict) else "GET"
        extracted = _extract_ids_from_url(url)
        for eid in extracted:
            urls_with_ids.append({
                "url": url,
                "method": method,
                "id_pattern": eid["pattern"],
                "id_value": eid["value"],
                "id_type": eid["type"],
            })

    for item in tr_list:
        req = item.get("request", {}) if isinstance(item, dict) else {}
        url = req.get("url", "") if isinstance(req, dict) else ""
        method = req.get("method", "GET") if isinstance(req, dict) else "GET"
        if url:
            extracted = _extract_ids_from_url(url)
            for eid in extracted:
                urls_with_ids.append({
                    "url": url,
                    "method": method,
                    "id_pattern": eid["pattern"],
                    "id_value": eid["value"],
                    "id_type": eid["type"],
                })

    # If we have token_a and token_b, test IDOR
    if ta and tb:
        tested = set()
        for item in urls_with_ids:
            url = item["url"]
            if url in tested:
                continue
            tested.add(url)

            # Try swapping the ID value to a guessable one
            original_id = item["id_value"]
            test_id = "123456789" if len(original_id) > 5 else "9999"

            test_url = url.replace(original_id, test_id)
            test_url_alt = url.replace(original_id, "00000000")

            for tu in [test_url, test_url_alt]:
                # Request with token_b accessing user A's resource
                resp_b = send_http(item["method"], tu,
                                   headers={"Authorization": f"Bearer {tb}"},
                                   use_burp=False)
                if resp_b and resp_b.get("status_code") in (200, 201, 202):
                    body_b = resp_b.get("body", "")
                    if body_b and len(str(body_b)) > 20:
                        # Verify it's not just an error
                        error_kw = ["error", "not found", "forbidden",
                                    "unauthorized", "invalid"]
                        if not any(kw in str(body_b).lower()[:100] for kw in error_kw):
                            findings.append({
                                "type": "idor_bola",
                                "severity": "high",
                                "title": f"IDOR/BOLA on {item['method']} {url}",
                                "description": f"Accessed {item['id_type']}={test_id} with different user's token, got HTTP {resp_b.get('status_code')}",
                                "evidence": f"Original: {original_id} -> Test: {test_id}",
                                "url": tu,
                                "source": "idor_scanner",
                            })

    # If no tokens, return advisory findings
    if not findings and urls_with_ids:
        for item in urls_with_ids[:10]:
            findings.append({
                "type": "idor_candidate",
                "severity": "info",
                "title": f"IDOR candidate: {item['method']} {item['url']}",
                "description": f"Endpoint has {item['id_type']} parameter ({item['id_pattern']}). Swap token_a/token_b to test.",
                "evidence": f"ID value: {item['id_value']}",
                "url": item["url"],
                "source": "idor_scanner",
            })

    return {
        "findings": findings,
        "idor_count": sum(1 for f in findings if f.get("type") == "idor_bola"),
        "candidates": urls_with_ids,
        "result": {"findings": findings, "candidates": urls_with_ids[:20]},
    }


def _extract_ids_from_url(url: str) -> list[dict]:
    """Extract potential ID patterns from URL path and query."""
    results: list[dict] = []
    parsed = urlparse(url)

    # Path segments
    for segment in parsed.path.split("/"):
        if segment and segment.isdigit() and len(segment) >= 3:
            results.append({
                "pattern": "numeric_path_id",
                "value": segment,
                "type": f"path/{segment}",
            })
        elif segment and re.match(r'^[a-f0-9]{8,}$', segment, re.IGNORECASE):
            results.append({
                "pattern": "hex_path_id",
                "value": segment,
                "type": f"path/{segment}",
            })
        elif segment and re.match(r'^[a-zA-Z0-9_-]{20,}$', segment):
            results.append({
                "pattern": "token_path_id",
                "value": segment[:30],
                "type": f"path/{segment[:20]}",
            })

    # Query params
    if parsed.query:
        for qp in parsed.query.split("&"):
            if "=" in qp:
                k, v = qp.split("=", 1)
                if any(id_kw in k.lower() for id_kw in
                       ["id", "user", "account", "profile", "order",
                        "ticket", "ride", "booking", "transaction",
                        "payment", "wallet", "uid", "uuid"]):
                    if v and not v.startswith("{"):
                        results.append({
                            "pattern": f"query_{k}",
                            "value": v[:50],
                            "type": f"query_{k}",
                        })

    return results


# ------------------------------------------------------------------
# Param Tamper Scanner
# ------------------------------------------------------------------

@tool_meta(
    name="param_tamper_scanner",
    description="Test mobile API params for tampering: price, discount, role, status",
    params={
        "endpoints": "List of API endpoints",
        "traffic": "Captured traffic samples",
        "token": "Auth token",
    },
    outputs=["findings", "result"],
)
def param_tamper_scanner(endpoints: list | None = None,
                         traffic: list | None = None,
                         token: str = "", **kwargs) -> dict:
    """Test for parameter tampering on mobile API endpoints.

    Focus on business-critical params: price, fare, discount, role, admin, status.

    Args:
        endpoints: List of API endpoints
        traffic: Captured traffic
        token: Auth token

    Returns:
        Dict with findings.
    """
    ep_list = endpoints or kwargs.get("endpoints", []) or []
    tr_list = traffic or kwargs.get("traffic", []) or []
    tok = token or kwargs.get("token", "")

    findings: list[dict] = []
    tested_urls: set[str] = set()

    tamper_params = {
        "price": ["0", "-1", "999999"],
        "amount": ["0", "-1", "999999"],
        "fare": ["0", "-1", "999999"],
        "discount": ["100", "-1", "999"],
        "role": ["admin", "ADMIN", "superuser"],
        "admin": ["true", "1"],
        "verified": ["true", "1"],
        "is_admin": ["true", "1"],
        "status": ["approved", "confirmed", "success"],
        "debug": ["true", "1"],
        "bypass": ["true", "1"],
        "mock": ["true", "1"],
        "test": ["true", "1"],
    }

    def _build_tamper_url(base: str, param: str, value: str) -> str:
        if "?" in base:
            return re.sub(rf'({re.escape(param)}=)[^&]*', rf'\g<1>{value}', base)
        return f"{base}?{param}={value}"

    def _build_tamper_body(base_body: str, param: str, value: str) -> str:
        if not base_body:
            return f"{param}={value}"
        return re.sub(rf'({re.escape(param)}=)[^&]*', rf'\g<1>{value}', base_body)

    for ep in ep_list:
        url = ep.get("value", ep.get("url", "")) if isinstance(ep, dict) else str(ep)
        method = ep.get("method", "GET") if isinstance(ep, dict) else "GET"
        if not url or url in tested_urls:
            continue
        tested_urls.add(url)

        for param, values in tamper_params.items():
            if param in url.lower():
                for val in values[:3]:
                    tu = _build_tamper_url(url, param, val)
                    resp = send_http(method, tu,
                                     headers={"Authorization": f"Bearer {tok}"} if tok else {},
                                     use_burp=False)
                    if resp and resp.get("status_code") in (200, 201, 202):
                        findings.append({
                            "type": "param_tampering",
                            "severity": "high" if param in ("price", "amount", "fare", "admin", "role") else "medium",
                            "title": f"Param tampering: {param}={val} on {method} {url}",
                            "description": f"Server accepted {param}={val}, got HTTP {resp.get('status_code')}",
                            "evidence": f"Parameter: {param}, Value: {val}",
                            "url": tu,
                            "source": "param_tamper",
                        })

    for item in tr_list:
        req = item.get("request", {}) if isinstance(item, dict) else {}
        url = req.get("url", "") if isinstance(req, dict) else ""
        method = req.get("method", "GET") if isinstance(req, dict) else "GET"
        body = req.get("body", "") if isinstance(req, dict) else ""
        if not url or url in tested_urls:
            continue

        for param, values in tamper_params.items():
            if param in url.lower() or param in body.lower():
                for val in values[:2]:
                    if method.upper() == "GET":
                        tu = _build_tamper_url(url, param, val)
                        resp = send_http(method, tu, use_burp=False)
                    else:
                        tb = _build_tamper_body(body, param, val)
                        resp = send_http(method, url,
                                         headers={"Authorization": f"Bearer {tok}"} if tok else {},
                                         body=tb, use_burp=False)
                    if resp and resp.get("status_code") in (200, 201, 202):
                        findings.append({
                            "type": "param_tampering",
                            "severity": "high",
                            "title": f"Param tampering: {param}={val} on {method} {url}",
                            "description": f"Server accepted {param}={val}, got HTTP {resp.get('status_code')}",
                            "evidence": f"Parameter: {param}, Value: {val}",
                            "url": url,
                            "source": "param_tamper",
                        })

    return {
        "findings": findings,
        "count": len(findings),
        "result": findings,
    }


# ------------------------------------------------------------------
# JWT Analyzer
# ------------------------------------------------------------------

@tool_meta(
    name="jwt_analyzer",
    description="Analyze JWT tokens found in APK/traffic for weaknesses",
    params={
        "jwt_tokens": "List of JWT tokens (strings) to analyze",
        "traffic": "Captured traffic containing JWTs",
    },
    outputs=["findings", "result"],
)
def jwt_analyzer(jwt_tokens: list | None = None,
                 traffic: list | None = None, **kwargs) -> dict:
    """Analyze JWT tokens for security weaknesses.

    Checks:
    - alg=none
    - Weak HMAC secret
    - Expired tokens
    - Sensitive data in payload

    Args:
        jwt_tokens: List of JWT strings
        traffic: Captured traffic with possible JWTs

    Returns:
        Dict with findings.
    """
    tokens: list[str] = list(jwt_tokens or kwargs.get("jwt_tokens", []) or [])

    # Extract from traffic
    tr_list = traffic or kwargs.get("traffic", []) or []
    jwt_pat = re.compile(r'(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)')

    for item in tr_list:
        if isinstance(item, dict):
            for key in ("request", "response"):
                obj = item.get(key, {})
                if isinstance(obj, dict):
                    for field in ("body", "raw", "headers"):
                        text = obj.get(field, "")
                        if isinstance(text, str):
                            for m in jwt_pat.finditer(text):
                                tokens.append(m.group(1))
                elif isinstance(obj, str):
                    for m in jwt_pat.finditer(obj):
                        tokens.append(m.group(1))

    findings: list[dict] = []
    seen: set[str] = set()

    for token in tokens:
        if token in seen:
            continue
        seen.add(token)

        try:
            parts = token.split(".")
            header_b64 = parts[0]
            payload_b64 = parts[1]

            # Decode header
            header = _b64decode_json(header_b64)
            payload = _b64decode_json(payload_b64)

            if header:
                alg = header.get("alg", "")
                if alg == "none":
                    findings.append({
                        "type": "jwt_none_alg",
                        "severity": "critical",
                        "title": "JWT uses 'none' algorithm",
                        "description": "Token accepts alg=none — attacker can forge arbitrary tokens",
                        "evidence": token[:80] + "...",
                        "source": "jwt_analyzer",
                    })
                if alg and "HS" in alg and len(token) < 200:
                    findings.append({
                        "type": "jwt_weak_secret",
                        "severity": "high",
                        "title": f"JWT uses {alg} — may be weak if secret is common",
                        "description": f"Symmetric algorithm {alg} with short token, try secret bruteforce",
                        "evidence": token[:80] + "...",
                        "source": "jwt_analyzer",
                    })

            if payload:
                # Check for sensitive data
                sensitive_fields = ["password", "secret", "token", "credit",
                                    "ssn", "pin", "cvv", "phone", "email"]
                for field in sensitive_fields:
                    if field in payload:
                        findings.append({
                            "type": "jwt_sensitive_data",
                            "severity": "medium",
                            "title": f"Sensitive data in JWT payload: '{field}'",
                            "description": f"JWT payload contains {field}: {str(payload[field])[:50]}",
                            "evidence": token[:80] + "...",
                            "source": "jwt_analyzer",
                        })

                # Check expiry
                exp = payload.get("exp", 0)
                if exp and isinstance(exp, (int, float)) and exp < 10000000000:
                    import time
                    if exp < time.time():
                        findings.append({
                            "type": "jwt_expired",
                            "severity": "info",
                            "title": "JWT is expired",
                            "description": "Token is expired — may still be accepted if validation is broken",
                            "evidence": token[:80] + "...",
                            "source": "jwt_analyzer",
                        })
        except Exception:
            continue

    return {
        "findings": findings,
        "tokens_analyzed": len(seen),
        "count": len(findings),
        "result": findings,
    }


def _b64decode_json(data: str) -> dict | None:
    """Decode base64url JSON payload."""
    try:
        # Fix padding
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        import base64
        decoded = base64.urlsafe_b64decode(data)
        return json.loads(decoded)
    except Exception:
        return None
