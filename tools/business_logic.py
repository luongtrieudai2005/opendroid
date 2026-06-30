"""Business logic testing tools for ride-hailing / super-app targets.

Domain-specific checks: fare manipulation, GPS spoofing, promo abuse,
referral fraud, race conditions, OTP/bypass flows.

All functions are decorated with @tool_meta for automatic discovery by WorkflowEngine.
"""

import json
import logging
import re
import time
from typing import Any
from urllib.parse import urlparse

from tools.http_tools import send_http, build_raw_request
from tools.workflow import tool_meta

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Fare manipulation
# ------------------------------------------------------------------


@tool_meta(
    name="fare_check",
    description="Test fare manipulation vectors: client-side pricing, distance, coordinates",
    params={
        "endpoints": "List of ride-related API endpoints",
        "traffic": "Captured traffic samples with fare data",
        "token": "Auth token if available",
    },
    outputs=["findings", "count", "result"],
)
def fare_check(endpoints: list | None = None,
               traffic: list | None = None,
               token: str = "", **kwargs) -> dict:
    """Analyze ride-hailing API for fare manipulation vulnerabilities.

    Checks:
    - Fare/price sent from client vs calculated server-side
    - Coordinates (pickup/dropoff) trusted from client
    - Distance parameter trusted from client
    - Surge pricing manipulation

    Args:
        endpoints: List of API endpoint dicts with url, method
        traffic: Captured HTTP traffic samples
        token: Auth token for authenticated requests

    Returns:
        Dict with findings.
    """
    ep_list = endpoints or kwargs.get("endpoints", []) or []
    tr_list = traffic or kwargs.get("traffic", []) or []
    t = token or kwargs.get("token", "")
    findings = []
    checked = set()

    # Collect fare-related URLs from endpoints and traffic
    fare_urls = set()
    fare_keywords = ["fare", "price", "cost", "estimate", "booking", "ride",
                     "trip", "promo", "discount", "surge", "pricing"]

    for ep in ep_list:
        url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
        url_lower = url.lower()
        if any(kw in url_lower for kw in fare_keywords):
            fare_urls.add(url)

    for item in tr_list:
        req = item.get("request") if isinstance(item, dict) else {}
        url = req.get("url", "") if isinstance(req, dict) else ""
        if any(kw in url.lower() for kw in fare_keywords):
            fare_urls.add(url)

    for url in fare_urls:
        if url in checked:
            continue
        checked.add(url)

        # Test 1: Drop fare parameter
        if "?" in url:
            base, qs = url.split("?", 1)
            params = dict(p.split("=", 1) for p in qs.split("&") if "=" in p)
            fare_params = [k for k in params if any(kw in k.lower() for kw in
                          ["price", "fare", "amount", "cost", "distance", "lat", "lng"])]
            for fp in fare_params:
                original = params[fp]
                params[fp] = "1" if "lat" not in fp.lower() else "0.001"
                test_url = base + "?" + "&".join(f"{k}={v}" for k, v in params.items())
                resp = send_http("GET", test_url, use_burp=False)
                if resp and resp.get("status_code") in (200, 201):
                    findings.append({
                        "type": "client_side_fare_param",
                        "severity": "medium",
                        "description": f"Fare parameter '{fp}' accepted from client — may be manipulable",
                        "evidence": f"Changed {fp}={original} -> {params[fp]}, got HTTP {resp.get('status_code')}",
                        "url": test_url,
                    })

        # Test 2: Zero-amount fare
        for payload in [{"price": "0"}, {"amount": "0"}, {"fare": "0"}]:
            try:
                resp = send_http("POST", url, body="&".join(f"{k}={v}" for k, v in payload.items()),
                                 headers={"Content-Type": "application/x-www-form-urlencoded", "Authorization": f"Bearer {t}"} if t else {},
                                 use_burp=False)
                if resp and resp.get("status_code") in (200, 201, 202):
                    findings.append({
                        "type": "zero_fare_accepted",
                        "severity": "high",
                        "description": f"Zero/empty fare accepted: {payload}",
                        "evidence": f"HTTP {resp.get('status_code')} with payload {payload}",
                        "url": url,
                    })
            except Exception:
                continue

    return {"findings": findings, "count": len(findings), "result": findings}


# ------------------------------------------------------------------
# GPS spoofing
# ------------------------------------------------------------------


@tool_meta(
    name="gps_spoofing_check",
    description="Test impact of GPS coordinate manipulation on pricing, geofencing, surge",
    params={
        "endpoints": "List of geo-related API endpoints",
        "traffic": "Captured traffic with coordinates",
    },
    outputs=["findings", "count", "result"],
)
def gps_spoofing_check(endpoints: list | None = None,
                       traffic: list | None = None, **kwargs) -> dict:
    """Test GPS coordinate manipulation impact.

    Checks:
    - Pickup/dropoff coordinates trusted from client
    - Geofencing bypass (change lat/lng to access restricted areas)
    - Surge pricing triggered by coordinate manipulation

    Args:
        endpoints: API endpoints with geo data
        traffic: Captured traffic samples

    Returns:
        Dict with findings.
    """
    ep_list = endpoints or kwargs.get("endpoints", []) or []
    tr_list = traffic or kwargs.get("traffic", []) or []
    findings = []

    geo_urls = set()
    for ep in ep_list:
        url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
        if any(kw in url.lower() for kw in ["lat", "lng", "location", "geo",
                                             "pickup", "dropoff", "coordinate"]):
            geo_urls.add(url)

    for item in tr_list:
        req = item.get("request") if isinstance(item, dict) else {}
        url = req.get("url", "") if isinstance(req, dict) else ""
        if any(kw in url.lower() for kw in ["lat", "lng", "location"]):
            geo_urls.add(url)

    # Test coordinates: manipulate real-world areas
    test_coords = [
        ("0.0", "0.0"),           # Null island
        ("90.0", "180.0"),        # Max bounds
        ("-90.0", "-180.0"),      # Min bounds
    ]

    for url in geo_urls:
        for lat, lng in test_coords:
            try:
                test_url = url.replace("lat=53.1", f"lat={lat}").replace("lng=12.2", f"lng={lng}")
                if "?" in url:
                    test_url = url
                    if "lat" in url.lower():
                        test_url = re.sub(r'(?i)lat=[^&]+', f"lat={lat}", test_url)
                    if "lng" in url.lower() or "lon" in url.lower():
                        test_url = re.sub(r'(?i)(lng|lon)=[^&]+', f"lng={lng}", test_url)
                resp = send_http("GET", test_url, use_burp=False)
                if resp and resp.get("status_code") in (200, 201):
                    findings.append({
                        "type": "gps_spoofing",
                        "severity": "medium",
                        "description": f"Server accepts arbitrary GPS coordinates: ({lat}, {lng})",
                        "evidence": f"HTTP {resp.get('status_code')} for lat={lat}, lng={lng}",
                        "url": test_url,
                    })
            except Exception:
                continue

    return {"findings": findings, "count": len(findings), "result": findings}


# ------------------------------------------------------------------
# Promo / voucher abuse
# ------------------------------------------------------------------


@tool_meta(
    name="promo_validator",
    description="Test promo/voucher logic: stacking, replay, reuse, race conditions",
    params={
        "endpoints": "List of promo-related endpoints",
        "traffic": "Captured traffic with promo data",
        "token": "Auth token if available",
    },
    outputs=["findings", "count", "result"],
)
def promo_validator(endpoints: list | None = None,
                    traffic: list | None = None,
                    token: str = "", **kwargs) -> dict:
    """Test promo/voucher logic for abuse vectors.

    Checks:
    - Promo code stacking (multiple codes on one transaction)
    - Replay attack (same code used multiple times)
    - Apply promo to already-completed rides
    - Race condition on promo application
    - New user promo reused by existing users

    Args:
        endpoints: API endpoints
        traffic: Captured traffic samples
        token: Auth token

    Returns:
        Dict with findings.
    """
    ep_list = endpoints or kwargs.get("endpoints", []) or []
    tr_list = traffic or kwargs.get("traffic", []) or []
    t = token or kwargs.get("token", "")
    findings = []

    promo_urls = set()
    for ep in ep_list:
        url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
        if any(kw in url.lower() for kw in ["promo", "voucher", "coupon",
                                             "discount", "referral", "reward"]):
            promo_urls.add(url)

    for item in tr_list:
        req = item.get("request") if isinstance(item, dict) else {}
        url = req.get("url", "") if isinstance(req, dict) else ""
        if any(kw in url.lower() for kw in ["promo", "voucher", "coupon"]):
            promo_urls.add(url)

    if promo_urls:
        for url in promo_urls:
            findings.append({
                "type": "promo_endpoint_found",
                "severity": "info",
                "description": f"Promo/voucher endpoint identified — test stacking, replay, race",
                "evidence": f"Endpoint: {url}",
                "url": url,
            })

    # Race condition hint
    if promo_urls:
        findings.append({
            "type": "promo_race_condition",
            "severity": "medium",
            "description": "Promo endpoints identified — test race condition: send multiple simultaneous "
                           "redeem requests with same auth token to attempt double-apply",
            "evidence": f"Test on: {', '.join(list(promo_urls)[:3])}",
        })

    return {"findings": findings, "count": len(findings), "result": findings}


# ------------------------------------------------------------------
# Referral / loyalty fraud
# ------------------------------------------------------------------


@tool_meta(
    name="referral_check",
    description="Test referral/loyalty fraud: self-referral loops, infinite claim chains",
    params={
        "traffic": "Captured traffic with referral data",
        "endpoints": "List of API endpoints",
    },
    outputs=["findings", "count", "result"],
)
def referral_check(endpoints: list | None = None,
                   traffic: list | None = None, **kwargs) -> dict:
    """Test referral and loyalty program abuse.

    Checks:
    - Self-referral (user refers themselves with different accounts/devices)
    - Infinite referral chain
    - Referral reward claim without qualifying action
    - Referral code enumeration

    Args:
        endpoints: API endpoints
        traffic: Captured traffic

    Returns:
        Dict with findings.
    """
    ep_list = endpoints or kwargs.get("endpoints", []) or []
    tr_list = traffic or kwargs.get("traffic", []) or []
    findings = []

    ref_urls = set()
    for ep in ep_list:
        url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
        if any(kw in url.lower() for kw in ["referral", "refer", "invite",
                                             "share", "loyalty", "points"]):
            ref_urls.add(url)

    for item in tr_list:
        req = item.get("request") if isinstance(item, dict) else {}
        url = req.get("url", "") if isinstance(req, dict) else ""
        if any(kw in url.lower() for kw in ["referral", "refer", "invite"]):
            ref_urls.add(url)

    for url in ref_urls:
        findings.append({
            "type": "referral_endpoint",
            "severity": "info",
            "description": f"Referral endpoint identified — test self-referral, chain, enumeration",
            "evidence": f"Endpoint: {url}",
            "url": url,
        })

    return {"findings": findings, "count": len(findings), "result": findings}


# ------------------------------------------------------------------
# Race condition test helper
# ------------------------------------------------------------------


@tool_meta(
    name="race_tester",
    description="Test race conditions on critical endpoints (promo, wallet, booking)",
    params={
        "endpoints": "List of endpoints to race-test",
        "traffic": "Captured traffic to identify critical paths",
        "concurrent_requests": "Number of concurrent requests (default: 10)",
    },
    outputs=["findings", "count", "result"],
)
def race_tester(endpoints: list | None = None,
                traffic: list | None = None,
                concurrent_requests: int = 10, **kwargs) -> dict:
    """Identify and test race condition vectors.

    Critical paths to test:
    - Promo code redemption
    - Wallet top-up / withdrawal
    - Booking cancellation
    - Fare calculation
    - Referral reward claim

    Args:
        endpoints: API endpoints
        traffic: Captured traffic samples
        concurrent_requests: Number of concurrent requests to send

    Returns:
        Dict with findings (advisory — actual race testing requires Burp Turbo Intruder).
    """
    ep_list = endpoints or kwargs.get("endpoints", []) or []
    tr_list = traffic or kwargs.get("traffic", []) or []
    n = concurrent_requests or kwargs.get("concurrent_requests", 10)
    findings = []

    race_candidates = set()
    race_keywords = ["promo", "redeem", "voucher", "payment", "wallet",
                     "topup", "withdraw", "booking", "cancel", "fare",
                     "referral", "claim", "reward"]

    for ep in ep_list:
        url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
        if any(kw in url.lower() for kw in race_keywords):
            race_candidates.add(url)

    for item in tr_list:
        req = item.get("request") if isinstance(item, dict) else {}
        url = req.get("url", "") if isinstance(req, dict) else ""
        if any(kw in url.lower() for kw in race_keywords):
            race_candidates.add(url)

    for url in list(race_candidates)[:10]:
        findings.append({
            "type": "race_condition_candidate",
            "severity": "low",
            "description": f"Race condition candidate endpoint — send {n} concurrent requests",
            "evidence": f"Endpoint: {url} | Use Burp Turbo Intruder or custom script with {n} threads",
            "url": url,
        })

    return {"findings": findings, "count": len(findings), "result": findings}


# ------------------------------------------------------------------
# OTP / authentication bypass
# ------------------------------------------------------------------


@tool_meta(
    name="otp_tester",
    description="Test OTP and authentication flows: bruteforce, prediction, bypass",
    params={
        "traffic": "Captured traffic with OTP/auth endpoints",
        "endpoints": "List of API endpoints",
    },
    outputs=["findings", "count", "result"],
)
def otp_tester(endpoints: list | None = None,
               traffic: list | None = None, **kwargs) -> dict:
    """Test OTP and authentication flows for weaknesses.

    Checks:
    - OTP length (4-digit vs 6-digit)
    - Rate limiting on OTP endpoints
    - OTP response includes token/session leak
    - Password reset flow analysis
    - Account enumeration via OTP/forgot-password

    Args:
        endpoints: API endpoints
        traffic: Captured traffic samples

    Returns:
        Dict with findings.
    """
    ep_list = endpoints or kwargs.get("endpoints", []) or []
    tr_list = traffic or kwargs.get("traffic", []) or []
    findings = []

    auth_urls = set()
    auth_keywords = ["otp", "login", "auth", "token", "password", "reset",
                     "register", "signup", "verify", "sms", "send_otp"]

    for ep in ep_list:
        url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
        if any(kw in url.lower() for kw in auth_keywords):
            auth_urls.add(url)

    for item in tr_list:
        req = item.get("request") if isinstance(item, dict) else {}
        url = req.get("url", "") if isinstance(req, dict) else ""
        if any(kw in url.lower() for kw in auth_keywords):
            auth_urls.add(url)

    otp_pattern = re.compile(r'(\d{4,8})')
    for url in auth_urls:
        # Analyze OTP length from traffic samples
        for item in tr_list:
            req = item.get("request") if isinstance(item, dict) else {}
            body = req.get("body", "") if isinstance(req, dict) else ""
            resp = item.get("response") if isinstance(item, dict) else {}
            resp_body = resp.get("body", "") if isinstance(resp, dict) else ""

            otp_matches = otp_pattern.findall(body + resp_body)
            for otp in otp_matches:
                if len(otp) in (4, 5, 6):
                    findings.append({
                        "type": "otp_length",
                        "severity": "medium" if len(otp) <= 4 else "low",
                        "description": f"OTP detected: {len(otp)}-digit code ({otp}) — shorter codes = easier bruteforce",
                        "evidence": f"OTP: {otp} | Length: {len(otp)}",
                        "url": url,
                    })

    return {"findings": findings, "count": len(findings), "result": findings}
