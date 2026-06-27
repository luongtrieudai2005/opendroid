"""APK analysis: decompile, extract endpoints, secrets, and check cloud services."""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.android_tools import (
    decompile_apk,
    extract_manifest,
    extract_endpoints,
    extract_secrets,
    analyze_apk as android_analyze_apk,
)

logger = logging.getLogger(__name__)


@dataclass
class CloudEndpoint:
    service: str
    url: str
    confidence: str
    file: str = ""


@dataclass
class ApkAnalysisResult:
    apk_path: str
    package: str = ""
    debuggable: bool = False
    allow_backup: bool = False
    permissions: list[str] = field(default_factory=list)
    exported_components: list[str] = field(default_factory=list)
    activities: list[str] = field(default_factory=list)
    endpoints: list[dict] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)
    cloud_services: list[CloudEndpoint] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "apk": self.apk_path,
            "package": self.package,
            "debuggable": self.debuggable,
            "allow_backup": self.allow_backup,
            "permissions": self.permissions,
            "exported_components": self.exported_components,
            "activities_count": len(self.activities),
            "endpoints_count": len(self.endpoints),
            "secrets_count": len(self.secrets),
            "cloud_services": [vars(c) for c in self.cloud_services],
            "findings": self.findings,
        }


def _check_firebase(url: str) -> dict:
    """Check if a Firebase URL is accessible (unauthenticated).

    Args:
        url: Firebase URL (e.g. https://project.firebaseio.com)

    Returns:
        Dict with check result.
    """
    try:
        import requests
        rest_url = f"{url.rstrip('/')}/.json"
        resp = requests.get(rest_url, timeout=10)
        if resp.status_code == 200:
            return {"accessible": True, "data_preview": str(resp.text[:200])}
        return {"accessible": False, "reason": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"accessible": False, "reason": str(e)}


def _check_aws_key(access_key: str) -> dict:
    """Quick check if an AWS access key is valid (without making real API calls).

    Args:
        access_key: AWS access key ID

    Returns:
        Dict with check result.
    """
    # Basic format validation
    if access_key.startswith("AKIA") and len(access_key) == 20:
        return {"valid_format": True, "type": "IAM user key"}
    elif access_key.startswith("ASIA") and len(access_key) == 20:
        return {"valid_format": True, "type": "Temporary session key"}
    return {"valid_format": False, "type": "unknown"}


def analyze_apk(apk_path: str, output_dir: str = "decompiled",
                check_cloud: bool = True) -> ApkAnalysisResult:
    """Full APK analysis pipeline.

    Steps:
    1. Decompile with jadx
    2. Parse AndroidManifest.xml
    3. Extract endpoints/URLs
    4. Extract secrets (API keys, tokens)
    5. Check cloud services (Firebase, AWS)

    Args:
        apk_path: Path to APK file
        output_dir: Output directory for decompiled code
        check_cloud: If True, verify cloud endpoints

    Returns:
        ApkAnalysisResult with all findings.
    """
    result = ApkAnalysisResult(apk_path=apk_path)

    # Step 1: Decompile
    logger.info("Decompiling %s ...", apk_path)
    out = decompile_apk(apk_path, output_dir)
    decompile_dir = str(out)

    # Step 2: Manifest analysis
    manifest = extract_manifest(decompile_dir)
    result.package = manifest.get("package", "")
    result.debuggable = manifest.get("debuggable", False)
    result.allow_backup = manifest.get("allowBackup", False)
    result.permissions = manifest.get("permissions", [])
    result.exported_components = manifest.get("exported_components", [])
    result.activities = manifest.get("activities", [])

    # Findings from manifest
    if result.debuggable:
        result.findings.append({
            "type": "debuggable_app",
            "severity": "high",
            "description": "App is debuggable (android:debuggable=true)",
        })
    if result.allow_backup:
        result.findings.append({
            "type": "allow_backup",
            "severity": "medium",
            "description": "App allows backup (android:allowBackup=true)",
        })
    if "android.permission.INTERNET" not in result.permissions:
        result.findings.append({
            "type": "no_internet",
            "severity": "info",
            "description": "App does not request INTERNET permission",
        })

    # Step 3: Extract endpoints
    result.endpoints = extract_endpoints(decompile_dir)

    # Step 4: Extract secrets
    result.secrets = extract_secrets(decompile_dir)

    # Step 5: Cloud service analysis
    if check_cloud:
        cloud_findings = _check_cloud_services(result.endpoints, result.secrets)
        result.cloud_services = cloud_findings["services"]
        result.findings.extend(cloud_findings["findings"])

    return result


def _check_cloud_services(
    endpoints: list[dict],
    secrets: list[dict],
) -> dict:
    """Identify and verify cloud services from extracted data."""
    services: list[CloudEndpoint] = []
    findings: list[dict] = []

    # Firebase URLs
    for ep in endpoints:
        url = ep.get("value", "")
        if "firebaseio.com" in url:
            services.append(CloudEndpoint(
                service="Firebase",
                url=url,
                confidence=ep.get("confidence", "medium"),
                file=ep.get("file", ""),
            ))

    # AWS keys
    for sec in secrets:
        if sec.get("type") == "aws_access_key":
            value = sec.get("value", "")
            check = _check_aws_key(value)
            if check.get("valid_format"):
                findings.append({
                    "type": "aws_key_exposed",
                    "severity": "critical",
                    "description": f"AWS access key found in {sec.get('file')}",
                    "evidence": value[:20] + "...",
                })

    # Firebase accessibility check
    for svc in services:
        try:
            fb_check = _check_firebase(svc.url)
            if fb_check.get("accessible"):
                findings.append({
                    "type": "firebase_open",
                    "severity": "critical",
                    "description": f"Firebase DB is publicly accessible: {svc.url}",
                    "evidence": str(fb_check.get("data_preview", "")[:200]),
                })
            else:
                findings.append({
                    "type": "firebase_found",
                    "severity": "info",
                    "description": f"Firebase URL found: {svc.url}",
                })
        except Exception as e:
            logger.debug("Firebase check failed for %s: %s", svc.url, e)

    return {"services": services, "findings": findings}


def generate_apk_report(analysis: ApkAnalysisResult) -> str:
    """Generate a markdown report from APK analysis.

    Args:
        analysis: ApkAnalysisResult from analyze_apk()

    Returns:
        Markdown report string.
    """
    lines = [
        f"# APK Analysis Report: {analysis.package}",
        f"",
        f"- **APK**: {analysis.apk_path}",
        f"- **Package**: {analysis.package}",
        f"- **Debuggable**: {'Yes' if analysis.debuggable else 'No'}",
        f"- **Allow Backup**: {'Yes' if analysis.allow_backup else 'No'}",
        f"",
        "## Permissions",
    ]
    for p in analysis.permissions:
        lines.append(f"- `{p}`")

    lines.extend(["", "## Exported Components"])
    for c in analysis.exported_components:
        lines.append(f"- {c}")

    if analysis.endpoints:
        lines.extend(["", "## Endpoints"])
        for ep in analysis.endpoints[:20]:
            lines.append(f"- [{ep['confidence']}] {ep['value']}")
        if len(analysis.endpoints) > 20:
            lines.append(f"- ... and {len(analysis.endpoints) - 20} more")

    if analysis.secrets:
        lines.extend(["", "## Secrets Found"])
        for sec in analysis.secrets:
            lines.append(
                f"- [{sec['confidence']}] {sec['type']}: {sec['value'][:50]} "
                f"(line {sec.get('line', '?')})"
            )

    if analysis.cloud_services:
        lines.extend(["", "## Cloud Services"])
        for svc in analysis.cloud_services:
            lines.append(f"- {svc.service}: {svc.url}")

    if analysis.findings:
        lines.extend(["", "## Findings"])
        for f in analysis.findings:
            lines.append(f"- **[{f['severity'].upper()}]** {f['description']}")

    lines.append("")
    return "\n".join(lines)
