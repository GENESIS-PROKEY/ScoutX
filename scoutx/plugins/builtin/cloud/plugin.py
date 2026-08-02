"""Cloud Asset Discovery Plugin — detect AWS, GCP, Azure, and other cloud services.

Analyzes probe responses, SSL certificates, and DNS records to identify
cloud infrastructure used by the target.
"""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin
from scoutx.utils.io import write_json

if TYPE_CHECKING:
    from scoutx.core.engine import ScanContext

logger = logging.getLogger("scoutx.plugins.cloud")

# Cloud provider patterns in CNAMEs, headers, and response bodies
CLOUD_PATTERNS: dict[str, dict[str, Any]] = {
    "aws": {
        "cnames": [
            r"\.amazonaws\.com$", r"\.cloudfront\.net$", r"\.elasticbeanstalk\.com$",
            r"\.elb\.amazonaws\.com$", r"\.s3\.amazonaws\.com$", r"\.s3[-.]",
        ],
        "headers": {"server": ["AmazonS3", "awselb"], "x-amz-request-id": None, "x-amz-id-2": None},
        "services": ["S3", "CloudFront", "Elastic Beanstalk", "ELB", "EC2", "Lambda"],
    },
    "gcp": {
        "cnames": [
            r"\.googleapis\.com$", r"\.appspot\.com$", r"\.run\.app$",
            r"\.cloudfunctions\.net$", r"\.storage\.googleapis\.com$",
        ],
        "headers": {"server": ["Google Frontend", "gws"], "x-goog-": None},
        "services": ["Cloud Run", "App Engine", "Cloud Functions", "Cloud Storage"],
    },
    "azure": {
        "cnames": [
            r"\.azurewebsites\.net$", r"\.azure-api\.net$", r"\.azureedge\.net$",
            r"\.blob\.core\.windows\.net$", r"\.cloudapp\.azure\.com$",
            r"\.trafficmanager\.net$", r"\.azurefd\.net$",
        ],
        "headers": {"server": ["Microsoft-IIS"], "x-ms-request-id": None, "x-azure-ref": None},
        "services": ["App Service", "Blob Storage", "CDN", "Traffic Manager", "Front Door"],
    },
    "cloudflare": {
        "cnames": [r"\.cloudflare\.com$", r"\.cloudflaressl\.com$"],
        "headers": {"server": ["cloudflare"], "cf-ray": None, "cf-cache-status": None},
        "services": ["CDN", "WAF", "DNS"],
    },
    "digitalocean": {
        "cnames": [r"\.digitaloceanspaces\.com$", r"\.ondigitalocean\.app$"],
        "headers": {"server": ["nginx"]},
        "services": ["Spaces", "App Platform", "Droplets"],
    },
    "heroku": {
        "cnames": [r"\.herokuapp\.com$", r"\.herokucdn\.com$", r"\.herokudns\.com$"],
        "headers": {"via": ["vegur"]},
        "services": ["Dynos", "Heroku Postgres"],
    },
    "vercel": {
        "cnames": [r"\.vercel\.app$", r"\.now\.sh$"],
        "headers": {"server": ["Vercel"], "x-vercel-id": None},
        "services": ["Serverless Functions", "Edge Network"],
    },
    "netlify": {
        "cnames": [r"\.netlify\.app$", r"\.netlify\.com$"],
        "headers": {"server": ["Netlify"]},
        "services": ["CDN", "Serverless Functions"],
    },
}

# S3 bucket patterns in URLs
S3_RE = re.compile(
    r"(?:https?://)?(?:([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-]|s3[.\-][a-z0-9\-]+\.amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}))",
    re.IGNORECASE,
)


class Plugin(ScoutPlugin):
    """Discover cloud infrastructure from probe data, SSL certs, and DNS."""

    meta = PluginMeta(
        name="cloud",
        description="Cloud asset discovery — AWS, GCP, Azure, Cloudflare, and more",
        version="0.1.0",
        author="ScoutX",
        tags=["cloud", "aws", "gcp", "azure", "infrastructure"],
    )
    depends_on: list[str] = ["probe", "ssl_analysis"]
    concurrent_with: list[str] = ["intelligence"]

    async def run(self, context: ScanContext) -> PluginResult:
        from scoutx.cli.ui import info, success

        output_dir = context.output_dir / "cloud"
        output_dir.mkdir(parents=True, exist_ok=True)

        probe_data = context.result_data("probe")
        ssl_data = context.result_data("ssl_analysis")

        hosts = probe_data.get("alive_hosts", [])
        if not hosts:
            return PluginResult.skipped("No alive hosts to analyze")

        info(f"Analyzing {len(hosts)} hosts for cloud infrastructure...")

        cloud_assets: dict[str, list[dict]] = {}
        s3_buckets: list[str] = []
        total_findings = 0

        for host in hosts:
            hostname = host.get("hostname", "") if isinstance(host, dict) else str(host)
            headers = host.get("headers", {}) if isinstance(host, dict) else {}
            cnames = host.get("cnames", []) if isinstance(host, dict) else []

            for provider, config in CLOUD_PATTERNS.items():
                detected = False
                evidence: list[str] = []

                # Check CNAMEs
                all_cnames = cnames if cnames else [hostname]
                for cname in all_cnames:
                    for pattern in config.get("cnames", []):
                        if re.search(pattern, str(cname), re.IGNORECASE):
                            detected = True
                            evidence.append(f"CNAME: {cname}")
                            break

                # Check response headers
                for header_key, header_vals in config.get("headers", {}).items():
                    header_lower = {k.lower(): v for k, v in headers.items()} if headers else {}
                    for hk, hv in header_lower.items():
                        if header_key.lower() in hk:
                            if header_vals is None or any(v.lower() in str(hv).lower() for v in header_vals):
                                detected = True
                                evidence.append(f"Header: {hk}={hv}")

                if detected:
                    if provider not in cloud_assets:
                        cloud_assets[provider] = []
                    cloud_assets[provider].append({
                        "hostname": hostname,
                        "services": config.get("services", []),
                        "evidence": evidence,
                    })
                    total_findings += 1

            # S3 bucket extraction from URLs
            body = host.get("body", "") if isinstance(host, dict) else ""
            for match in S3_RE.finditer(str(body) + str(hostname)):
                bucket = match.group(1) or match.group(2)
                if bucket and bucket not in s3_buckets:
                    s3_buckets.append(bucket)

        # Check SSL cert SANs for cloud patterns
        ssl_certs = ssl_data.get("certificates", [])
        for cert in ssl_certs:
            sans = cert.get("san", []) if isinstance(cert, dict) else []
            for san in sans:
                for provider, config in CLOUD_PATTERNS.items():
                    for pattern in config.get("cnames", []):
                        if re.search(pattern, str(san), re.IGNORECASE):
                            if provider not in cloud_assets:
                                cloud_assets[provider] = []
                            cloud_assets[provider].append({
                                "hostname": san,
                                "services": config.get("services", []),
                                "evidence": [f"SSL SAN: {san}"],
                            })
                            total_findings += 1

        result = {
            "cloud_providers": cloud_assets,
            "s3_buckets": s3_buckets,
            "total_assets": total_findings,
            "providers_detected": list(cloud_assets.keys()),
        }

        write_json(output_dir / "cloud_assets.json", result)

        if cloud_assets:
            success(f"Found {total_findings} cloud assets across {len(cloud_assets)} providers")
            for provider, assets in cloud_assets.items():
                info(f"  {provider.upper()}: {len(assets)} assets")
        if s3_buckets:
            info(f"  S3 buckets: {len(s3_buckets)}")

        return PluginResult.completed(data=result, findings_count=total_findings)

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={"cloud_providers": dict, "s3_buckets": list, "total_assets": int},
            description="Cloud infrastructure detected for the target",
        )
