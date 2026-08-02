"""Historical DNS and Wayback Machine Plugin — dig into the past.

Queries the Wayback Machine CDX API for archived URLs and SecurityTrails
for historical DNS records. Compares current vs historical to find
removed-but-not-deleted assets.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx

from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin
from scoutx.utils.io import write_json

if TYPE_CHECKING:
    from scoutx.core.engine import ScanContext

logger = logging.getLogger("scoutx.plugins.historical")

# Interesting URL patterns in Wayback data
INTERESTING_PATTERNS = [
    "/admin", "/login", "/dashboard", "/config", "/api/",
    "/internal", "/staging", "/debug", "/backup",
    ".env", ".git", ".sql", ".bak", ".old", ".zip",
    "wp-admin", "phpinfo", "phpmyadmin",
    "swagger", "graphql", "api-docs",
    "/console", "/manager", "/jenkins",
]


class Plugin(ScoutPlugin):
    """Pull historical intelligence from Wayback Machine and DNS archives."""

    meta = PluginMeta(
        name="historical",
        description="Historical DNS records and Wayback Machine URL discovery",
        version="0.1.0",
        author="ScoutX",
        tags=["wayback", "historical", "dns", "archive", "osint"],
    )
    depends_on: list[str] = ["subdomains"]
    concurrent_with: list[str] = ["github_dork"]

    async def run(self, context: ScanContext) -> PluginResult:
        from scoutx.cli.ui import info, success

        output_dir = context.output_dir / "historical"
        output_dir.mkdir(parents=True, exist_ok=True)

        domain = context.target
        info(f"Querying historical data for: {domain}")

        wayback_urls = await self._query_wayback(domain)
        interesting_urls = self._filter_interesting(wayback_urls)

        # SecurityTrails historical DNS (if API key available)
        st_key = context.config.get("api_keys.securitytrails", "")
        dns_history: dict[str, Any] = {}
        if st_key:
            dns_history = await self._query_securitytrails(domain, st_key)
        else:
            info("  SecurityTrails API key not set, skipping historical DNS")

        # Compare with current subdomains
        sub_data = context.result_data("subdomains")
        current_subs = set()
        for entry in sub_data.get("subdomains", []):
            if isinstance(entry, dict):
                current_subs.add(entry.get("hostname", ""))
            elif isinstance(entry, str):
                current_subs.add(entry)

        # Extract historical subdomains from Wayback URLs
        historical_subs = set()
        for url in wayback_urls:
            try:
                parsed = urlparse(url)
                if parsed.hostname:
                    historical_subs.add(parsed.hostname)
            except ValueError:
                continue

        # Find removed subdomains (existed historically but not in current scan)
        removed_subs = historical_subs - current_subs

        result = {
            "wayback_urls_total": len(wayback_urls),
            "interesting_urls": interesting_urls[:500],
            "historical_subdomains": sorted(historical_subs)[:200],
            "removed_subdomains": sorted(removed_subs)[:100],
            "dns_history": dns_history,
        }

        write_json(output_dir / "wayback_urls.json", {
            "total": len(wayback_urls),
            "interesting": interesting_urls[:500],
            "all_urls": wayback_urls[:2000],
        })

        if dns_history:
            write_json(output_dir / "dns_history.json", dns_history)

        total_findings = len(interesting_urls) + len(removed_subs)
        success(
            f"Historical: {len(wayback_urls)} Wayback URLs, "
            f"{len(interesting_urls)} interesting, "
            f"{len(removed_subs)} removed subdomains"
        )

        return PluginResult.completed(data=result, findings_count=total_findings)

    async def _query_wayback(self, domain: str) -> list[str]:
        """Query Wayback Machine CDX API for archived URLs."""
        cdx_url = "http://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"*.{domain}",
            "output": "json",
            "fl": "original,timestamp,statuscode",
            "collapse": "urlkey",
            "limit": "5000",
        }

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(cdx_url, params=params)
                if resp.status_code != 200:
                    logger.warning(f"Wayback CDX returned {resp.status_code}")
                    return []

                rows = resp.json()
                if not rows or len(rows) < 2:
                    return []

                # First row is header
                urls = []
                for row in rows[1:]:
                    if len(row) >= 1:
                        urls.append(row[0])
                return list(set(urls))

        except httpx.HTTPError as e:
            logger.warning(f"Wayback Machine error: {e}")
            return []
        except Exception as e:
            logger.warning(f"Wayback parse error: {e}")
            return []

    def _filter_interesting(self, urls: list[str]) -> list[str]:
        """Filter URLs for interesting patterns."""
        interesting = []
        for url in urls:
            url_lower = url.lower()
            if any(pattern in url_lower for pattern in INTERESTING_PATTERNS):
                interesting.append(url)
        return interesting

    async def _query_securitytrails(self, domain: str, api_key: str) -> dict[str, Any]:
        """Query SecurityTrails for historical DNS records."""
        headers = {"APIKEY": api_key, "Accept": "application/json"}

        result: dict[str, Any] = {}

        try:
            async with httpx.AsyncClient(timeout=15, headers=headers) as client:
                # Historical A records
                resp = await client.get(
                    f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
                )
                if resp.status_code == 200:
                    data = resp.json()
                    records = data.get("records", [])
                    result["a_records"] = [
                        {
                            "ip": r.get("values", [{}])[0].get("ip", "") if r.get("values") else "",
                            "first_seen": r.get("first_seen", ""),
                            "last_seen": r.get("last_seen", ""),
                        }
                        for r in records[:50]
                    ]

                # Historical NS records
                resp = await client.get(
                    f"https://api.securitytrails.com/v1/history/{domain}/dns/ns"
                )
                if resp.status_code == 200:
                    data = resp.json()
                    records = data.get("records", [])
                    result["ns_records"] = [
                        {
                            "nameserver": r.get("values", [{}])[0].get("nameserver", "") if r.get("values") else "",
                            "first_seen": r.get("first_seen", ""),
                            "last_seen": r.get("last_seen", ""),
                        }
                        for r in records[:30]
                    ]

        except httpx.HTTPError as e:
            logger.warning(f"SecurityTrails error: {e}")

        return result

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={
                "wayback_urls_total": int,
                "interesting_urls": list,
                "removed_subdomains": list,
                "dns_history": dict,
            },
            description="Historical DNS and Wayback Machine data for the target",
        )
