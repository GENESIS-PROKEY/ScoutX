"""Subdomain source: AlienVault OTX — Open Threat Exchange.

Free passive DNS data. No API key required for basic queries.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger("scoutx.sources.alienvault")

SOURCE_NAME = "alienvault"
REQUIRES_KEY = False
BASE_URL = "https://otx.alienvault.com/api/v1/indicators/domain"


async def fetch(domain: str, client: httpx.AsyncClient, **kwargs: Any) -> set[str]:
    """Query AlienVault OTX for passive DNS subdomains."""
    results: set[str] = set()
    try:
        resp = await client.get(
            f"{BASE_URL}/{domain}/passive_dns",
            timeout=20.0,
        )
        if resp.status_code != 200:
            logger.warning("AlienVault returned %d", resp.status_code)
            return results

        data = resp.json()
        for record in data.get("passive_dns", []):
            hostname = record.get("hostname", "").strip().lower()
            if hostname and (hostname.endswith(f".{domain}") or hostname == domain):
                results.add(hostname)

    except httpx.TimeoutException:
        logger.warning("AlienVault timed out for %s", domain)
    except Exception as exc:
        logger.warning("AlienVault error for %s: %s", domain, exc)

    return results
