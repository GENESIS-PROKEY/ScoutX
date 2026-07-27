"""Subdomain source: AnubisDB — free subdomain database."""
from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger("scoutx.sources.anubis")

SOURCE_NAME = "anubis"
REQUIRES_KEY = False
BASE_URL = "https://jldc.me/anubis/subdomains"


async def fetch(domain: str, client: httpx.AsyncClient, **kwargs: Any) -> set[str]:
    """Query AnubisDB for subdomains."""
    results: set[str] = set()
    try:
        resp = await client.get(
            f"{BASE_URL}/{domain}",
            timeout=20.0,
        )
        if resp.status_code != 200:
            logger.warning("AnubisDB returned %d", resp.status_code)
            return results

        subdomains = resp.json()
        if isinstance(subdomains, list):
            for sub in subdomains:
                hostname = str(sub).strip().lower()
                if hostname and (hostname.endswith(f".{domain}") or hostname == domain):
                    results.add(hostname)

    except httpx.TimeoutException:
        logger.warning("AnubisDB timed out for %s", domain)
    except Exception as exc:
        logger.warning("AnubisDB error for %s: %s", domain, exc)

    return results
