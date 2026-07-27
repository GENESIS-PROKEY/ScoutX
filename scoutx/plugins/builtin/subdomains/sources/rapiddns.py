"""Subdomain source: RapidDNS — free DNS lookup database."""
from __future__ import annotations

import logging
import re
from typing import Any

import httpx

logger = logging.getLogger("scoutx.sources.rapiddns")

SOURCE_NAME = "rapiddns"
REQUIRES_KEY = False
BASE_URL = "https://rapiddns.io/subdomain"


async def fetch(domain: str, client: httpx.AsyncClient, **kwargs: Any) -> set[str]:
    """Scrape RapidDNS for subdomains."""
    results: set[str] = set()
    try:
        resp = await client.get(
            f"{BASE_URL}/{domain}",
            params={"full": 1, "down": 1},
            timeout=20.0,
            headers={"Accept": "text/html"},
        )
        if resp.status_code != 200:
            logger.warning("RapidDNS returned %d", resp.status_code)
            return results

        # Parse subdomains from HTML table
        pattern = re.compile(r"([a-zA-Z0-9\-\.]+\." + re.escape(domain) + r")")
        for match in pattern.finditer(resp.text):
            hostname = match.group(1).strip().lower()
            if hostname:
                results.add(hostname)

    except httpx.TimeoutException:
        logger.warning("RapidDNS timed out for %s", domain)
    except Exception as exc:
        logger.warning("RapidDNS error for %s: %s", domain, exc)

    return results
