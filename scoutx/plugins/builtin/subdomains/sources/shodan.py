"""Subdomain source: Shodan DNS API.

Requires an API key. Get one at https://account.shodan.io/
Set via config: api_keys.shodan or env: SX_SHODAN_KEY
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger("scoutx.sources.shodan")

SOURCE_NAME = "Shodan"
REQUIRES_KEY = True
BASE_URL = "https://api.shodan.io"


async def fetch(domain: str, client: httpx.AsyncClient, **kwargs: Any) -> set[str]:
    """Query Shodan DNS for subdomains."""
    results: set[str] = set()

    api_key = kwargs.get("api_key") or os.environ.get("SX_SHODAN_KEY", "")
    if not api_key:
        logger.debug("Shodan: no API key, skipping")
        return results

    try:
        resp = await client.get(
            f"{BASE_URL}/dns/domain/{domain}",
            params={"key": api_key},
            timeout=30.0,
        )
        if resp.status_code != 200:
            logger.warning("Shodan returned %d", resp.status_code)
            return results

        data = resp.json()
        for record in data.get("data", []):
            sub = record.get("subdomain", "").strip().lower()
            if sub:
                fqdn = f"{sub}.{domain}" if sub != domain else domain
                results.add(fqdn)

        # Also check the subdomains field directly
        for sub in data.get("subdomains", []):
            fqdn = f"{sub.strip().lower()}.{domain}"
            results.add(fqdn)

    except httpx.TimeoutException:
        logger.warning("Shodan timed out for %s", domain)
    except Exception as exc:
        logger.warning("Shodan error for %s: %s", domain, exc)

    return results
