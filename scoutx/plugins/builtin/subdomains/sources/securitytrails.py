"""Subdomain source: SecurityTrails API.

Requires an API key. Get one at https://securitytrails.com/app/signup
Set via config: api_keys.securitytrails or env: SX_SECURITYTRAILS_KEY
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger("scoutx.sources.securitytrails")

SOURCE_NAME = "SecurityTrails"
REQUIRES_KEY = True
BASE_URL = "https://api.securitytrails.com/v1"


async def fetch(domain: str, client: httpx.AsyncClient, **kwargs: Any) -> set[str]:
    """Query SecurityTrails for subdomains."""
    results: set[str] = set()

    api_key = kwargs.get("api_key") or os.environ.get("SX_SECURITYTRAILS_KEY", "")
    if not api_key:
        logger.debug("SecurityTrails: no API key, skipping")
        return results

    try:
        resp = await client.get(
            f"{BASE_URL}/domain/{domain}/subdomains",
            headers={"APIKEY": api_key, "Accept": "application/json"},
            timeout=30.0,
        )
        if resp.status_code != 200:
            logger.warning("SecurityTrails returned %d", resp.status_code)
            return results

        data = resp.json()
        for sub in data.get("subdomains", []):
            fqdn = f"{sub.strip().lower()}.{domain}"
            results.add(fqdn)

    except httpx.TimeoutException:
        logger.warning("SecurityTrails timed out for %s", domain)
    except Exception as exc:
        logger.warning("SecurityTrails error for %s: %s", domain, exc)

    return results
