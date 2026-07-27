"""Subdomain source: Censys Certificates API v2.

Requires API ID + Secret. Get them at https://search.censys.io/account/api
Set via config: api_keys.censys_id / api_keys.censys_secret
Or env: SX_CENSYS_ID / SX_CENSYS_SECRET
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any

import httpx

logger = logging.getLogger("scoutx.sources.censys")

SOURCE_NAME = "Censys"
REQUIRES_KEY = True
BASE_URL = "https://search.censys.io/api/v2"


async def fetch(domain: str, client: httpx.AsyncClient, **kwargs: Any) -> set[str]:
    """Query Censys certificate search for subdomains."""
    results: set[str] = set()

    api_id = kwargs.get("censys_id") or os.environ.get("SX_CENSYS_ID", "")
    api_secret = kwargs.get("censys_secret") or os.environ.get("SX_CENSYS_SECRET", "")
    if not api_id or not api_secret:
        logger.debug("Censys: no credentials, skipping")
        return results

    try:
        cursor = None
        for _ in range(3):  # Max 3 pages
            params: dict[str, Any] = {"q": f"names: {domain}", "per_page": 100}
            if cursor:
                params["cursor"] = cursor

            resp = await client.get(
                f"{BASE_URL}/certificates/search",
                auth=(api_id, api_secret),
                params=params,
                timeout=30.0,
            )
            if resp.status_code != 200:
                logger.warning("Censys returned %d", resp.status_code)
                break

            data = resp.json()
            for hit in data.get("result", {}).get("hits", []):
                for name in hit.get("names", []):
                    clean = name.strip().lower().lstrip("*.")
                    if clean and (clean.endswith(f".{domain}") or clean == domain):
                        if _is_valid(clean):
                            results.add(clean)

            # Pagination
            links = data.get("result", {}).get("links", {})
            cursor = links.get("next") if links.get("next") != "" else None
            if not cursor:
                break

    except httpx.TimeoutException:
        logger.warning("Censys timed out for %s", domain)
    except Exception as exc:
        logger.warning("Censys error for %s: %s", domain, exc)

    return results


def _is_valid(hostname: str) -> bool:
    """Basic hostname validation."""
    if not hostname or " " in hostname or "*" in hostname:
        return False
    return bool(re.match(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$", hostname))
