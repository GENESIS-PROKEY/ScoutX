"""Subdomain source: VirusTotal API v3.

Requires an API key. Get one at https://www.virustotal.com/gui/join-us
Set via config: api_keys.virustotal or env: SX_VIRUSTOTAL_KEY
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger("scoutx.sources.virustotal")

SOURCE_NAME = "VirusTotal"
REQUIRES_KEY = True
BASE_URL = "https://www.virustotal.com/api/v3"


async def fetch(domain: str, client: httpx.AsyncClient, **kwargs: Any) -> set[str]:
    """Query VirusTotal for subdomains."""
    results: set[str] = set()

    api_key = kwargs.get("api_key") or os.environ.get("SX_VIRUSTOTAL_KEY", "")
    if not api_key:
        logger.debug("VirusTotal: no API key, skipping")
        return results

    try:
        cursor = None
        for _ in range(5):  # Max 5 pages
            params: dict[str, Any] = {"limit": 40}
            if cursor:
                params["cursor"] = cursor

            resp = await client.get(
                f"{BASE_URL}/domains/{domain}/subdomains",
                headers={"x-apikey": api_key, "Accept": "application/json"},
                params=params,
                timeout=30.0,
            )
            if resp.status_code != 200:
                logger.warning("VirusTotal returned %d", resp.status_code)
                break

            data = resp.json()
            for item in data.get("data", []):
                sub_id = item.get("id", "").strip().lower()
                if sub_id and (sub_id.endswith(f".{domain}") or sub_id == domain):
                    results.add(sub_id)

            # Pagination
            cursor = data.get("meta", {}).get("cursor")
            if not cursor or not data.get("data"):
                break

    except httpx.TimeoutException:
        logger.warning("VirusTotal timed out for %s", domain)
    except Exception as exc:
        logger.warning("VirusTotal error for %s: %s", domain, exc)

    return results
