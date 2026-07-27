"""Subdomain source: HackerTarget — free hosted DNS tools."""
from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger("scoutx.sources.hackertarget")

SOURCE_NAME = "hackertarget"
REQUIRES_KEY = False
BASE_URL = "https://api.hackertarget.com/hostsearch"


async def fetch(domain: str, client: httpx.AsyncClient, **kwargs: Any) -> set[str]:
    """Query HackerTarget host search API."""
    results: set[str] = set()
    try:
        resp = await client.get(
            BASE_URL,
            params={"q": domain},
            timeout=20.0,
        )
        if resp.status_code != 200:
            logger.warning("HackerTarget returned %d", resp.status_code)
            return results

        text = resp.text.strip()
        if "error" in text.lower() or "api count" in text.lower():
            logger.warning("HackerTarget rate limited for %s", domain)
            return results

        for line in text.splitlines():
            parts = line.strip().split(",")
            if parts:
                hostname = parts[0].strip().lower()
                if hostname and (hostname.endswith(f".{domain}") or hostname == domain):
                    results.add(hostname)

    except httpx.TimeoutException:
        logger.warning("HackerTarget timed out for %s", domain)
    except Exception as exc:
        logger.warning("HackerTarget error for %s: %s", domain, exc)

    return results
