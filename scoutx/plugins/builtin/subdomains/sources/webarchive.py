"""Subdomain source: Web Archive (Wayback Machine) — historical URL data."""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("scoutx.sources.webarchive")

SOURCE_NAME = "webarchive"
REQUIRES_KEY = False
BASE_URL = "https://web.archive.org/cdx/search/cdx"


async def fetch(domain: str, client: httpx.AsyncClient, **kwargs: Any) -> set[str]:
    """Query Wayback Machine CDX API for historical subdomains."""
    results: set[str] = set()
    try:
        resp = await client.get(
            BASE_URL,
            params={
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey",
                "limit": 5000,
            },
            timeout=30.0,
        )
        if resp.status_code != 200:
            logger.warning("Wayback returned %d", resp.status_code)
            return results

        rows = resp.json()
        for row in rows[1:]:  # Skip header row
            if not row:
                continue
            url = row[0] if isinstance(row, list) else str(row)
            try:
                hostname = urlparse(url).hostname
                if hostname:
                    hostname = hostname.strip().lower()
                    if hostname.endswith(f".{domain}") or hostname == domain:
                        results.add(hostname)
            except Exception:
                continue

    except httpx.TimeoutException:
        logger.warning("Wayback timed out for %s", domain)
    except Exception as exc:
        logger.warning("Wayback error for %s: %s", domain, exc)

    return results
