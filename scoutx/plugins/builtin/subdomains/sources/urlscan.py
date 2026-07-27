"""Subdomain source: urlscan.io — web page scanning service.

Searches urlscan.io's public dataset for subdomains. Free, no key required.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger("scoutx.sources.urlscan")

SOURCE_NAME = "urlscan"
REQUIRES_KEY = False
BASE_URL = "https://urlscan.io/api/v1/search"


async def fetch(domain: str, client: httpx.AsyncClient, **kwargs: Any) -> set[str]:
    """Query urlscan.io for subdomains."""
    results: set[str] = set()
    try:
        resp = await client.get(
            BASE_URL,
            params={"q": f"domain:{domain}", "size": 1000},
            timeout=20.0,
        )
        if resp.status_code != 200:
            logger.warning("urlscan.io returned %d", resp.status_code)
            return results

        data = resp.json()
        for result in data.get("results", []):
            page = result.get("page", {})
            hostname = page.get("domain", "").strip().lower()
            if hostname and (hostname.endswith(f".{domain}") or hostname == domain):
                results.add(hostname)
            # Also check the task URL
            task_url = result.get("task", {}).get("url", "")
            if task_url:
                from urllib.parse import urlparse
                parsed_host = urlparse(task_url).hostname or ""
                parsed_host = parsed_host.lower()
                if parsed_host and (parsed_host.endswith(f".{domain}") or parsed_host == domain):
                    results.add(parsed_host)

    except httpx.TimeoutException:
        logger.warning("urlscan.io timed out for %s", domain)
    except Exception as exc:
        logger.warning("urlscan.io error for %s: %s", domain, exc)

    return results
