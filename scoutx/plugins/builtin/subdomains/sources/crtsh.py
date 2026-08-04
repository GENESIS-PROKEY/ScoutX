"""Subdomain source: crt.sh — Certificate Transparency logs.

The single most reliable passive subdomain source. Free, no API key,
massive dataset from CT logs. This is always the first source we hit.
"""
from __future__ import annotations

import logging
import re
from typing import Any

import httpx

logger = logging.getLogger("scoutx.sources.crtsh")

SOURCE_NAME = "crt.sh"
REQUIRES_KEY = False
BASE_URL = "https://crt.sh"


async def fetch(domain: str, client: httpx.AsyncClient, **kwargs: Any) -> set[str]:
    """Query crt.sh for subdomains via Certificate Transparency logs.

    Falls back to CertSpotter if crt.sh is unavailable.
    """
    results: set[str] = set()

    # Primary: crt.sh
    try:
        resp = await client.get(
            f"{BASE_URL}/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=45.0,
        )
        if resp.status_code == 200:
            entries = resp.json()
            for entry in entries:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    clean = name.strip().lower().lstrip("*.")
                    if clean and (clean.endswith(f".{domain}") or clean == domain):
                        if _is_valid_hostname(clean):
                            results.add(clean)
            if results:
                return results
        else:
            logger.warning("crt.sh returned %d", resp.status_code)
    except httpx.TimeoutException:
        logger.warning("crt.sh timed out for %s", domain)
    except Exception as exc:
        logger.warning("crt.sh error for %s: %s", domain, exc)

    # Fallback: CertSpotter (free tier, no key needed)
    if not results:
        try:
            resp = await client.get(
                "https://api.certspotter.com/v1/issuances",
                params={
                    "domain": domain,
                    "include_subdomains": "true",
                    "expand": "dns_names",
                },
                timeout=30.0,
            )
            if resp.status_code == 200:
                for entry in resp.json():
                    for name in entry.get("dns_names", []):
                        clean = name.strip().lower().lstrip("*.")
                        if clean and (clean.endswith(f".{domain}") or clean == domain):
                            if _is_valid_hostname(clean):
                                results.add(clean)
        except Exception as exc:
            logger.debug("CertSpotter fallback failed: %s", exc)

    return results


def _is_valid_hostname(hostname: str) -> bool:
    """Basic hostname validation — no spaces, no wildcards left."""
    if not hostname or " " in hostname or "*" in hostname:
        return False
    if not re.match(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$", hostname):
        return False
    return True
