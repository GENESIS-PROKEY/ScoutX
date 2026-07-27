"""Subdomain source: DNSDB (Farsight Security) API v2.

Requires an API key. Get one at https://www.dnsdb.info/
Set via config: api_keys.dnsdb or env: SX_DNSDB_KEY
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any

import httpx

logger = logging.getLogger("scoutx.sources.dnsdb")

SOURCE_NAME = "DNSDB"
REQUIRES_KEY = True
BASE_URL = "https://api.dnsdb.info/dnsdb/v2"


async def fetch(domain: str, client: httpx.AsyncClient, **kwargs: Any) -> set[str]:
    """Query DNSDB for historical subdomain records."""
    results: set[str] = set()

    api_key = kwargs.get("api_key") or os.environ.get("SX_DNSDB_KEY", "")
    if not api_key:
        logger.debug("DNSDB: no API key, skipping")
        return results

    try:
        resp = await client.get(
            f"{BASE_URL}/lookup/rrset/name/*.{domain}",
            headers={
                "X-API-Key": api_key,
                "Accept": "application/x-ndjson",
            },
            timeout=30.0,
        )
        if resp.status_code != 200:
            logger.warning("DNSDB returned %d", resp.status_code)
            return results

        # DNSDB returns NDJSON (one JSON object per line)
        import json
        for line in resp.text.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                obj = record.get("obj", {})
                rrname = obj.get("rrname", "").strip().lower().rstrip(".")
                if rrname and (rrname.endswith(f".{domain}") or rrname == domain):
                    if _is_valid(rrname):
                        results.add(rrname)
            except json.JSONDecodeError:
                continue

    except httpx.TimeoutException:
        logger.warning("DNSDB timed out for %s", domain)
    except Exception as exc:
        logger.warning("DNSDB error for %s: %s", domain, exc)

    return results


def _is_valid(hostname: str) -> bool:
    """Basic hostname validation."""
    if not hostname or " " in hostname or "*" in hostname:
        return False
    return bool(re.match(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$", hostname))
