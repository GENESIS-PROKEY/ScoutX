"""DNS utilities — async resolution, bulk lookups, wildcard detection."""
from __future__ import annotations

import asyncio
import logging
import socket

logger = logging.getLogger("scoutx.dns")


async def resolve(hostname: str, record_type: str = "A") -> list[str]:
    """Async DNS resolution using getaddrinfo."""
    loop = asyncio.get_running_loop()
    try:
        if record_type == "A":
            results = await loop.getaddrinfo(hostname, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
            return list({r[4][0] for r in results})
        elif record_type == "AAAA":
            results = await loop.getaddrinfo(hostname, None, family=socket.AF_INET6, type=socket.SOCK_STREAM)
            return list({r[4][0] for r in results})
        else:
            results = await loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
            return list({r[4][0] for r in results})
    except (socket.gaierror, OSError):
        return []


async def resolve_bulk(
    hostnames: list[str],
    concurrency: int = 50,
    record_type: str = "A",
) -> dict[str, list[str]]:
    """Resolve multiple hostnames concurrently."""
    semaphore = asyncio.Semaphore(concurrency)
    results: dict[str, list[str]] = {}

    async def _resolve_one(host: str) -> None:
        async with semaphore:
            ips = await resolve(host, record_type)
            results[host] = ips

    await asyncio.gather(*[_resolve_one(h) for h in hostnames], return_exceptions=True)
    return results


async def reverse_lookup(ip: str) -> str | None:
    """Reverse DNS lookup."""
    loop = asyncio.get_running_loop()
    try:
        hostname, _, _ = await loop.getnameinfo((ip, 0), socket.NI_NAMEREQD)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


async def is_wildcard(domain: str) -> bool:
    """Detect wildcard DNS by resolving a random subdomain."""
    import secrets
    import string

    random_sub = "".join(secrets.choice(string.ascii_lowercase) for _ in range(12))
    test_host = f"{random_sub}.{domain}"
    ips = await resolve(test_host)
    return len(ips) > 0


async def zone_transfer(domain: str) -> list[str]:
    """Attempt DNS zone transfer (AXFR).

    Returns list of discovered hostnames or empty list if transfer denied.
    Note: Most DNS servers deny zone transfers — this is a best-effort check.
    """
    # Zone transfer requires dnspython or similar — stub for now
    # Will be implemented with dnspython in Phase 2
    logger.debug("Zone transfer attempt for %s (stub — requires dnspython)", domain)
    return []
