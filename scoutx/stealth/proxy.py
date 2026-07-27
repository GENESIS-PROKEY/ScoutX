"""Proxy Rotation — round-robin through proxy servers for distributed scanning."""
from __future__ import annotations

import itertools
import logging
import re
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("scoutx.stealth.proxy")

# Supported proxy schemes
_PROXY_RE = re.compile(r"^(https?|socks5)://[\w\.\-]+(:\d+)?$", re.IGNORECASE)


class ProxyRotator:
    """Round-robin proxy rotation with health tracking."""

    def __init__(
        self,
        proxies: list[str] | None = None,
        proxy_file: str | None = None,
    ) -> None:
        self._all: list[str] = []
        self._dead: set[str] = set()

        if proxies:
            self._all.extend(p.strip() for p in proxies if self._validate(p.strip()))

        if proxy_file:
            path = Path(proxy_file)
            if path.exists():
                for line in path.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and self._validate(line):
                        self._all.append(line)

        self._cycle = itertools.cycle(self._all) if self._all else None

        if self._all:
            logger.info("Loaded %d proxies for rotation", len(self._all))

    @staticmethod
    def _validate(proxy: str) -> bool:
        """Check if proxy URL format is valid."""
        if _PROXY_RE.match(proxy):
            return True
        logger.warning("Invalid proxy format (skipping): %s", proxy)
        return False

    def next_proxy(self) -> str | None:
        """Get the next available proxy. Returns None if no proxies."""
        if not self._cycle:
            return None

        # Try up to len(all) times to find a non-dead proxy
        for _ in range(len(self._all)):
            proxy = next(self._cycle)
            if proxy not in self._dead:
                return proxy

        return None  # All proxies dead

    async def check_proxy(self, proxy: str, timeout: float = 5.0) -> bool:
        """Verify a proxy is working by making a test request."""
        try:
            async with httpx.AsyncClient(
                proxy=proxy,
                timeout=httpx.Timeout(timeout),
                verify=False,
            ) as client:
                resp = await client.get("https://httpbin.org/ip")
                return resp.status_code == 200
        except Exception:
            return False

    def remove_dead(self, proxy: str) -> None:
        """Mark a proxy as dead (skip in rotation)."""
        self._dead.add(proxy)
        alive = len(self._all) - len(self._dead)
        logger.warning("Proxy marked dead: %s (%d remaining)", proxy[:30], alive)

    def revive(self, proxy: str) -> None:
        """Revive a previously dead proxy."""
        self._dead.discard(proxy)

    @property
    def available_count(self) -> int:
        """Number of currently available (non-dead) proxies."""
        return len(self._all) - len(self._dead)

    @property
    def total_count(self) -> int:
        """Total number of loaded proxies."""
        return len(self._all)

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "total": len(self._all),
            "available": self.available_count,
            "dead": len(self._dead),
        }
