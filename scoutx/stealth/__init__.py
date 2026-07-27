"""Ghost Mode — stealth scanning infrastructure.

Combines adaptive rate limiting and proxy rotation into a unified
interface for responsible, distributed scanning.
"""
from __future__ import annotations

import logging
from typing import Any

from scoutx.stealth.proxy import ProxyRotator
from scoutx.stealth.ratelimit import AdaptiveRateLimiter

__all__ = ["StealthManager", "AdaptiveRateLimiter", "ProxyRotator"]

logger = logging.getLogger("scoutx.stealth")


class StealthManager:
    """Unified stealth interface — rate limiting + proxy rotation.

    Config format (in scoutx.yaml):
        stealth:
          enabled: true
          rate_limit:
            base_delay: 0.1
            max_delay: 5.0
            backoff_factor: 2.0
          proxy:
            file: proxies.txt
            rotate: true
    """

    def __init__(
        self,
        rate_limiter: AdaptiveRateLimiter | None = None,
        proxy_rotator: ProxyRotator | None = None,
        enabled: bool = True,
    ) -> None:
        self.enabled = enabled
        self.rate_limiter = rate_limiter or AdaptiveRateLimiter()
        self.proxy_rotator = proxy_rotator

    async def acquire(self, host: str) -> str | None:
        """Wait for rate limit clearance and return proxy URL (or None).

        Call this before each outbound request:
            proxy = await stealth.acquire("example.com")
            async with httpx.AsyncClient(proxy=proxy) as client:
                resp = await client.get(url)
                stealth.report_response("example.com", resp.status_code)
        """
        if not self.enabled:
            return self.proxy_rotator.next_proxy() if self.proxy_rotator else None

        await self.rate_limiter.acquire(host)
        return self.proxy_rotator.next_proxy() if self.proxy_rotator else None

    def report_response(self, host: str, status_code: int) -> None:
        """Report response for adaptive pacing."""
        if self.enabled:
            self.rate_limiter.report_response(host, status_code)

    def report_error(self, host: str, error: Exception) -> None:
        """Report connection error."""
        if self.enabled:
            self.rate_limiter.report_error(host, error)

    @property
    def has_proxies(self) -> bool:
        return self.proxy_rotator is not None and self.proxy_rotator.available_count > 0

    @property
    def stats(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "enabled": self.enabled,
            "rate_limiter": self.rate_limiter.stats,
        }
        if self.proxy_rotator:
            result["proxy"] = self.proxy_rotator.stats
        return result

    @classmethod
    def from_config(cls, config: dict) -> StealthManager:
        """Create StealthManager from ScoutX config dict."""
        stealth_cfg = config.get("stealth", {})
        enabled = stealth_cfg.get("enabled", False)

        # Rate limiter
        rl_cfg = stealth_cfg.get("rate_limit", {})
        rate_limiter = AdaptiveRateLimiter(
            base_delay=float(rl_cfg.get("base_delay", 0.1)),
            max_delay=float(rl_cfg.get("max_delay", 5.0)),
            backoff_factor=float(rl_cfg.get("backoff_factor", 2.0)),
        )

        # Proxy rotator
        proxy_rotator = None
        proxy_cfg = stealth_cfg.get("proxy", {})
        proxy_file = proxy_cfg.get("file")
        proxy_list = proxy_cfg.get("list", [])
        if proxy_file or proxy_list:
            proxy_rotator = ProxyRotator(
                proxies=proxy_list if proxy_list else None,
                proxy_file=proxy_file,
            )

        return cls(
            rate_limiter=rate_limiter,
            proxy_rotator=proxy_rotator,
            enabled=enabled,
        )
