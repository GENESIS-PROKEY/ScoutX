"""Adaptive Rate Limiter — intelligent request pacing for responsible scanning.

Tracks per-host response patterns and adjusts request timing to avoid
overwhelming targets. This is a POLITE scanner feature — we respect
server capacity and avoid tripping rate limiters so our scans complete
successfully without causing disruption.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("scoutx.stealth.ratelimit")


@dataclass
class HostStats:
    """Per-host request statistics."""

    requests: int = 0
    successes: int = 0
    rate_limited: int = 0
    errors: int = 0
    current_delay: float = 0.0
    last_request: float = 0.0
    total_wait: float = 0.0


class AdaptiveRateLimiter:
    """Adaptive rate limiter that adjusts pacing based on server responses.

    When a target returns 429 (Too Many Requests) or 503 (Service Unavailable),
    we back off exponentially per-host. On successful responses, we gradually
    reduce the delay back to baseline. This ensures our scans complete
    successfully while being responsible.
    """

    def __init__(
        self,
        base_delay: float = 0.1,
        max_delay: float = 5.0,
        backoff_factor: float = 2.0,
        cooldown_factor: float = 0.8,
    ) -> None:
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._backoff_factor = backoff_factor
        self._cooldown_factor = cooldown_factor
        self._host_delays: dict[str, float] = {}
        self._host_stats: dict[str, HostStats] = {}
        self._lock = asyncio.Lock()

    def _ensure_stats(self, host: str) -> HostStats:
        if host not in self._host_stats:
            self._host_stats[host] = HostStats(current_delay=self._base_delay)
        return self._host_stats[host]

    async def acquire(self, host: str) -> None:
        """Wait the appropriate delay before making a request to host."""
        async with self._lock:
            stats = self._ensure_stats(host)
            delay = self._host_delays.get(host, self._base_delay)

            # Enforce minimum inter-request spacing
            now = time.monotonic()
            if stats.last_request > 0:
                elapsed = now - stats.last_request
                if elapsed < delay:
                    wait = delay - elapsed
                    stats.total_wait += wait
                    # Release lock during sleep
                    self._lock.release()
                    try:
                        await asyncio.sleep(wait)
                    finally:
                        await self._lock.acquire()

            stats.requests += 1
            stats.last_request = time.monotonic()

    def report_response(self, host: str, status_code: int) -> None:
        """Report a response -- adjusts rate based on status codes."""
        stats = self._ensure_stats(host)

        # Overloaded / rate-limited responses >> back off
        if status_code in (429, 503, 520, 521, 522, 523, 524, 525, 526):
            stats.rate_limited += 1
            old_delay = self._host_delays.get(host, self._base_delay)
            new_delay = min(old_delay * self._backoff_factor, self._max_delay)
            self._host_delays[host] = new_delay
            stats.current_delay = new_delay

            if stats.rate_limited == 1 or stats.rate_limited % 5 == 0:
                logger.info(
                    "Rate limiting detected on %s (HTTP %d) >> delay now %.1fs",
                    host, status_code, new_delay,
                )

        # Success >> gradually cool down
        elif 200 <= status_code < 400:
            stats.successes += 1
            current = self._host_delays.get(host, self._base_delay)
            if current > self._base_delay:
                new_delay = max(current * self._cooldown_factor, self._base_delay)
                self._host_delays[host] = new_delay
                stats.current_delay = new_delay

    def report_error(self, host: str, error: Exception) -> None:
        """Report a connection error -- may indicate blocking."""
        stats = self._ensure_stats(host)
        stats.errors += 1

        # Connection refused or reset might mean we're blocked
        error_str = str(error).lower()
        if any(kw in error_str for kw in ("refused", "reset", "forbidden", "blocked")):
            old_delay = self._host_delays.get(host, self._base_delay)
            new_delay = min(old_delay * self._backoff_factor, self._max_delay)
            self._host_delays[host] = new_delay
            stats.current_delay = new_delay
            logger.warning(
                "Possible blocking on %s (%s) >> delay now %.1fs",
                host, type(error).__name__, new_delay,
            )

    def get_delay(self, host: str) -> float:
        """Get current delay for a host."""
        return self._host_delays.get(host, self._base_delay)

    @property
    def stats(self) -> dict[str, Any]:
        """Return rate limiting statistics."""
        result: dict[str, Any] = {
            "hosts_tracked": len(self._host_stats),
            "total_requests": sum(s.requests for s in self._host_stats.values()),
            "total_rate_limited": sum(s.rate_limited for s in self._host_stats.values()),
            "total_errors": sum(s.errors for s in self._host_stats.values()),
            "total_wait_seconds": round(sum(s.total_wait for s in self._host_stats.values()), 2),
        }

        # Per-host breakdown for hosts that were rate-limited
        throttled = {}
        for host, s in self._host_stats.items():
            if s.rate_limited > 0 or s.errors > 0:
                throttled[host] = {
                    "requests": s.requests,
                    "rate_limited": s.rate_limited,
                    "errors": s.errors,
                    "current_delay": round(s.current_delay, 3),
                    "total_wait": round(s.total_wait, 2),
                }
        if throttled:
            result["throttled_hosts"] = throttled

        return result

    def reset(self, host: str | None = None) -> None:
        """Reset delays for a specific host or all hosts."""
        if host:
            self._host_delays.pop(host, None)
            self._host_stats.pop(host, None)
        else:
            self._host_delays.clear()
            self._host_stats.clear()
