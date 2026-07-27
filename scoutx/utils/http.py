"""Async HTTP client with retry, rate limiting, proxy rotation, and UA rotation.

The Swiss Army knife of HTTP for recon. Every outbound request goes through here.
"""
from __future__ import annotations

import asyncio
import random
import time
from typing import Any

import httpx

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0",
]

TRANSIENT_STATUS_CODES = {429, 500, 502, 503, 504}


class RateLimiter:
    """Async token-bucket rate limiter."""

    def __init__(self, rate: float, burst: int = 1) -> None:
        self._rate = rate  # tokens per second
        self._burst = burst
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
            self._last_refill = now

            if self._tokens < 1:
                wait = (1 - self._tokens) / self._rate
                await asyncio.sleep(wait)
                self._tokens = 0
            else:
                self._tokens -= 1


class PerHostSemaphore:
    """Per-hostname concurrency limiter."""

    def __init__(self, max_per_host: int = 2) -> None:
        self._max = max_per_host
        self._semaphores: dict[str, asyncio.Semaphore] = {}

    def get(self, hostname: str) -> asyncio.Semaphore:
        if hostname not in self._semaphores:
            self._semaphores[hostname] = asyncio.Semaphore(self._max)
        return self._semaphores[hostname]


class HttpClient:
    """Async HTTP client with retry, rate limiting, and proxy support."""

    def __init__(
        self,
        timeout: float = 10.0,
        max_retries: int = 2,
        rate_limit: float = 0,
        proxy: str | None = None,
        random_ua: bool = True,
        user_agent: str | None = None,
        per_host_limit: int = 2,
        verify_ssl: bool = False,
    ) -> None:
        self._timeout = timeout
        self._max_retries = max_retries
        self._proxy = proxy
        self._random_ua = random_ua
        self._user_agent = user_agent
        self._per_host = PerHostSemaphore(per_host_limit)
        self._verify_ssl = verify_ssl
        self._rate_limiter = RateLimiter(rate_limit, burst=max(1, int(rate_limit))) if rate_limit > 0 else None

        # Stats
        self.requests_sent = 0
        self.responses_received = 0
        self.errors = 0

    def _headers(self) -> dict[str, str]:
        ua = self._user_agent or (random.choice(USER_AGENTS) if self._random_ua else USER_AGENTS[0])
        return {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }

    def _client_kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "timeout": httpx.Timeout(self._timeout, connect=min(self._timeout, 10.0)),
            "follow_redirects": True,
            "verify": self._verify_ssl,
            "http2": True,
        }
        if self._proxy:
            kwargs["proxy"] = self._proxy
        return kwargs

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """GET request with retry and rate limiting."""
        return await self._request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        """HEAD request."""
        return await self._request("HEAD", url, **kwargs)

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Execute an HTTP request with retry logic."""
        from scoutx.utils.validators import extract_hostname

        hostname = extract_hostname(url)
        host_sem = self._per_host.get(hostname)

        last_exc: Exception | None = None
        for attempt in range(self._max_retries + 1):
            if self._rate_limiter:
                await self._rate_limiter.acquire()

            async with host_sem:
                try:
                    async with httpx.AsyncClient(**self._client_kwargs()) as client:
                        headers = {**self._headers(), **kwargs.pop("headers", {})}
                        self.requests_sent += 1
                        resp = await client.request(method, url, headers=headers, **kwargs)
                        self.responses_received += 1

                        if resp.status_code not in TRANSIENT_STATUS_CODES:
                            return resp

                        # Transient error — retry with backoff
                        last_exc = httpx.HTTPStatusError(
                            f"HTTP {resp.status_code}",
                            request=resp.request,
                            response=resp,
                        )
                        if attempt < self._max_retries:
                            delay = min(2 ** attempt, 8)
                            retry_after = resp.headers.get("retry-after", "")
                            if retry_after:
                                try:
                                    delay = min(float(retry_after), 30)
                                except ValueError:
                                    pass
                            await asyncio.sleep(delay)

                except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError) as exc:
                    self.errors += 1
                    last_exc = exc
                    if attempt < self._max_retries:
                        await asyncio.sleep(2 ** attempt)

        raise last_exc or httpx.ConnectError("Request failed after retries")

    @property
    def stats(self) -> dict[str, int]:
        return {
            "requests_sent": self.requests_sent,
            "responses_received": self.responses_received,
            "errors": self.errors,
        }
