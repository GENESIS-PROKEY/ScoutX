"""Generic HTTP webhook notifier — works with any REST endpoint."""
from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger("scoutx.notifications.webhook")


class WebhookNotifier:
    """Send notifications to any HTTP endpoint."""

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        method: str = "POST",
    ) -> None:
        self._url = url
        self._headers = headers or {}
        self._method = method.upper()

    async def send(
        self,
        title: str,
        message: str,
        color: str = "#58a6ff",
        fields: list[dict[str, str]] | None = None,
    ) -> bool:
        """Send notification as JSON payload."""
        payload: dict[str, Any] = {
            "source": "scoutx",
            "title": title,
            "message": message,
            "severity_color": color,
        }

        if fields:
            payload["fields"] = {f["name"]: f["value"] for f in fields}

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                if self._method == "POST":
                    resp = await client.post(
                        self._url, json=payload, headers=self._headers,
                    )
                elif self._method == "PUT":
                    resp = await client.put(
                        self._url, json=payload, headers=self._headers,
                    )
                else:
                    logger.error("Unsupported webhook method: %s", self._method)
                    return False

                if 200 <= resp.status_code < 300:
                    logger.info("Webhook notification sent: %s", title)
                    return True
                else:
                    logger.warning(
                        "Webhook returned %d: %s",
                        resp.status_code, resp.text[:200],
                    )
                    return False
        except Exception as exc:
            logger.error("Webhook notification failed: %s", exc)
            return False
