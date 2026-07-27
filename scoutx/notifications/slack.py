"""Slack webhook notifier — rich message embeds with attachments."""
from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger("scoutx.notifications.slack")


class SlackNotifier:
    """Send notifications via Slack Incoming Webhooks."""

    def __init__(
        self,
        webhook_url: str,
        channel: str | None = None,
        username: str = "ScoutX",
        icon_emoji: str = ":mag:",
    ) -> None:
        self._webhook_url = webhook_url
        self._channel = channel
        self._username = username
        self._icon_emoji = icon_emoji

    async def send(
        self,
        title: str,
        message: str,
        color: str = "#58a6ff",
        fields: list[dict[str, str]] | None = None,
    ) -> bool:
        """Send a Slack message via webhook."""
        attachment: dict[str, Any] = {
            "color": color,
            "title": title,
            "text": message,
            "footer": "ScoutX Recon Framework",
            "ts": __import__("time").time(),
        }

        if fields:
            attachment["fields"] = [
                {"title": f["name"], "value": f["value"], "short": True}
                for f in fields
            ]

        payload: dict[str, Any] = {
            "username": self._username,
            "icon_emoji": self._icon_emoji,
            "attachments": [attachment],
        }

        if self._channel:
            payload["channel"] = self._channel

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(self._webhook_url, json=payload)
                if resp.status_code == 200:
                    logger.info("Slack notification sent: %s", title)
                    return True
                else:
                    logger.warning(
                        "Slack webhook returned %d: %s",
                        resp.status_code, resp.text[:200],
                    )
                    return False
        except Exception as exc:
            logger.error("Slack notification failed: %s", exc)
            return False
