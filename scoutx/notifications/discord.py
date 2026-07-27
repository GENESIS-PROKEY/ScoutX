"""Discord webhook notifier — rich embed messages."""
from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger("scoutx.notifications.discord")


class DiscordNotifier:
    """Send notifications via Discord Webhooks with rich embeds."""

    def __init__(self, webhook_url: str) -> None:
        self._webhook_url = webhook_url

    async def send(
        self,
        title: str,
        message: str,
        color: str = "#58a6ff",
        fields: list[dict[str, str]] | None = None,
    ) -> bool:
        """Send a Discord embed message."""
        # Discord expects color as integer
        color_int = int(color.lstrip("#"), 16) if color.startswith("#") else 0x58A6FF

        embed: dict[str, Any] = {
            "title": title,
            "description": message,
            "color": color_int,
            "footer": {"text": "ScoutX Recon Framework"},
        }

        if fields:
            embed["fields"] = [
                {"name": f["name"], "value": f["value"], "inline": True}
                for f in fields
            ]

        payload = {
            "username": "ScoutX",
            "embeds": [embed],
        }

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(self._webhook_url, json=payload)
                if resp.status_code in (200, 204):
                    logger.info("Discord notification sent: %s", title)
                    return True
                else:
                    logger.warning(
                        "Discord webhook returned %d: %s",
                        resp.status_code, resp.text[:200],
                    )
                    return False
        except Exception as exc:
            logger.error("Discord notification failed: %s", exc)
            return False
