"""Notification engine — dispatches alerts to configured channels.

Supports multiple notification backends (Slack, Discord, generic webhook).
Triggers on configurable events: scan_complete, critical_finding, new_subdomain.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Protocol

logger = logging.getLogger("scoutx.notifications.engine")


class Notifier(Protocol):
    """Interface that all notification backends implement."""

    async def send(self, title: str, message: str, color: str = "info",
                   fields: list[dict[str, str]] | None = None) -> bool:
        """Send a notification. Returns True on success."""
        ...


@dataclass
class NotificationEvent:
    """An event that can trigger notifications."""
    event_type: str  # scan_complete, critical_finding, new_subdomain, scan_error
    target: str
    title: str
    message: str
    severity: str = "info"  # info, warning, critical
    fields: list[dict[str, str]] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)


# Severity to color mapping for embeds
SEVERITY_COLORS = {
    "info": "#58a6ff",
    "warning": "#d29922",
    "critical": "#f85149",
    "success": "#3fb950",
}


class NotificationEngine:
    """Dispatch notifications to all configured backends."""

    def __init__(self) -> None:
        self._notifiers: list[Notifier] = []
        self._enabled_events: set[str] = {
            "scan_complete", "critical_finding", "scan_error",
        }

    def add_notifier(self, notifier: Notifier) -> None:
        """Register a notification backend."""
        self._notifiers.append(notifier)

    def set_enabled_events(self, events: set[str]) -> None:
        """Configure which event types trigger notifications."""
        self._enabled_events = events

    @property
    def has_notifiers(self) -> bool:
        return len(self._notifiers) > 0

    async def notify(self, event: NotificationEvent) -> int:
        """Send notification to all backends. Returns count of successful sends."""
        if event.event_type not in self._enabled_events:
            logger.debug("Event %s not in enabled events, skipping", event.event_type)
            return 0

        if not self._notifiers:
            return 0

        color = SEVERITY_COLORS.get(event.severity, SEVERITY_COLORS["info"])

        results = await asyncio.gather(
            *[n.send(event.title, event.message, color, event.fields)
              for n in self._notifiers],
            return_exceptions=True,
        )

        successes = sum(1 for r in results if r is True)
        failures = len(results) - successes

        if failures > 0:
            for i, r in enumerate(results):
                if isinstance(r, Exception):
                    logger.warning("Notifier %d failed: %s", i, r)

        logger.info(
            "Notification dispatched: %s (%d/%d succeeded)",
            event.event_type, successes, len(results),
        )
        return successes

    # ── Convenience methods for common events ──────────────────────────

    async def scan_complete(self, target: str, duration: float,
                            findings: dict[str, int]) -> int:
        """Notify that a scan completed."""
        fields = [
            {"name": "Target", "value": target},
            {"name": "Duration", "value": f"{duration:.1f}s"},
        ]
        for k, v in findings.items():
            if v > 0:
                fields.append({"name": k, "value": str(v)})

        total_findings = sum(findings.values())
        severity = "critical" if findings.get("secrets", 0) > 0 else "success"

        return await self.notify(NotificationEvent(
            event_type="scan_complete",
            target=target,
            title=f"ScoutX Scan Complete: {target}",
            message=f"Scan finished in {duration:.1f}s with {total_findings} total findings.",
            severity=severity,
            fields=fields,
        ))

    async def critical_finding(self, target: str, finding_type: str,
                               details: str) -> int:
        """Notify about a critical finding."""
        return await self.notify(NotificationEvent(
            event_type="critical_finding",
            target=target,
            title=f"CRITICAL: {finding_type} on {target}",
            message=details,
            severity="critical",
            fields=[
                {"name": "Target", "value": target},
                {"name": "Type", "value": finding_type},
            ],
        ))

    async def scan_error(self, target: str, error_msg: str) -> int:
        """Notify about a scan error."""
        return await self.notify(NotificationEvent(
            event_type="scan_error",
            target=target,
            title=f"Scan Error: {target}",
            message=error_msg,
            severity="warning",
        ))

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> NotificationEngine:
        """Build engine from ScoutX config dict.

        Expected config structure:
            notifications:
              slack:
                webhook_url: "https://hooks.slack.com/..."
                channel: "#recon"
              discord:
                webhook_url: "https://discord.com/api/webhooks/..."
              webhook:
                url: "https://your-server.com/api/notify"
                headers:
                  Authorization: "Bearer token"
              events:
                - scan_complete
                - critical_finding
                - scan_error
        """
        from scoutx.notifications.discord import DiscordNotifier
        from scoutx.notifications.slack import SlackNotifier
        from scoutx.notifications.webhook import WebhookNotifier

        engine = cls()

        notif_config = config.get("notifications", {})
        if not notif_config:
            return engine

        # Slack
        slack_url = notif_config.get("slack_webhook")
        if slack_url:
            engine.add_notifier(SlackNotifier(
                webhook_url=slack_url,
                channel=notif_config.get("slack_channel"),
                username=notif_config.get("slack_username", "ScoutX"),
            ))

        # Discord
        discord_url = notif_config.get("discord_webhook")
        if discord_url:
            engine.add_notifier(DiscordNotifier(
                webhook_url=discord_url,
            ))

        # Generic webhook
        webhook_url = notif_config.get("webhook_url")
        if webhook_url:
            engine.add_notifier(WebhookNotifier(
                url=webhook_url,
                headers=notif_config.get("webhook_headers", {}),
                method=notif_config.get("webhook_method", "POST"),
            ))

        # Events filter
        events = set()
        if notif_config.get("on_complete"):
            events.add("scan_complete")
        if notif_config.get("on_critical"):
            events.add("critical_finding")
        
        # Always allow scan_error if any notifications are configured
        if events or engine.has_notifiers:
            events.add("scan_error")

        if events:
            engine.set_enabled_events(events)

        logger.info(
            "Notification engine configured: %d backends, %d event types",
            len(engine._notifiers), len(engine._enabled_events),
        )
        return engine
