"""Event bus — async decoupled communication for the entire framework.

Plugins emit events. Notifications consume them. The CLI displays them.
Everyone's happy. Nobody's tightly coupled.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Coroutine

logger = logging.getLogger("scoutx.events")


class EventType(Enum):
    """All event types in the ScoutX lifecycle."""

    # Scan lifecycle
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SCAN_RESUMED = "scan.resumed"

    # Module lifecycle
    MODULE_STARTED = "module.started"
    MODULE_COMPLETED = "module.completed"
    MODULE_FAILED = "module.failed"
    MODULE_SKIPPED = "module.skipped"
    MODULE_TIMEOUT = "module.timeout"

    # Discoveries
    FINDING_DISCOVERED = "finding.discovered"
    SUBDOMAIN_FOUND = "subdomain.found"
    HOST_ALIVE = "host.alive"
    SECRET_DETECTED = "secret.detected"
    VULNERABILITY_FOUND = "vulnerability.found"
    ENDPOINT_FOUND = "endpoint.found"
    PORT_OPEN = "port.open"
    TAKEOVER_POSSIBLE = "takeover.possible"

    # Progress
    PROGRESS_UPDATE = "progress.update"
    PHASE_STARTED = "phase.started"
    PHASE_COMPLETED = "phase.completed"


@dataclass(frozen=True)
class Event:
    """An immutable event emitted by the event bus."""

    type: EventType
    data: dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scan_id: str = ""
    source: str = ""  # which plugin/module emitted it


# Handler type: can be sync or async
EventHandler = Callable[[Event], Any] | Callable[[Event], Coroutine[Any, Any, Any]]


class EventBus:
    """Async event bus for decoupled communication across the framework."""

    def __init__(self) -> None:
        self._handlers: dict[EventType, list[EventHandler]] = {}
        self._global_handlers: list[EventHandler] = []

    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Subscribe a handler to a specific event type."""
        self._handlers.setdefault(event_type, []).append(handler)

    def subscribe_all(self, handler: EventHandler) -> None:
        """Subscribe a handler to ALL event types (for logging, notifications)."""
        self._global_handlers.append(handler)

    def unsubscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Remove a handler from an event type."""
        handlers = self._handlers.get(event_type, [])
        self._handlers[event_type] = [h for h in handlers if h is not handler]

    async def emit(self, event: Event) -> None:
        """Emit an event to all subscribed handlers."""
        handlers = list(self._handlers.get(event.type, [])) + list(self._global_handlers)
        for handler in handlers:
            try:
                result = handler(event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as exc:
                logger.warning("Event handler error for %s: %s", event.type.value, exc)

    def on(self, event_type: EventType) -> Callable:
        """Decorator to subscribe a handler to an event type.

        Usage:
            @event_bus.on(EventType.SUBDOMAIN_FOUND)
            async def handle_subdomain(event: Event):
                ...
        """

        def decorator(func: EventHandler) -> EventHandler:
            self.subscribe(event_type, func)
            return func

        return decorator

    def emit_sync(self, event: Event) -> None:
        """Fire-and-forget emit for non-async contexts."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.emit(event))
        except RuntimeError:
            # No running loop — just run sync handlers
            for handler in list(self._handlers.get(event.type, [])) + list(self._global_handlers):
                try:
                    result = handler(event)
                    if asyncio.iscoroutine(result):
                        pass  # Can't await in sync context — skip async handlers
                except Exception:
                    pass
