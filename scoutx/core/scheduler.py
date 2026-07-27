"""Scan scheduling module."""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger("scoutx.core.scheduler")


class ScanScheduler:
    """Manages one-time and recurring scan schedules."""

    def __init__(self, state_file: Path, engine: Any) -> None:
        self.state_file = state_file
        self.engine = engine
        self._tasks: dict[str, asyncio.Task] = {}
        self._schedules: dict[str, dict[str, Any]] = {}
        self._load_state()

    def _load_state(self) -> None:
        if self.state_file.exists():
            try:
                content = self.state_file.read_text(encoding="utf-8")
                self._schedules = json.loads(content)
            except Exception as exc:
                logger.error("Failed to load schedules: %s", exc)
                self._schedules = {}

    def _save_state(self) -> None:
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            self.state_file.write_text(json.dumps(self._schedules, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.error("Failed to save schedules: %s", exc)

    def schedule_once(self, target: str, delay_seconds: int, profile: str) -> str:
        """Schedule a scan to run once after a delay."""
        schedule_id = uuid.uuid4().hex[:8]
        self._schedules[schedule_id] = {
            "target": target,
            "profile": profile,
            "type": "once",
            "delay_seconds": delay_seconds,
        }
        self._save_state()

        async def _run_once() -> None:
            try:
                await asyncio.sleep(delay_seconds)
                logger.info("Executing scheduled scan (once) for %s", target)
                await self.engine.run(target, profile=profile)
            finally:
                self._schedules.pop(schedule_id, None)
                self._tasks.pop(schedule_id, None)
                self._save_state()

        task = asyncio.create_task(_run_once())
        self._tasks[schedule_id] = task
        return schedule_id

    def schedule_recurring(self, target: str, interval_hours: int, profile: str) -> str:
        """Schedule a scan to run repeatedly at a given interval."""
        schedule_id = uuid.uuid4().hex[:8]
        self._schedules[schedule_id] = {
            "target": target,
            "profile": profile,
            "type": "recurring",
            "interval_hours": interval_hours,
        }
        self._save_state()

        async def _run_recurring() -> None:
            while True:
                await asyncio.sleep(interval_hours * 3600)
                logger.info("Executing scheduled scan (recurring) for %s", target)
                try:
                    await self.engine.run(target, profile=profile)
                except Exception as exc:
                    logger.error("Recurring scan for %s failed: %s", target, exc)

        task = asyncio.create_task(_run_recurring())
        self._tasks[schedule_id] = task
        return schedule_id

    def list_scheduled(self) -> list[dict[str, Any]]:
        """List all active scheduled scans."""
        return [{"id": k, **v} for k, v in self._schedules.items()]

    def cancel(self, schedule_id: str) -> bool:
        """Cancel a scheduled scan."""
        canceled = False
        if schedule_id in self._tasks:
            self._tasks[schedule_id].cancel()
            self._tasks.pop(schedule_id)
            canceled = True
        
        if schedule_id in self._schedules:
            self._schedules.pop(schedule_id)
            self._save_state()
            canceled = True
            
        return canceled
