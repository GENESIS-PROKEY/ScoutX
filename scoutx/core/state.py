"""Scan state — persistent checkpointing for resume capability.

Every module's status is tracked so interrupted scans can pick up where they left off.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class ScanState:
    """Persistent scan state for resume capability."""

    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    target: str = ""
    profile: str = "balanced"
    started_at: datetime = field(default_factory=_now)
    completed_modules: set[str] = field(default_factory=set)
    failed_modules: dict[str, str] = field(default_factory=dict)  # module → error
    skipped_modules: dict[str, str] = field(default_factory=dict)  # module → reason
    module_durations: dict[str, float] = field(default_factory=dict)
    module_metadata: dict[str, Any] = field(default_factory=dict)

    def is_completed(self, module: str) -> bool:
        """Check if a module has already completed."""
        return module in self.completed_modules

    def is_failed(self, module: str) -> bool:
        return module in self.failed_modules

    def mark_completed(self, module: str, duration: float, metadata: dict[str, Any] | None = None) -> None:
        """Mark a module as completed."""
        self.completed_modules.add(module)
        self.failed_modules.pop(module, None)
        self.skipped_modules.pop(module, None)
        self.module_durations[module] = round(duration, 3)
        if metadata:
            self.module_metadata[module] = metadata

    def mark_failed(self, module: str, error: str, duration: float) -> None:
        """Mark a module as failed."""
        self.failed_modules[module] = error
        self.module_durations[module] = round(duration, 3)

    def mark_skipped(self, module: str, reason: str) -> None:
        """Mark a module as skipped."""
        self.skipped_modules[module] = reason

    def save(self, path: Path) -> None:
        """Persist state to JSON file (atomic write)."""
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "scan_id": self.scan_id,
            "target": self.target,
            "profile": self.profile,
            "started_at": self.started_at.isoformat(),
            "completed_modules": sorted(self.completed_modules),
            "failed_modules": self.failed_modules,
            "skipped_modules": self.skipped_modules,
            "module_durations": self.module_durations,
            "module_metadata": self.module_metadata,
        }
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        tmp.replace(path)

    @classmethod
    def load(cls, path: Path) -> ScanState:
        """Load state from JSON file."""
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:
            return cls()
        if not isinstance(data, dict):
            return cls()
        state = cls(
            scan_id=data.get("scan_id", uuid.uuid4().hex[:12]),
            target=data.get("target", ""),
            profile=data.get("profile", "balanced"),
            completed_modules=set(data.get("completed_modules", [])),
            failed_modules=data.get("failed_modules", {}),
            skipped_modules=data.get("skipped_modules", {}),
            module_durations=data.get("module_durations", {}),
            module_metadata=data.get("module_metadata", {}),
        )
        if started := data.get("started_at"):
            try:
                state.started_at = datetime.fromisoformat(started)
            except (ValueError, TypeError):
                pass
        return state

    @property
    def status(self) -> str:
        """Overall scan status."""
        if self.failed_modules and not self.completed_modules:
            return "failed"
        if self.failed_modules:
            return "partial"
        return "running"
