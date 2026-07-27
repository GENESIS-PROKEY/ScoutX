"""Plugin base class — the contract every ScoutX scanner must fulfil.

If you're writing a plugin, this is your bible. Inherit ScoutPlugin,
implement run() and schema(), declare your dependencies. Done.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scoutx.core.engine import ScanContext


@dataclass
class PluginMeta:
    """Plugin metadata — describes what a plugin is."""

    name: str
    description: str
    version: str = "0.1.0"
    author: str = "ScoutX"
    tags: list[str] = field(default_factory=list)


@dataclass
class PluginResult:
    """Result returned by a plugin after execution."""

    status: str = "completed"  # completed, skipped, failed, timeout, partial
    reason: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    findings_count: int = 0
    duration_seconds: float = 0.0
    artifacts: list[Path] = field(default_factory=list)

    @classmethod
    def completed(cls, data: dict[str, Any] | None = None, findings_count: int = 0, artifacts: list[Path] | None = None) -> PluginResult:
        return cls(status="completed", data=data or {}, findings_count=findings_count, artifacts=artifacts or [])

    @classmethod
    def skipped(cls, reason: str) -> PluginResult:
        return cls(status="skipped", reason=reason)

    @classmethod
    def failed(cls, reason: str) -> PluginResult:
        return cls(status="failed", reason=reason)


@dataclass
class ResultSchema:
    """Describes the output format of a plugin for validation and reporting."""

    fields: dict[str, type] = field(default_factory=dict)
    description: str = ""


class ScoutPlugin(ABC):
    """Base class for all ScoutX scanner plugins.

    To create a plugin:
        1. Inherit from ScoutPlugin
        2. Set ``meta`` with your plugin metadata
        3. Set ``depends_on`` if you need output from other plugins
        4. Implement ``run(context)`` — do your thing, return a PluginResult
        5. Implement ``schema()`` — describe your output format
    """

    meta: PluginMeta
    depends_on: list[str] = []
    concurrent_with: list[str] = []
    enabled: bool = True

    @abstractmethod
    async def run(self, context: ScanContext) -> PluginResult:
        """Execute the plugin's scanning logic.

        Args:
            context: Shared scan context with config, scope, prior results, etc.

        Returns:
            PluginResult describing what happened.
        """
        ...

    @abstractmethod
    def schema(self) -> ResultSchema:
        """Describe the plugin's output format."""
        ...

    def validate_dependencies(self, completed: set[str]) -> bool:
        """Check that all required dependencies have completed."""
        return all(dep in completed for dep in self.depends_on)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.meta.name!r} enabled={self.enabled}>"
