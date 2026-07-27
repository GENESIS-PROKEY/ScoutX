"""ScoutX Programmatic API.

Provides a clean interface for integrating ScoutX into other Python applications.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Optional

from scoutx.core.config import ScoutXConfig
from scoutx.core.engine import ScanEngine, ScanResult
from scoutx.core.events import EventBus
from scoutx.core.scope import Scope
from scoutx.database.repository import Repository
from scoutx.plugins.manager import PluginManager


class ScoutX:
    """Main API for running ScoutX programmatically."""

    def __init__(self, profile: str = "balanced", config_overrides: Optional[dict[str, Any]] = None) -> None:
        self.profile = profile
        overrides = config_overrides or {}
        overrides["scan_profile"] = profile
        self.config = ScoutXConfig(overrides=overrides)
        
        self.plugin_manager = PluginManager(self.config)
        self.plugin_manager.discover_builtin()
        
        db_path = self.config.database_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db = Repository(db_path)
        
        self.event_bus = EventBus()

    async def scan(self, target: str, output_dir: Optional[str] = None) -> ScanResult:
        """Run a full scan on the target."""
        scope = Scope.from_target(target)
        out_path = Path(output_dir) if output_dir else self.config.output_dir
        
        engine = ScanEngine(
            config=self.config,
            scope=scope,
            plugin_manager=self.plugin_manager,
            db=self.db,
            event_bus=self.event_bus,
        )
        
        result = await engine.run(
            target=target,
            profile=self.profile,
            resume=False,
            output_dir=out_path,
        )
        return result

    async def scan_plugins(self, target: str, plugins: list[str], output_dir: Optional[str] = None) -> ScanResult:
        """Run a scan with only specific plugins enabled."""
        scope = Scope.from_target(target)
        out_path = Path(output_dir) if output_dir else self.config.output_dir
        
        # Disable all plugins first, then enable the requested ones
        for plugin in self.plugin_manager.get_all():
            self.plugin_manager.disable(plugin.meta.name)
            
        for plugin_name in plugins:
            self.plugin_manager.enable(plugin_name)
            
        engine = ScanEngine(
            config=self.config,
            scope=scope,
            plugin_manager=self.plugin_manager,
            db=self.db,
            event_bus=self.event_bus,
        )
        
        result = await engine.run(
            target=target,
            profile=self.profile,
            resume=False,
            output_dir=out_path,
        )
        return result

    def list_plugins(self) -> list[dict[str, Any]]:
        """List all available plugins and their metadata."""
        return [
            {
                "name": p.meta.name,
                "description": p.meta.description,
                "version": p.meta.version,
                "author": p.meta.author,
                "enabled": p.enabled,
                "depends_on": p.depends_on,
            }
            for p in self.plugin_manager.get_all()
        ]
