"""Plugin manager — discovers, loads, and manages plugin lifecycle.

Handles both built-in plugins (under scoutx.plugins.builtin) and
external plugins loaded from directories.
"""
from __future__ import annotations

import importlib
import logging
import pkgutil
from pathlib import Path

from scoutx.core.config import ScoutXConfig
from scoutx.plugins.base import ScoutPlugin

logger = logging.getLogger("scoutx.plugins")


class PluginManager:
    """Discovers, loads, and manages plugin lifecycle."""

    def __init__(self, config: ScoutXConfig) -> None:
        self._plugins: dict[str, ScoutPlugin] = {}
        self._config = config

    def discover_builtin(self) -> None:
        """Discover built-in plugins from scoutx.plugins.builtin package."""
        try:
            from scoutx.plugins import builtin as builtin_pkg

            package_path = builtin_pkg.__path__
            for importer, modname, ispkg in pkgutil.iter_modules(package_path):
                if ispkg:
                    try:
                        module = importlib.import_module(f"scoutx.plugins.builtin.{modname}")
                        # Look for a Plugin class or plugin instance
                        plugin_cls = getattr(module, "Plugin", None)
                        if plugin_cls and isinstance(plugin_cls, type) and issubclass(plugin_cls, ScoutPlugin):
                            instance = plugin_cls()
                            self.register(instance)
                            logger.debug("Discovered built-in plugin: %s", instance.meta.name)
                    except Exception as exc:
                        logger.warning("Failed to load built-in plugin %s: %s", modname, exc)
        except ImportError:
            logger.debug("No built-in plugins package found — that's fine for Phase 1")

    def discover_external(self, path: Path) -> None:
        """Discover external plugins from a directory.

        Each subdirectory should contain a ``plugin.py`` with a ``Plugin`` class.
        """
        if not path.exists() or not path.is_dir():
            return

        for child in path.iterdir():
            if not child.is_dir():
                continue
            plugin_file = child / "plugin.py"
            if not plugin_file.exists():
                continue
            try:
                import importlib.util

                spec = importlib.util.spec_from_file_location(
                    f"scoutx_ext_{child.name}",
                    plugin_file,
                )
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)  # type: ignore[union-attr]
                    plugin_cls = getattr(module, "Plugin", None)
                    if plugin_cls and isinstance(plugin_cls, type) and issubclass(plugin_cls, ScoutPlugin):
                        instance = plugin_cls()
                        self.register(instance)
                        logger.info("Loaded external plugin: %s from %s", instance.meta.name, plugin_file)
            except Exception as exc:
                logger.warning("Failed to load external plugin from %s: %s", child, exc)

    def register(self, plugin: ScoutPlugin) -> None:
        """Register a plugin instance."""
        name = plugin.meta.name
        if name in self._plugins:
            logger.warning("Plugin %s already registered — overwriting", name)
        self._plugins[name] = plugin

    def unregister(self, name: str) -> None:
        """Remove a plugin by name."""
        self._plugins.pop(name, None)

    def get(self, name: str) -> ScoutPlugin | None:
        """Get a plugin by name."""
        return self._plugins.get(name)

    def get_all(self) -> list[ScoutPlugin]:
        """Get all registered plugins."""
        return list(self._plugins.values())

    def get_enabled(self) -> list[ScoutPlugin]:
        """Get all enabled plugins."""
        return [p for p in self._plugins.values() if p.enabled]

    def enable(self, name: str) -> None:
        """Enable a plugin by name."""
        plugin = self._plugins.get(name)
        if plugin:
            plugin.enabled = True
        else:
            logger.warning("Plugin %s not found", name)

    def disable(self, name: str) -> None:
        """Disable a plugin by name."""
        plugin = self._plugins.get(name)
        if plugin:
            plugin.enabled = False
        else:
            logger.warning("Plugin %s not found", name)

    def resolve_execution_order(self) -> list[list[ScoutPlugin]]:
        """Topologically sort enabled plugins into concurrent execution phases.

        Uses Kahn's algorithm. Plugins with no unmet dependencies
        run in the same phase for concurrent execution.
        """
        enabled = self.get_enabled()
        if not enabled:
            return []

        plugin_map = {p.meta.name: p for p in enabled}
        in_degree: dict[str, int] = {p.meta.name: 0 for p in enabled}
        dependents: dict[str, list[str]] = {p.meta.name: [] for p in enabled}

        for plugin in enabled:
            for dep in plugin.depends_on:
                if dep in plugin_map:
                    in_degree[plugin.meta.name] += 1
                    dependents[dep].append(plugin.meta.name)

        phases: list[list[ScoutPlugin]] = []
        available = {name for name, degree in in_degree.items() if degree == 0}

        while available:
            phase = [plugin_map[name] for name in sorted(available)]
            phases.append(phase)

            next_available: set[str] = set()
            for name in available:
                for dependent in dependents.get(name, []):
                    in_degree[dependent] -= 1
                    if in_degree[dependent] == 0:
                        next_available.add(dependent)

            available = next_available

        # Handle cycles
        resolved = {p.meta.name for phase in phases for p in phase}
        unresolved = set(plugin_map.keys()) - resolved
        if unresolved:
            logger.warning("Circular dependencies: %s — forcing into final phase", unresolved)
            phases.append([plugin_map[n] for n in sorted(unresolved)])

        return phases
