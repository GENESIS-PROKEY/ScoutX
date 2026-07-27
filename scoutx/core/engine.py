"""Scan engine — the beating heart of ScoutX.

Orchestrates the full async pipeline with phase-based concurrent execution.
Plugins declare their dependencies; the engine resolves execution order
using topological sort and runs independent plugins concurrently.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scoutx.cli.ui import error, format_duration, info, print_module_header, skip, success, warn
from scoutx.core.config import ScoutXConfig
from scoutx.core.events import Event, EventBus, EventType
from scoutx.core.scope import Scope
from scoutx.core.state import ScanState
from scoutx.database.repository import Repository
from scoutx.plugins.base import PluginResult, ScoutPlugin

logger = logging.getLogger("scoutx.engine")


@dataclass
class ScanContext:
    """Shared context passed to all plugins during a scan."""

    scan_id: str
    target: str
    scope: Scope
    config: ScoutXConfig
    output_dir: Path
    profile: str
    state: ScanState
    results: dict[str, PluginResult] = field(default_factory=dict)
    db: Repository | None = None
    events: EventBus = field(default_factory=EventBus)
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("scoutx.scan"))

    def result_data(self, plugin_name: str) -> dict[str, Any]:
        """Get result data from a completed plugin.

        First checks in-memory results, then falls back to reading
        the plugin's JSON output file from the output directory.
        """
        result = self.results.get(plugin_name)
        if result and result.data:
            return result.data

        # Fall back to reading from the output directory JSON
        from scoutx.utils.io import read_json
        json_path = self.output_dir / plugin_name / f"{plugin_name}.json"
        if json_path.exists():
            return read_json(json_path, {})

        # Some plugins use a different name (e.g., probe -> probe.json)
        alt_names = {"ssl_analysis": "ssl"}
        alt = alt_names.get(plugin_name, plugin_name)
        alt_path = self.output_dir / alt / f"{alt}.json"
        if alt_path.exists():
            return read_json(alt_path, {})

        return {}


@dataclass
class ScanResult:
    """Final result of a complete scan run."""

    scan_id: str
    target: str
    profile: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float
    plugin_results: dict[str, PluginResult]
    status: str  # completed, partial, failed
    phases_executed: int = 0


class ScanEngine:
    """Async scan orchestration engine with phase-based concurrent execution."""

    def __init__(
        self,
        config: ScoutXConfig,
        scope: Scope,
        plugin_manager: Any,  # avoid circular import
        db: Repository,
        event_bus: EventBus,
    ) -> None:
        self._config = config
        self._scope = scope
        self._plugin_manager = plugin_manager
        self._db = db
        self._event_bus = event_bus

    async def run(
        self,
        target: str,
        profile: str = "balanced",
        resume: bool = False,
        output_dir: Path | None = None,
    ) -> ScanResult:
        """Execute the full scan pipeline."""
        scan_id = uuid.uuid4().hex[:12]
        out = output_dir or self._config.output_dir
        target_dir = out / target
        target_dir.mkdir(parents=True, exist_ok=True)

        state_path = target_dir / "scan_state.json"
        state = ScanState.load(state_path) if resume else ScanState(
            scan_id=scan_id,
            target=target,
            profile=profile,
        )

        if resume:
            scan_id = state.scan_id
            info(f"Resuming scan {scan_id}")
            await self._event_bus.emit(Event(
                type=EventType.SCAN_RESUMED,
                data={"target": target, "scan_id": scan_id},
                scan_id=scan_id,
            ))

        context = ScanContext(
            scan_id=scan_id,
            target=target,
            scope=self._scope,
            config=self._config,
            output_dir=target_dir,
            profile=profile,
            state=state,
            db=self._db,
            events=self._event_bus,
        )

        # Initialize database
        try:
            await self._db.initialize()
            await self._db.create_scan(scan_id, target, profile, self._config.raw)
        except Exception as exc:
            logger.warning("Database init failed (continuing without persistence): %s", exc)

        # Emit scan started
        await self._event_bus.emit(Event(
            type=EventType.SCAN_STARTED,
            data={"target": target, "profile": profile},
            scan_id=scan_id,
        ))

        started_at = datetime.now(timezone.utc)
        start_time = time.perf_counter()

        # Resolve execution plan
        enabled_plugins = self._plugin_manager.get_enabled()
        phases = self._resolve_execution_plan(enabled_plugins)

        info(f"Execution plan: {len(phases)} phases, {len(enabled_plugins)} plugins")
        for i, phase in enumerate(phases, 1):
            names = [p.meta.name for p in phase]
            info(f"  Phase {i}: {', '.join(names)}")

        # Execute phases
        all_results: dict[str, PluginResult] = {}
        phases_executed = 0
        has_failures = False

        for phase_idx, phase in enumerate(phases, 1):
            await self._event_bus.emit(Event(
                type=EventType.PHASE_STARTED,
                data={"phase": phase_idx, "plugins": [p.meta.name for p in phase]},
                scan_id=scan_id,
            ))

            phase_results = await self._execute_phase(phase, context)
            all_results.update(phase_results)
            context.results.update(phase_results)
            phases_executed = phase_idx

            # Save state after each phase
            state.save(state_path)

            # Check for failures
            for name, result in phase_results.items():
                if result.status == "failed":
                    has_failures = True

            await self._event_bus.emit(Event(
                type=EventType.PHASE_COMPLETED,
                data={"phase": phase_idx, "results": {k: v.status for k, v in phase_results.items()}},
                scan_id=scan_id,
            ))

        duration = time.perf_counter() - start_time
        completed_at = datetime.now(timezone.utc)

        # Determine overall status — skipped plugins don't count as failures
        completed_count = sum(1 for r in all_results.values() if r.status == "completed")
        skipped_count = sum(1 for r in all_results.values() if r.status == "skipped")
        failed_count = sum(1 for r in all_results.values() if r.status == "failed")

        if failed_count == 0:
            status = "completed"
        elif completed_count > 0:
            status = "partial"
        else:
            status = "failed"

        # Update database
        try:
            await self._db.update_scan(scan_id, status=status, completed_at=completed_at, duration_seconds=round(duration, 2))
        except Exception:
            pass

        # Emit completion
        event_type = EventType.SCAN_COMPLETED if status == "completed" else EventType.SCAN_FAILED
        await self._event_bus.emit(Event(
            type=event_type,
            data={"target": target, "duration": duration, "status": status},
            scan_id=scan_id,
        ))

        # Fire notifications if configured
        try:
            from scoutx.notifications.engine import NotificationEngine
            notif_engine = NotificationEngine.from_config(self._config._data)
            if notif_engine.has_notifiers:
                findings = {
                    "subdomains": len(all_results.get("subdomains", PluginResult.skipped("")).data.get("subdomains", [])) if "subdomains" in all_results else 0,
                    "alive_hosts": all_results.get("probe", PluginResult.skipped("")).data.get("alive", 0) if "probe" in all_results else 0,
                    "open_ports": all_results.get("ports", PluginResult.skipped("")).data.get("total_open", 0) if "ports" in all_results else 0,
                    "secrets": all_results.get("secrets", PluginResult.skipped("")).data.get("total", 0) if "secrets" in all_results else 0,
                    "endpoints": len(all_results.get("endpoints", PluginResult.skipped("")).data.get("endpoints", [])) if "endpoints" in all_results else 0,
                }
                await notif_engine.scan_complete(target, duration, findings)
        except Exception as notif_exc:
            logger.debug("Notification dispatch failed: %s", notif_exc)

        return ScanResult(
            scan_id=scan_id,
            target=target,
            profile=profile,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=round(duration, 2),
            plugin_results=all_results,
            status=status,
            phases_executed=phases_executed,
        )

    def _resolve_execution_plan(self, plugins: list[ScoutPlugin]) -> list[list[ScoutPlugin]]:
        """Topologically sort plugins into concurrent execution phases.

        Uses Kahn's algorithm. Plugins with no unmet dependencies run
        in the same phase (concurrently).
        """
        if not plugins:
            return []

        # Build adjacency list
        plugin_map = {p.meta.name: p for p in plugins}
        in_degree: dict[str, int] = {p.meta.name: 0 for p in plugins}
        dependents: dict[str, list[str]] = {p.meta.name: [] for p in plugins}

        for plugin in plugins:
            for dep in plugin.depends_on:
                if dep in plugin_map:
                    in_degree[plugin.meta.name] += 1
                    dependents[dep].append(plugin.meta.name)

        # Kahn's algorithm — group by levels for concurrent phases
        phases: list[list[ScoutPlugin]] = []
        available = {name for name, degree in in_degree.items() if degree == 0}

        while available:
            # All available plugins can run concurrently
            phase = [plugin_map[name] for name in sorted(available)]
            phases.append(phase)

            next_available: set[str] = set()
            for name in available:
                for dependent in dependents[name]:
                    in_degree[dependent] -= 1
                    if in_degree[dependent] == 0:
                        next_available.add(dependent)

            available = next_available

        # Detect cycles (shouldn't happen but let's be safe)
        resolved = {p.meta.name for phase in phases for p in phase}
        unresolved = set(plugin_map.keys()) - resolved
        if unresolved:
            logger.warning("Circular dependencies detected in plugins: %s", unresolved)
            # Force remaining into final phase
            phases.append([plugin_map[name] for name in sorted(unresolved)])

        return phases

    async def _execute_phase(
        self,
        phase: list[ScoutPlugin],
        context: ScanContext,
    ) -> dict[str, PluginResult]:
        """Execute all plugins in a phase concurrently."""
        tasks = [
            self._execute_plugin(plugin, context)
            for plugin in phase
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        phase_results: dict[str, PluginResult] = {}
        for plugin, result in zip(phase, results):
            name = plugin.meta.name
            if isinstance(result, Exception):
                error_msg = str(result)
                logger.exception("Plugin %s raised: %s", name, error_msg)
                phase_results[name] = PluginResult(status="failed", reason=error_msg)
                context.state.mark_failed(name, error_msg, 0.0)
            else:
                phase_results[name] = result

        return phase_results

    async def _execute_plugin(
        self,
        plugin: ScoutPlugin,
        context: ScanContext,
    ) -> PluginResult:
        """Execute a single plugin with error handling, timing, and state tracking."""
        name = plugin.meta.name

        # Skip if already completed (resume mode)
        if context.state.is_completed(name):
            skip(f"Skipping completed module: {name}")
            return PluginResult(status="skipped", reason="Already completed (resume)")

        # Check dependencies
        if not plugin.validate_dependencies(context.state.completed_modules):
            missing = [d for d in plugin.depends_on if d not in context.state.completed_modules]
            reason = f"Missing dependencies: {', '.join(missing)}"
            warn(f"{name}: {reason}")
            context.state.mark_skipped(name, reason)
            return PluginResult(status="skipped", reason=reason)

        print_module_header(name, context.target)
        await context.events.emit(Event(
            type=EventType.MODULE_STARTED,
            data={"module": name},
            scan_id=context.scan_id,
            source=name,
        ))

        start = time.perf_counter()
        try:
            result = await asyncio.wait_for(
                plugin.run(context),
                timeout=context.config.get("timeouts.module", 600),
            )
            duration = time.perf_counter() - start
            result.duration_seconds = duration

            if result.status == "completed":
                context.state.mark_completed(name, duration)
                success(f"Completed {name} in {format_duration(duration)}")
            elif result.status == "skipped":
                context.state.mark_skipped(name, result.reason)
                skip(f"Skipped {name}: {result.reason}")
            else:
                context.state.mark_failed(name, result.reason, duration)
                warn(f"Failed {name}: {result.reason}")

            # Track in database
            try:
                if context.db:
                    await context.db.track_module(
                        context.scan_id, name, result.status,
                        duration_seconds=duration,
                        findings_count=result.findings_count,
                        error_message=result.reason if result.status == "failed" else None,
                    )
            except Exception:
                pass

            event_type = {
                "completed": EventType.MODULE_COMPLETED,
                "failed": EventType.MODULE_FAILED,
                "skipped": EventType.MODULE_SKIPPED,
            }.get(result.status, EventType.MODULE_COMPLETED)

            await context.events.emit(Event(
                type=event_type,
                data={"module": name, "duration": duration, "status": result.status},
                scan_id=context.scan_id,
                source=name,
            ))

            return result

        except asyncio.TimeoutError:
            duration = time.perf_counter() - start
            context.state.mark_failed(name, "Timeout", duration)
            warn(f"{name} timed out after {format_duration(duration)}")
            await context.events.emit(Event(
                type=EventType.MODULE_TIMEOUT,
                data={"module": name, "duration": duration},
                scan_id=context.scan_id,
                source=name,
            ))
            return PluginResult(status="timeout", reason="Module timed out", duration_seconds=duration)

        except Exception as exc:
            duration = time.perf_counter() - start
            error_msg = str(exc)
            logger.exception("Plugin %s crashed: %s", name, error_msg)
            context.state.mark_failed(name, error_msg, duration)
            error(f"{name} failed: {error_msg}")
            return PluginResult(status="failed", reason=error_msg, duration_seconds=duration)
