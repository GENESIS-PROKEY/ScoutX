"""Methodology Runner — maps the 10-phase workflow to ScoutX plugins and tools.

Validates that required external tools are available for each phase,
and reports which methodology phases can run with the current tool setup.
"""
from __future__ import annotations

import logging
from typing import Any

from scoutx.methodology.phases import (
    METHODOLOGY_PHASES,
    MethodologyPhase,
    get_passive_phases,
)
from scoutx.tools.registry import check_tool

logger = logging.getLogger("scoutx.methodology.runner")


class MethodologyRunner:
    """Maps methodology phases to available ScoutX plugins and tools."""

    def __init__(self, profile: str = "balanced") -> None:
        self._profile = profile

    def check_readiness(self) -> dict[str, Any]:
        """Check which methodology phases can run with current tool setup."""
        report: dict[str, Any] = {
            "profile": self._profile,
            "phases": [],
            "total_phases": len(METHODOLOGY_PHASES),
            "ready_phases": 0,
            "partial_phases": 0,
            "blocked_phases": 0,
        }

        include_active = self._profile == "aggressive"
        phases = METHODOLOGY_PHASES if include_active else get_passive_phases()

        for phase in phases:
            phase_status = self._check_phase(phase)
            report["phases"].append(phase_status)

            if phase_status["status"] == "ready":
                report["ready_phases"] += 1
            elif phase_status["status"] == "partial":
                report["partial_phases"] += 1
            else:
                report["blocked_phases"] += 1

        return report

    def _check_phase(self, phase: MethodologyPhase) -> dict[str, Any]:
        """Check a single phase for tool availability."""
        available: list[str] = []
        missing: list[str] = []

        for tool_name in phase.external_tools:
            if check_tool(tool_name):
                available.append(tool_name)
            else:
                missing.append(tool_name)

        total = len(phase.external_tools)
        avail_count = len(available)

        if total == 0 or avail_count == total:
            status = "ready"
        elif avail_count > 0:
            status = "partial"
        else:
            status = "degraded"

        return {
            "id": phase.id,
            "name": phase.name,
            "plugin": phase.scoutx_plugin,
            "active": phase.active,
            "status": status,
            "tools_available": available,
            "tools_missing": missing,
            "coverage": f"{avail_count}/{total}",
        }

    def get_install_recommendations(self) -> list[dict[str, str]]:
        """Get tool install recommendations ordered by impact."""
        recs: list[dict[str, str]] = []
        seen: set[str] = set()

        for phase in METHODOLOGY_PHASES:
            for tool_name in phase.external_tools:
                if tool_name not in seen and not check_tool(tool_name):
                    seen.add(tool_name)
                    recs.append({
                        "tool": tool_name,
                        "phase": phase.name,
                        "impact": "core" if phase.order <= 2 else "extended",
                    })

        # Sort: core tools first
        recs.sort(key=lambda r: 0 if r["impact"] == "core" else 1)
        return recs
