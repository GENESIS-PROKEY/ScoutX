"""Attack Chain Generation Plugin — the final analysis phase.

Runs AFTER intelligence. Consumes ALL prior plugin results, correlates
findings across the attack surface, and generates step-by-step
exploitation playbooks that a penetration tester can follow manually.

This is ScoutX's crown jewel.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin
from scoutx.utils.io import write_json

if TYPE_CHECKING:
    from scoutx.core.engine import ScanContext

logger = logging.getLogger("scoutx.plugins.attack_chains")


class Plugin(ScoutPlugin):
    """Attack Chain Engine — generates exploitation playbooks from recon data."""

    meta = PluginMeta(
        name="attack_chains",
        description="Generates step-by-step attack chain playbooks from scan findings",
        version="0.1.0",
        author="ScoutX",
        tags=["analysis", "chains", "exploitation", "playbook"],
    )
    depends_on: list[str] = ["intelligence"]
    concurrent_with: list[str] = []

    async def run(self, context: ScanContext) -> PluginResult:
        """Analyze all scan data and generate attack chains."""
        from scoutx.chains.engine import AttackChainEngine
        from scoutx.chains.reporter import ChainReporter
        from scoutx.cli.ui import info, success

        output_dir = context.output_dir / "attack_chains"
        output_dir.mkdir(parents=True, exist_ok=True)

        info("Analyzing attack surface for exploitation chains...")

        # Run the engine
        engine = AttackChainEngine()
        report = engine.analyze(context)

        # Write reports in all formats
        reporter = ChainReporter(report)
        report_paths = reporter.write_all(output_dir)

        # Also save raw data
        write_json(output_dir / "chain_data.json", report.to_dict())

        # Summary
        sev = report.severity_counts()
        total = len(report.chains)
        applicable = len(report.applicable_checks)
        checklist_total = len(report.checklist)

        if total > 0:
            crit = sev.get("critical", 0)
            high = sev.get("high", 0)
            if crit > 0:
                success(
                    f"Generated {total} attack chains "
                    f"(C:{crit} H:{high} M:{sev.get('medium', 0)} L:{sev.get('low', 0)})"
                )
            else:
                success(f"Generated {total} attack chains ({high} high, {sev.get('medium', 0)} medium)")
        else:
            info("No exploitable attack chains detected")

        info(f"Vulnerability checklist: {applicable}/{checklist_total} checks applicable")

        return PluginResult.completed(
            data=report.to_dict(),
            findings_count=total,
            artifacts=[p for p in report_paths],
        )

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={
                "total_chains": int,
                "severity_breakdown": dict,
                "chains": list,
                "checklist_applicable": int,
                "checklist_total": int,
            },
            description="Attack chain playbooks with step-by-step exploitation instructions",
        )
