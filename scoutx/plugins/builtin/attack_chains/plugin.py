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

        # CVSS scoring — auto-calculate scores for each chain
        try:
            from scoutx.chains.cvss import score_chain
            for chain in report.chains:
                cvss_score, cvss_vector = score_chain(chain.category)
                chain.cvss_score = cvss_score
                chain.cvss_vector = cvss_vector
            # Re-save with CVSS data
            write_json(output_dir / "chain_data.json", report.to_dict())
        except Exception as cvss_exc:
            logger.debug("CVSS scoring skipped: %s", cvss_exc)

        # AI Narrator — generate natural-language exploitation narratives
        try:
            from scoutx.ai.client import create_client
            ai_provider = context.config.get("ai.provider", "none")
            if ai_provider and ai_provider != "none":
                client = create_client(
                    provider=ai_provider,
                    model=context.config.get("ai.model", ""),
                    api_key=context.config.get("ai.api_key", ""),
                    base_url=context.config.get("ai.base_url", ""),
                )
                if client:
                    import asyncio
                    from scoutx.chains.narrator import ChainNarrator
                    narrator = ChainNarrator(client)
                    narrative = asyncio.get_event_loop().run_until_complete(
                        narrator.narrate_report(report.to_dict())
                    ) if not asyncio.get_event_loop().is_running() else await narrator.narrate_report(report.to_dict())
                    if narrative:
                        narrative_path = output_dir / "narrative.md"
                        narrative_path.write_text(narrative, encoding="utf-8")
                        info(f"AI narrative generated ({client.provider_name()})")
        except Exception as ai_exc:
            logger.debug("AI narration skipped: %s", ai_exc)

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
