"""Attack Chain Engine — correlates all recon data into exploitation playbooks.

This is the brain. It takes every plugin's output, feeds it through the
pattern database, scores and ranks the resulting chains, and produces
a ChainReport ready for human review.
"""
from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

from scoutx.chains.models import AttackChain, ChainReport
from scoutx.chains.patterns import ALL_PATTERNS

if TYPE_CHECKING:
    from scoutx.core.engine import ScanContext

logger = logging.getLogger("scoutx.chains.engine")


class AttackChainEngine:
    """Generates attack chains from scan results.

    Usage:
        engine = AttackChainEngine()
        report = engine.analyze(context)
    """

    def __init__(self) -> None:
        self._patterns = ALL_PATTERNS

    def analyze(self, context: ScanContext) -> ChainReport:
        """Run all pattern detectors against scan data and build the report."""
        start = time.time()

        # Collect all plugin results into a single dict
        scan_data = self._collect_scan_data(context)

        # Run every pattern detector
        all_chains: list[AttackChain] = []
        for pattern_fn in self._patterns:
            try:
                chains = pattern_fn(scan_data)
                all_chains.extend(chains)
            except Exception as exc:
                logger.warning(
                    "Pattern %s failed: %s", pattern_fn.__name__, exc
                )

        # Sort by severity (critical > high > medium > low), then confidence
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        all_chains.sort(
            key=lambda c: (severity_order.get(c.severity, 99), -c.confidence)
        )

        # Deduplicate by chain ID
        seen: set[str] = set()
        unique_chains: list[AttackChain] = []
        for chain in all_chains:
            if chain.id not in seen:
                seen.add(chain.id)
                unique_chains.append(chain)

        # Build the checklist mapping
        from scoutx.chains.checklist import VulnChecklist
        checklist = VulnChecklist()
        applicable_items = checklist.map_findings(scan_data)

        elapsed = time.time() - start
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for chain in unique_chains:
            if chain.severity in severity_counts:
                severity_counts[chain.severity] += 1

        report = ChainReport(
            target=context.target,
            scan_id=context.scan_id if hasattr(context, "scan_id") else "",
            chains=unique_chains,
            checklist=applicable_items,
            summary={
                "total_chains": len(unique_chains),
                "severity_breakdown": severity_counts,
                "checklist_applicable": len([i for i in applicable_items if i.applicable]),
                "checklist_total": len(applicable_items),
                "analysis_time_seconds": round(elapsed, 2),
                "patterns_evaluated": len(self._patterns),
            },
        )

        logger.info(
            "Generated %d attack chains in %.2fs (C:%d H:%d M:%d L:%d)",
            len(unique_chains), elapsed,
            severity_counts["critical"], severity_counts["high"],
            severity_counts["medium"], severity_counts["low"],
        )

        return report

    def _collect_scan_data(self, context: ScanContext) -> dict[str, Any]:
        """Pull all plugin results into a flat dictionary."""
        data: dict[str, Any] = {}
        plugin_names = [
            "subdomains", "probe", "ports", "ssl_analysis", "cors",
            "js", "endpoints", "parameters", "secrets", "takeover",
            "screenshots", "nuclei", "intelligence",
            "cloud", "api_discovery", "github_dork", "historical",
        ]
        for name in plugin_names:
            try:
                result = context.result_data(name)
                if result:
                    data[name] = result
            except Exception:
                data[name] = {}
        return data
