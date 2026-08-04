"""Attack Chain Engine — correlates all recon data into exploitation playbooks.

This is the brain. It takes every plugin's output, feeds it through the
pattern database, scores and ranks the resulting chains, and produces
a ChainReport ready for human review.
"""
from __future__ import annotations

import hashlib
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

        # --- Smart Dedup ---
        # Standard dedup by chain ID
        seen_ids: set[str] = set()
        deduped: list[AttackChain] = []
        for chain in all_chains:
            if chain.id not in seen_ids:
                seen_ids.add(chain.id)
                deduped.append(chain)

        # Secret-specific dedup: merge chains with same secret value
        # (same key found in multiple JS files = one chain, not 7)
        secret_chains: list[AttackChain] = []
        non_secret_chains: list[AttackChain] = []
        for chain in deduped:
            if chain.category == "credential_exposure":
                secret_chains.append(chain)
            else:
                non_secret_chains.append(chain)

        merged_secrets: list[AttackChain] = []
        seen_secret_values: dict[str, int] = {}  # secret_hash -> index in merged_secrets
        for chain in secret_chains:
            # Extract the actual secret value from evidence
            evidence = chain.evidence if isinstance(chain.evidence, dict) else {}
            raw_match = evidence.get("match_raw", evidence.get("match", ""))
            if not raw_match:
                # Fallback: try to get from description
                merged_secrets.append(chain)
                continue

            # Hash first 20 chars of the actual secret (ignoring file path)
            secret_key = raw_match[:20].strip()
            secret_hash = hashlib.md5(secret_key.encode()).hexdigest()[:12]

            if secret_hash in seen_secret_values:
                # Merge: add this file to the existing chain's affected_assets
                idx = seen_secret_values[secret_hash]
                existing = merged_secrets[idx]
                for asset in chain.affected_assets:
                    if asset not in existing.affected_assets:
                        existing.affected_assets.append(asset)
                # Keep the higher severity/confidence
                if chain.severity == "critical" and existing.severity != "critical":
                    existing.severity = "critical"
                if chain.confidence > existing.confidence:
                    existing.confidence = chain.confidence
            else:
                seen_secret_values[secret_hash] = len(merged_secrets)
                merged_secrets.append(chain)

        unique_chains = non_secret_chains + merged_secrets

        # --- Exploitability Scoring ---
        for chain in unique_chains:
            chain.exploitability = self._score_exploitability(chain)

        # Sort by: exploitability (desc), severity (crit>high>med>low), confidence (desc)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        unique_chains.sort(
            key=lambda c: (
                -c.exploitability,
                severity_order.get(c.severity, 99),
                -c.confidence,
            )
        )

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
                "dedup_removed": len(all_chains) - len(unique_chains),
            },
        )

        logger.info(
            "Generated %d attack chains in %.2fs (C:%d H:%d M:%d L:%d, deduped %d)",
            len(unique_chains), elapsed,
            severity_counts["critical"], severity_counts["high"],
            severity_counts["medium"], severity_counts["low"],
            len(all_chains) - len(unique_chains),
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

    @staticmethod
    def _score_exploitability(chain: AttackChain) -> float:
        """Score how likely a chain is to be a REAL exploitable finding (0.0-1.0).

        Higher score = more likely to be real and worth reporting.
        This prioritizes chains with specific, verifiable evidence over
        generic pattern matches.
        """
        score = 0.0

        # --- Category base scores ---
        # Some categories are inherently more likely to be real
        CATEGORY_SCORES = {
            "takeover": 0.85,        # Dangling CNAMEs are very concrete
            "ssrf": 0.75,            # Cloud SSRF is high-impact if confirmed
            "injection": 0.60,       # SQLi needs manual validation
            "data_exfil": 0.70,      # Open DB ports are verifiable
            "credential_exposure": 0.55,  # Many secrets are false positives
            "auth_bypass": 0.65,     # OAuth chains need chaining
            "xss": 0.40,             # Reflection != exploitation
            "cors_theft": 0.50,      # CORS needs specific conditions
            "ssl_downgrade": 0.30,   # Often informational
            "cloud_misconfig": 0.60, # S3 buckets are verifiable
            "api_exposure": 0.55,    # Swagger in prod is concrete
            "github_leak": 0.50,     # Needs credential validation
        }
        score = CATEGORY_SCORES.get(chain.category, 0.40)

        # --- Confidence boost ---
        score += chain.confidence * 0.15

        # --- Evidence specificity boosts ---
        evidence = chain.evidence if isinstance(chain.evidence, dict) else {}

        # Real secret prefixes that are almost certainly not placeholders
        raw_match = evidence.get("match_raw", evidence.get("match", ""))
        REAL_PREFIXES = (
            "AKIA",     # AWS access key
            "ghp_",     # GitHub PAT
            "gho_",     # GitHub OAuth
            "sk_live_", # Stripe live
            "xoxb-",    # Slack bot
            "xoxp-",    # Slack user
            "AIza",     # Google API
            "sk-ant-",  # Anthropic
            "sk-",      # OpenAI
        )
        if raw_match and any(raw_match.startswith(p) for p in REAL_PREFIXES):
            score += 0.20  # Known real key prefix

        # Penalize likely placeholders
        PLACEHOLDER_PATTERNS = (
            "xxx", "test", "example", "changeme", "your_", "insert",
            "replace", "todo", "fixme", "dummy", "sample", "demo",
            "000000", "111111", "abcdef", "123456",
        )
        if raw_match and any(p in raw_match.lower() for p in PLACEHOLDER_PATTERNS):
            score -= 0.30

        # Boost for nuclei-confirmed findings
        if chain.category == "nuclei_exploit":
            score += 0.25

        # Boost for multiple affected assets (more evidence = more real)
        if len(chain.affected_assets) >= 3:
            score += 0.05
        if len(chain.affected_assets) >= 5:
            score += 0.05

        # Boost if target_host looks like a real production URL
        host = chain.target_host.lower()
        if any(env in host for env in ("prod", "api.", "app.", "www.")):
            score += 0.05
        # Penalize staging/test environments slightly
        if any(env in host for env in ("staging", "test", "dev.", "localhost")):
            score -= 0.05

        return max(0.0, min(1.0, round(score, 3)))
