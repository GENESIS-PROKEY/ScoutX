"""SARIF report generator — Static Analysis Results Interchange Format.

SARIF is the standard for integrating security tools with CI/CD pipelines,
GitHub Code Scanning, Azure DevOps, and VS Code. This lets ScoutX findings
show up directly in your IDE and PR reviews.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scoutx.reporting.aggregator import ScanSummary

logger = logging.getLogger("scoutx.reporting.sarif")

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

# Map ScoutX severity to SARIF level
SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


class SarifReporter:
    """Generate SARIF 2.1.0 output for CI/CD integration."""

    def __init__(self, summary: ScanSummary) -> None:
        self._s = summary

    def generate(self, output_path: Path) -> Path:
        """Render and write the SARIF report."""
        rules: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        rule_ids: set[str] = set()

        # Secret findings
        for idx, sec in enumerate(self._s.secrets):
            rule_id = f"scoutx/secrets/{sec.get('pattern', 'unknown').lower().replace(' ', '-')}"
            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": sec.get("pattern", "Unknown"),
                    "shortDescription": {"text": sec.get("description", "Secret detected")},
                    "defaultConfiguration": {
                        "level": SEVERITY_MAP.get(sec.get("severity", "info"), "note"),
                    },
                    "properties": {
                        "tags": ["security", "secret-detection"],
                        "precision": sec.get("confidence", "medium"),
                    },
                })

            results.append({
                "ruleId": rule_id,
                "level": SEVERITY_MAP.get(sec.get("severity", "info"), "note"),
                "message": {
                    "text": f"{sec.get('pattern', 'Secret')}: {sec.get('match', 'redacted')}",
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": sec.get("source_url", sec.get("source_file", "")),
                        },
                        "region": {
                            "startLine": sec.get("line_number", 1),
                        },
                    },
                }],
                "properties": {
                    "confidence": sec.get("confidence", "medium"),
                },
            })

        # SSL issues
        for issue in self._s.ssl_issues:
            rule_id = f"scoutx/ssl/{issue.get('issue', 'unknown').lower().replace(' ', '-')}"
            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": issue.get("issue", "SSL Issue"),
                    "shortDescription": {"text": issue.get("issue", "")},
                    "defaultConfiguration": {
                        "level": SEVERITY_MAP.get(issue.get("severity", "info"), "note"),
                    },
                    "properties": {"tags": ["security", "ssl"]},
                })

            results.append({
                "ruleId": rule_id,
                "level": SEVERITY_MAP.get(issue.get("severity", "info"), "note"),
                "message": {
                    "text": f"{issue.get('issue', '')}: {issue.get('hostname', '')} - {issue.get('details', '')}",
                },
                "locations": [{
                    "logicalLocations": [{
                        "name": issue.get("hostname", ""),
                        "kind": "host",
                    }],
                }],
            })

        # Interesting endpoints
        for ep in self._s.endpoints:
            if not ep.get("interesting"):
                continue
            cats = ", ".join(ep.get("categories", []))
            rule_id = "scoutx/endpoints/interesting-endpoint"
            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": "Interesting Endpoint",
                    "shortDescription": {"text": "Potentially sensitive API endpoint discovered in JavaScript"},
                    "defaultConfiguration": {"level": "note"},
                    "properties": {"tags": ["security", "endpoint-discovery"]},
                })

            results.append({
                "ruleId": rule_id,
                "level": "note",
                "message": {"text": f"Interesting endpoint: {ep.get('path', '')} (categories: {cats})"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": ep.get("path", "")},
                    },
                }],
            })

        # Build the SARIF document
        sarif: dict[str, Any] = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "ScoutX",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/scoutx-recon/scoutx",
                        "rules": rules,
                    },
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": self._s.scan_state.get("started_at", datetime.now(timezone.utc).isoformat()),
                }],
                "properties": {
                    "target": self._s.target,
                    "profile": self._s.profile,
                    "scanId": self._s.scan_id,
                },
            }],
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(sarif, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        logger.info("SARIF report written to %s (%d results, %d rules)", output_path, len(results), len(rules))
        return output_path
