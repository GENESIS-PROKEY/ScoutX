"""Tests for the Attack Chain Engine."""
from __future__ import annotations

import pytest

from scoutx.chains.checklist import VulnChecklist
from scoutx.chains.models import AttackChain, AttackStep, ChainReport, ChecklistItem
from scoutx.chains.patterns import (
    detect_cors_theft,
    detect_exposed_databases,
    detect_internal_endpoints,
    detect_nuclei_exploits,
    detect_secret_exploitation,
    detect_subdomain_takeover,
    detect_tech_cve_chains,
)


class TestAttackChainModels:
    def test_attack_step_creation(self):
        step = AttackStep(1, "Test action", "curl http://x", "curl", "200 OK")
        assert step.order == 1
        assert step.tool == "curl"

    def test_attack_chain_to_dict(self):
        chain = AttackChain(
            id="test-001", title="Test Chain", severity="high",
            confidence=0.8, category="test", description="A test",
            steps=[AttackStep(1, "Do thing", "cmd", "tool", "result")],
        )
        d = chain.to_dict()
        assert d["id"] == "test-001"
        assert d["severity"] == "high"
        assert len(d["steps"]) == 1

    def test_chain_report_severity_counts(self):
        chains = [
            AttackChain(id="a", title="", severity="critical", confidence=1.0, category="", description=""),
            AttackChain(id="b", title="", severity="critical", confidence=1.0, category="", description=""),
            AttackChain(id="c", title="", severity="high", confidence=1.0, category="", description=""),
            AttackChain(id="d", title="", severity="medium", confidence=1.0, category="", description=""),
        ]
        report = ChainReport(target="test.com", scan_id="001", chains=chains)
        counts = report.severity_counts()
        assert counts["critical"] == 2
        assert counts["high"] == 1
        assert counts["medium"] == 1
        assert counts["low"] == 0


class TestPatternDetectors:
    def test_subdomain_takeover_detection(self):
        scan_data = {
            "takeover": {
                "vulnerable": [
                    {"subdomain": "old.test.com", "service": "GitHub Pages", "cname": "old.github.io"},
                ]
            }
        }
        chains = detect_subdomain_takeover(scan_data)
        assert len(chains) == 1
        assert chains[0].severity == "high"
        assert "old.test.com" in chains[0].title
        assert len(chains[0].steps) > 0

    def test_takeover_empty(self):
        chains = detect_subdomain_takeover({"takeover": {"vulnerable": []}})
        assert len(chains) == 0

    def test_cors_detection(self):
        scan_data = {
            "cors": {
                "findings": [
                    {"url": "https://api.test.com/data", "severity": "high", "issue": "reflects origin"},
                ]
            }
        }
        chains = detect_cors_theft(scan_data)
        assert len(chains) == 1
        assert chains[0].category == "data_exfil"

    def test_secret_detection(self):
        scan_data = {
            "secrets": {
                "findings": [
                    {"type": "AWS Key", "severity": "critical", "file": "app.js", "match": "AKIAIOSFODNN7EXAMPLE"},
                ]
            }
        }
        chains = detect_secret_exploitation(scan_data)
        assert len(chains) == 1
        assert chains[0].severity == "critical"
        # AWS-specific steps should include aws sts
        assert any("aws" in s.command.lower() for s in chains[0].steps)

    def test_exposed_database_detection(self):
        scan_data = {
            "ports": {
                "hosts": [
                    {"host": "db.test.com", "ports": [27017, 80]},
                ]
            }
        }
        chains = detect_exposed_databases(scan_data)
        assert len(chains) == 1
        assert "MongoDB" in chains[0].title

    def test_internal_endpoint_detection(self):
        scan_data = {
            "endpoints": {
                "endpoints": [
                    "/admin/dashboard",
                    "/api/v1/users",
                    "http://192.168.1.100/internal",
                ]
            }
        }
        chains = detect_internal_endpoints(scan_data)
        assert len(chains) >= 1

    def test_tech_cve_detection(self):
        scan_data = {
            "intelligence": {
                "tech_intelligence": {
                    "detected_technologies": ["WordPress 6.2", "PHP 8.1"]
                }
            }
        }
        chains = detect_tech_cve_chains(scan_data)
        assert len(chains) >= 1
        assert any("WordPress" in c.title or "PHP" in c.title for c in chains)

    def test_nuclei_exploit_detection(self):
        scan_data = {
            "nuclei": {
                "findings": [
                    {
                        "template_id": "cve-2021-44228",
                        "template_name": "Log4Shell",
                        "severity": "critical",
                        "host": "app.test.com",
                        "matched_at": "https://app.test.com/api",
                        "description": "Log4j RCE",
                        "reference": ["https://nvd.nist.gov"],
                        "curl_command": "curl https://app.test.com/api",
                    }
                ]
            }
        }
        chains = detect_nuclei_exploits(scan_data)
        assert len(chains) == 1
        assert chains[0].severity == "critical"


class TestVulnChecklist:
    def test_checklist_always_applies(self):
        checklist = VulnChecklist()
        items = checklist.map_findings({})
        # "always" condition items should be applicable
        always_items = [i for i in items if i.applicable]
        assert len(always_items) > 0

    def test_checklist_jwt_detection(self):
        scan_data = {
            "secrets": {"findings": [{"type": "JWT Token", "severity": "high"}]},
            "intelligence": {"tech_intelligence": {"detected_technologies": []}},
            "endpoints": {"endpoints": []},
            "ports": {"hosts": {}},
        }
        checklist = VulnChecklist()
        items = checklist.map_findings(scan_data)
        jwt_items = [i for i in items if "JWT" in i.check and i.applicable]
        assert len(jwt_items) > 0

    def test_checklist_api_detection(self):
        scan_data = {
            "secrets": {"findings": []},
            "intelligence": {"tech_intelligence": {"detected_technologies": []}},
            "endpoints": {"endpoints": ["/api/v1/users", "/api/v2/data"]},
            "ports": {"hosts": {}},
        }
        checklist = VulnChecklist()
        items = checklist.map_findings(scan_data)
        api_items = [i for i in items if i.id.startswith("VLN-API") and i.applicable]
        assert len(api_items) > 0
