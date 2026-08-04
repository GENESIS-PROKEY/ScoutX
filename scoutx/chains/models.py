"""Attack chain data models — the DNA of every exploitation playbook.

These dataclasses define the structure of attack chains: from individual
steps with tool commands, to full chains with prerequisites, evidence,
severity scoring, and mitigation guidance.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AttackStep:
    """A single step in an attack chain playbook."""

    order: int
    action: str               # Human-readable description: "Verify CNAME is dangling"
    command: str               # Exact command to run: "dig CNAME sub.target.com"
    tool: str                  # Tool needed: "dig"
    expected_result: str       # What to look for: "NXDOMAIN or unclaimed service"
    notes: str = ""            # Extra context / tips


@dataclass
class AttackChain:
    """A complete attack chain — a step-by-step exploitation playbook."""

    id: str                           # Unique chain ID: "chain-takeover-001"
    title: str                        # "Subdomain Takeover via Dangling CNAME"
    severity: str                     # critical / high / medium / low
    confidence: float                 # 0.0 - 1.0 (how sure are we this is exploitable)
    category: str                     # takeover, data_exfil, auth_bypass, rce, etc.
    description: str                  # What this chain does and why it matters
    prerequisites: list[str] = field(default_factory=list)   # What must be true
    steps: list[AttackStep] = field(default_factory=list)     # Ordered steps
    tools_needed: list[str] = field(default_factory=list)     # All tools required
    references: list[str] = field(default_factory=list)       # OWASP, blog links, etc.
    mitigation: str = ""              # How to fix this
    evidence: dict[str, Any] = field(default_factory=dict)    # Raw recon data
    target_host: str = ""             # Which host this applies to
    affected_assets: list[str] = field(default_factory=list)  # URLs, subdomains, etc.
    cvss_score: float = 0.0           # CVSS v3.1 base score (auto-calculated)
    cvss_vector: str = ""             # CVSS v3.1 vector string
    exploitability: float = 0.0       # 0.0 - 1.0 how likely this is a REAL exploitable finding

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for JSON export."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "description": self.description,
            "target_host": self.target_host,
            "affected_assets": self.affected_assets,
            "prerequisites": self.prerequisites,
            "steps": [
                {
                    "order": s.order,
                    "action": s.action,
                    "command": s.command,
                    "tool": s.tool,
                    "expected_result": s.expected_result,
                    "notes": s.notes,
                }
                for s in self.steps
            ],
            "tools_needed": self.tools_needed,
            "references": self.references,
            "mitigation": self.mitigation,
            "evidence": self.evidence,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "exploitability": self.exploitability,
        }


@dataclass
class ChecklistItem:
    """A single item from the vulnerability checklist."""

    id: str                    # "VLN-AUTH-001"
    phase: str                 # "Authentication & Session"
    category: str              # "JWT Attacks"
    check: str                 # "JWT - None Algorithm Attack"
    severity: str              # critical / high / medium / low
    applicable: bool = False   # Whether this check applies to the target
    reason: str = ""           # Why it's applicable: "JWT detected in auth flow"
    verification_steps: list[str] = field(default_factory=list)


@dataclass
class ChainReport:
    """Container for all attack chains and checklist results from a scan."""

    target: str
    scan_id: str
    chains: list[AttackChain] = field(default_factory=list)
    checklist: list[ChecklistItem] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    @property
    def critical_chains(self) -> list[AttackChain]:
        return [c for c in self.chains if c.severity == "critical"]

    @property
    def high_chains(self) -> list[AttackChain]:
        return [c for c in self.chains if c.severity == "high"]

    @property
    def applicable_checks(self) -> list[ChecklistItem]:
        return [c for c in self.checklist if c.applicable]

    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for chain in self.chains:
            if chain.severity in counts:
                counts[chain.severity] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scan_id": self.scan_id,
            "total_chains": len(self.chains),
            "severity_breakdown": self.severity_counts(),
            "chains": [c.to_dict() for c in self.chains],
            "checklist_applicable": len(self.applicable_checks),
            "checklist_total": len(self.checklist),
            "summary": self.summary,
        }
