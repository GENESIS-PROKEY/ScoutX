"""Elite Recon Methodology — 10-phase workflow as structured data.

Maps the FINAL-MASTER-RECON methodology to ScoutX plugins and
external tool dependencies. Each phase defines what gets done,
which plugin handles it, and what external tools enhance it.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class MethodologyPhase:
    """A single phase in the recon methodology."""

    id: str
    name: str
    description: str
    scoutx_plugin: str          # Which ScoutX plugin handles this
    external_tools: list[str]   # External tools that enhance this phase
    active: bool = False        # Requires --profile aggressive
    order: int = 0


# The 10-phase Elite Recon Methodology
METHODOLOGY_PHASES: list[MethodologyPhase] = [
    MethodologyPhase(
        id="PHASE-01",
        name="OSINT & Passive Intelligence",
        description="WHOIS lookup, DNS enumeration (all record types), ASN discovery, "
                    "email harvesting, SPF/DKIM/DMARC analysis, dnstwist typosquatting",
        scoutx_plugin="osint",
        external_tools=["whois", "dig", "theHarvester", "dnstwist", "checkdmarc"],
        order=1,
    ),
    MethodologyPhase(
        id="PHASE-02",
        name="Infrastructure Mapping",
        description="Shodan/Censys host search, certificate transparency, "
                    "cloud provider detection, CDN identification",
        scoutx_plugin="osint",
        external_tools=["shodan", "uncover", "tlsx"],
        order=1,
    ),
    MethodologyPhase(
        id="PHASE-03",
        name="Passive Subdomain Discovery",
        description="Multi-source subdomain enumeration: crtsh, SecurityTrails, "
                    "VirusTotal, Shodan, Censys, DNSDB, assetfinder, subfinder",
        scoutx_plugin="subdomains",
        external_tools=["subfinder", "assetfinder", "tlsx"],
        order=1,
    ),
    MethodologyPhase(
        id="PHASE-04",
        name="Active Subdomain Brute-Force",
        description="DNS brute-forcing with wildcard filtering, permutation "
                    "scanning with gotator/alterx, DNS resolution with dnsx",
        scoutx_plugin="subdomains",
        external_tools=["puredns", "gotator", "alterx", "dnsx"],
        active=True,
        order=1,
    ),
    MethodologyPhase(
        id="PHASE-05",
        name="HTTP Probing & Tech Fingerprint",
        description="Alive host detection, technology fingerprinting, "
                    "WAF detection, favicon hash, CDN identification, screenshots",
        scoutx_plugin="probe",
        external_tools=["httpx-pd", "whatweb", "wafw00f", "gowitness"],
        order=2,
    ),
    MethodologyPhase(
        id="PHASE-06",
        name="Port Scanning & Service Enum",
        description="Full port scanning, service version detection, "
                    "banner grabbing, SSL/TLS analysis",
        scoutx_plugin="ports",
        external_tools=["naabu", "nmap", "masscan"],
        order=2,
    ),
    MethodologyPhase(
        id="PHASE-07",
        name="URL & Endpoint Discovery",
        description="Wayback Machine, Common Crawl, crawling, URL harvesting, "
                    "parameter discovery, JS endpoint extraction",
        scoutx_plugin="endpoints",
        external_tools=["gau", "waybackurls", "katana", "hakrawler",
                        "gospider", "waymore", "arjun", "unfurl"],
        order=3,
    ),
    MethodologyPhase(
        id="PHASE-08",
        name="JS Deep Analysis",
        description="Source map detection, webpack chunk discovery, "
                    "SAST analysis, deobfuscation detection, secret scanning",
        scoutx_plugin="js_deep",
        external_tools=["subjs", "getJS", "jsluice", "sourcemapper",
                        "mantra", "LinkFinder", "semgrep", "retire"],
        order=4,
    ),
    MethodologyPhase(
        id="PHASE-09",
        name="Directory & File Discovery",
        description="Directory brute-forcing, backup file detection, "
                    "sensitive path scanning, git exposure check",
        scoutx_plugin="directories",
        external_tools=["ffuf", "feroxbuster", "dirsearch", "seclists",
                        "git-dumper"],
        active=True,
        order=3,
    ),
    MethodologyPhase(
        id="PHASE-10",
        name="Secret & Credential Hunting",
        description="GitHub org secret hunting, entropy-based detection, "
                    "S3 bucket verification, JWT payload decoding, git leaks",
        scoutx_plugin="secrets",
        external_tools=["trufflehog", "gitleaks", "gh"],
        order=4,
    ),
]


def get_phase(phase_id: str) -> MethodologyPhase | None:
    """Get a methodology phase by ID."""
    for phase in METHODOLOGY_PHASES:
        if phase.id == phase_id:
            return phase
    return None


def get_phases_for_plugin(plugin_name: str) -> list[MethodologyPhase]:
    """Get all methodology phases handled by a plugin."""
    return [p for p in METHODOLOGY_PHASES if p.scoutx_plugin == plugin_name]


def get_passive_phases() -> list[MethodologyPhase]:
    """Get phases that don't require aggressive profile."""
    return [p for p in METHODOLOGY_PHASES if not p.active]


def get_active_phases() -> list[MethodologyPhase]:
    """Get phases that require --profile aggressive."""
    return [p for p in METHODOLOGY_PHASES if p.active]


def get_all_required_tools() -> list[str]:
    """Get all external tools referenced in the methodology."""
    tools: set[str] = set()
    for phase in METHODOLOGY_PHASES:
        tools.update(phase.external_tools)
    return sorted(tools)
