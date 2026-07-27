"""Tool Registry — 40+ external tools with platform-aware install commands.

Every tool from the Elite Recon Methodology, categorized and ready for
auto-detection and installation. Each entry knows how to check if it's
installed and how to install itself on Linux and Windows.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass


@dataclass
class ToolEntry:
    """Metadata for a single external tool."""

    name: str
    check_cmd: str
    install_linux: str
    install_windows: str
    category: str         # core, extended, osint, sast, system
    description: str
    required: bool
    url: str


# ── CORE: ProjectDiscovery Go tools ───────────────────────────────────

_CORE = [
    ToolEntry("subfinder", "subfinder -version",
              "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
              "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
              "core", "Passive subdomain discovery (40+ sources)", True,
              "https://github.com/projectdiscovery/subfinder"),
    ToolEntry("httpx-pd", "httpx -version",
              "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
              "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
              "core", "Web server probing and fingerprinting", True,
              "https://github.com/projectdiscovery/httpx"),
    ToolEntry("nuclei", "nuclei -version",
              "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
              "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
              "core", "Template-based vulnerability scanner", True,
              "https://github.com/projectdiscovery/nuclei"),
    ToolEntry("naabu", "naabu -version",
              "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
              "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
              "core", "Fast port scanner", True,
              "https://github.com/projectdiscovery/naabu"),
    ToolEntry("katana", "katana -version",
              "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
              "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
              "core", "JS-aware web crawler", True,
              "https://github.com/projectdiscovery/katana"),
    ToolEntry("dnsx", "dnsx -version",
              "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
              "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
              "core", "Fast DNS resolver and record extractor", True,
              "https://github.com/projectdiscovery/dnsx"),
    ToolEntry("tlsx", "tlsx -version",
              "go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
              "go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
              "core", "TLS/SSL SAN extraction", False,
              "https://github.com/projectdiscovery/tlsx"),
    ToolEntry("alterx", "alterx -version",
              "go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest",
              "go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest",
              "core", "Smart subdomain permutation generator", False,
              "https://github.com/projectdiscovery/alterx"),
    ToolEntry("puredns", "puredns version",
              "go install -v github.com/d3mondev/puredns/v2@latest",
              "go install -v github.com/d3mondev/puredns/v2@latest",
              "core", "Active DNS brute-force with wildcard filtering", False,
              "https://github.com/d3mondev/puredns"),
]

# ── EXTENDED: Additional Go recon tools ───────────────────────────────

_EXTENDED = [
    ToolEntry("ffuf", "ffuf -V",
              "go install -v github.com/ffuf/ffuf/v2@latest",
              "go install -v github.com/ffuf/ffuf/v2@latest",
              "extended", "Fast web fuzzer for dirs and files", False,
              "https://github.com/ffuf/ffuf"),
    ToolEntry("gowitness", "gowitness version",
              "go install -v github.com/sensepost/gowitness@latest",
              "go install -v github.com/sensepost/gowitness@latest",
              "extended", "Webpage screenshot utility", False,
              "https://github.com/sensepost/gowitness"),
    ToolEntry("hakrawler", "hakrawler -h",
              "go install -v github.com/hakluke/hakrawler@latest",
              "go install -v github.com/hakluke/hakrawler@latest",
              "extended", "Fast web crawler", False,
              "https://github.com/hakluke/hakrawler"),
    ToolEntry("gotator", "gotator -version",
              "go install -v github.com/Josue87/gotator@latest",
              "go install -v github.com/Josue87/gotator@latest",
              "extended", "Subdomain permutation tool", False,
              "https://github.com/Josue87/gotator"),
    ToolEntry("gau", "gau -version",
              "go install -v github.com/lc/gau/v2/cmd/gau@latest",
              "go install -v github.com/lc/gau/v2/cmd/gau@latest",
              "extended", "Fetch URLs from AlienVault, Wayback, Common Crawl", False,
              "https://github.com/lc/gau"),
    ToolEntry("waybackurls", "waybackurls -h",
              "go install -v github.com/tomnomnom/waybackurls@latest",
              "go install -v github.com/tomnomnom/waybackurls@latest",
              "extended", "Historical URLs from Wayback Machine", False,
              "https://github.com/tomnomnom/waybackurls"),
    ToolEntry("anew", "anew -h",
              "go install -v github.com/tomnomnom/anew@latest",
              "go install -v github.com/tomnomnom/anew@latest",
              "extended", "Append unique lines to files", False,
              "https://github.com/tomnomnom/anew"),
    ToolEntry("unfurl", "unfurl -h",
              "go install -v github.com/tomnomnom/unfurl@latest",
              "go install -v github.com/tomnomnom/unfurl@latest",
              "extended", "URL parsing and extraction", False,
              "https://github.com/tomnomnom/unfurl"),
    ToolEntry("subjs", "subjs -h",
              "go install -v github.com/lc/subjs@latest",
              "go install -v github.com/lc/subjs@latest",
              "extended", "JS file URL extractor", False,
              "https://github.com/lc/subjs"),
    ToolEntry("jsluice", "jsluice version",
              "go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest",
              "go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest",
              "extended", "JS AST parser for URLs and secrets", False,
              "https://github.com/BishopFox/jsluice"),
    ToolEntry("sourcemapper", "sourcemapper -h",
              "go install -v github.com/denandz/sourcemapper@latest",
              "go install -v github.com/denandz/sourcemapper@latest",
              "extended", "Reconstruct source from .map files", False,
              "https://github.com/denandz/sourcemapper"),
    ToolEntry("uncover", "uncover -version",
              "go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest",
              "go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest",
              "extended", "Search Shodan, Censys, FOFA from CLI", False,
              "https://github.com/projectdiscovery/uncover"),
    ToolEntry("mantra", "mantra -h",
              "go install -v github.com/MrEmpy/mantra@latest",
              "go install -v github.com/MrEmpy/mantra@latest",
              "extended", "Fast regex secret/endpoint extractor", False,
              "https://github.com/MrEmpy/mantra"),
    ToolEntry("assetfinder", "assetfinder -h",
              "go install -v github.com/tomnomnom/assetfinder@latest",
              "go install -v github.com/tomnomnom/assetfinder@latest",
              "extended", "Subdomain discovery from various sources", False,
              "https://github.com/tomnomnom/assetfinder"),
    ToolEntry("gospider", "gospider -h",
              "go install -v github.com/jaeles-project/gospider@latest",
              "go install -v github.com/jaeles-project/gospider@latest",
              "extended", "Fast web spider for endpoint and link extraction", False,
              "https://github.com/jaeles-project/gospider"),
    ToolEntry("getJS", "getJS -h",
              "go install -v github.com/003random/getJS@latest",
              "go install -v github.com/003random/getJS@latest",
              "extended", "Extract JS file URLs from pages", False,
              "https://github.com/003random/getJS"),
]

# ── OSINT: Python / CLI intelligence tools ────────────────────────────

_OSINT = [
    ToolEntry("theHarvester", "theHarvester -h",
              "pip install theHarvester", "pip install theHarvester",
              "osint", "Email, subdomain, and name harvester", False,
              "https://github.com/laramies/theHarvester"),
    ToolEntry("dnstwist", "dnstwist --help",
              "pip install dnstwist[full]", "pip install dnstwist",
              "osint", "Typosquatting domain scanner", False,
              "https://github.com/elceef/dnstwist"),
    ToolEntry("checkdmarc", "checkdmarc --help",
              "pip install checkdmarc", "pip install checkdmarc",
              "osint", "SPF/DKIM/DMARC validator", False,
              "https://github.com/domainaware/checkdmarc"),
    ToolEntry("waymore", "waymore -h",
              "pip install waymore", "pip install waymore",
              "osint", "Wayback, URLScan, OTX fetcher", False,
              "https://github.com/xnl-h4ck3r/waymore"),
    ToolEntry("arjun", "arjun -h",
              "pip install arjun", "pip install arjun",
              "osint", "HTTP parameter discovery", False,
              "https://github.com/s0md3v/Arjun"),
    ToolEntry("shodan", "shodan version",
              "pip install shodan", "pip install shodan",
              "osint", "Shodan CLI for host search", False,
              "https://cli.shodan.io"),
    ToolEntry("trufflehog", "trufflehog --version",
              "pip install trufflehog", "pip install trufflehog",
              "osint", "Git secret finder", False,
              "https://github.com/trufflesecurity/trufflehog"),
    ToolEntry("gitleaks", "gitleaks version",
              "go install github.com/gitleaks/gitleaks/v8@latest",
              "go install github.com/gitleaks/gitleaks/v8@latest",
              "osint", "Git repository secret scanner", False,
              "https://github.com/gitleaks/gitleaks"),
    ToolEntry("whois", "whois --version",
              "sudo apt install -y whois", "choco install whois -y",
              "osint", "Domain WHOIS lookup", False,
              "https://github.com/rfc1036/whois"),
    ToolEntry("dig", "dig -v",
              "sudo apt install -y dnsutils", "choco install bind-toolsonly -y",
              "osint", "DNS query and zone transfer utility", False,
              "https://www.isc.org/bind/"),
    ToolEntry("gh", "gh --version",
              "sudo apt install -y gh", "choco install gh -y",
              "osint", "GitHub CLI for org recon and secret hunting", False,
              "https://cli.github.com"),
    ToolEntry("git-dumper", "git-dumper -h",
              "pip install git-dumper", "pip install git-dumper",
              "osint", "Dump exposed .git directories", False,
              "https://github.com/arthaud/git-dumper"),
    ToolEntry("LinkFinder", "python3 -m linkfinder -h",
              "pip install linkfinder", "pip install linkfinder",
              "osint", "Discover endpoints in JS files", False,
              "https://github.com/GerbenJavado/LinkFinder"),
]

# ── SAST: Static analysis tools ───────────────────────────────────────

_SAST = [
    ToolEntry("semgrep", "semgrep --version",
              "pip install semgrep", "pip install semgrep",
              "sast", "Lightweight SAST engine (1000+ rules)", False,
              "https://semgrep.dev"),
    ToolEntry("retire", "retire --version",
              "npm install -g retire", "npm install -g retire",
              "sast", "Identify vulnerable JS libraries", False,
              "https://retirejs.github.io/retire.js"),
    ToolEntry("eslint", "eslint --version",
              "npm install -g eslint eslint-plugin-security",
              "npm install -g eslint eslint-plugin-security",
              "sast", "JS linter with security plugin", False,
              "https://eslint.org"),
    ToolEntry("nodejsscan", "nodejsscan -h",
              "pip install nodejsscan", "pip install nodejsscan",
              "sast", "Node.js static security code scanner", False,
              "https://github.com/ajinabraham/nodejsscan"),
    ToolEntry("graudit", "graudit -h",
              "sudo apt install -y graudit || git clone https://github.com/wireghoul/graudit ~/tools/graudit",
              "git clone https://github.com/wireghoul/graudit %USERPROFILE%\\tools\\graudit",
              "sast", "Grep-based source code auditing", False,
              "https://github.com/wireghoul/graudit"),
    ToolEntry("jshint", "jshint --version",
              "npm install -g jshint", "npm install -g jshint",
              "sast", "JS static analysis and linting", False,
              "https://jshint.com"),
]

# ── SYSTEM: Core system tools ─────────────────────────────────────────

_SYSTEM = [
    ToolEntry("nmap", "nmap --version",
              "sudo apt install -y nmap", "choco install nmap -y",
              "system", "Network port scanner", False,
              "https://nmap.org"),
    ToolEntry("masscan", "masscan --version",
              "sudo apt install -y masscan", "choco install masscan -y",
              "system", "High-speed TCP port scanner", False,
              "https://github.com/robertdavidgraham/masscan"),
    ToolEntry("whatweb", "whatweb --version",
              "sudo apt install -y whatweb", "gem install whatweb",
              "system", "Web technology fingerprinter", False,
              "https://github.com/urbanadventurer/WhatWeb"),
    ToolEntry("feroxbuster", "feroxbuster --version",
              "sudo apt install -y feroxbuster",
              "choco install feroxbuster -y",
              "system", "Recursive directory brute-forcer", False,
              "https://github.com/epi052/feroxbuster"),
    ToolEntry("wafw00f", "wafw00f --version",
              "pip install wafw00f", "pip install wafw00f",
              "system", "WAF detection tool", False,
              "https://github.com/EnableSecurity/wafw00f"),
    ToolEntry("go", "go version",
              "sudo apt install -y golang-go || (wget -q https://go.dev/dl/go1.22.5.linux-amd64.tar.gz && sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz && rm go1.22.5.linux-amd64.tar.gz)",
              "choco install golang -y",
              "system", "Go language (required for Go tools)", False,
              "https://go.dev"),
    ToolEntry("dirsearch", "dirsearch -h",
              "pip install dirsearch", "pip install dirsearch",
              "system", "Web path discovery / dir brute-forcer", False,
              "https://github.com/maurosoria/dirsearch"),
    ToolEntry("seclists", "ls /usr/share/seclists/Discovery 2>/dev/null || ls ~/seclists 2>/dev/null",
              "sudo apt install -y seclists || git clone --depth 1 https://github.com/danielmiessler/SecLists ~/seclists",
              "git clone --depth 1 https://github.com/danielmiessler/SecLists %USERPROFILE%\\seclists",
              "system", "SecLists wordlists collection", False,
              "https://github.com/danielmiessler/SecLists"),
]


# ── Master registry ──────────────────────────────────────────────────

TOOL_REGISTRY: list[ToolEntry] = _CORE + _EXTENDED + _OSINT + _SAST + _SYSTEM

CATEGORIES = {
    "core": _CORE,
    "extended": _EXTENDED,
    "osint": _OSINT,
    "sast": _SAST,
    "system": _SYSTEM,
}


def check_tool(name: str) -> bool:
    """Check if a tool is available on PATH."""
    # Map tool names to actual binary names
    binary_map = {
        "httpx-pd": "httpx",
        "theHarvester": "theHarvester",
    }
    binary = binary_map.get(name, name)
    return shutil.which(binary) is not None


def check_all() -> dict[str, bool]:
    """Check all registered tools. Returns {name: is_installed}."""
    return {tool.name: check_tool(tool.name) for tool in TOOL_REGISTRY}


def get_missing(category: str | None = None) -> list[ToolEntry]:
    """Get list of missing tools, optionally filtered by category."""
    tools = CATEGORIES.get(category, TOOL_REGISTRY) if category else TOOL_REGISTRY
    return [t for t in tools if not check_tool(t.name)]


def get_installed(category: str | None = None) -> list[ToolEntry]:
    """Get list of installed tools."""
    tools = CATEGORIES.get(category, TOOL_REGISTRY) if category else TOOL_REGISTRY
    return [t for t in tools if check_tool(t.name)]


def get_by_category() -> dict[str, list[tuple[ToolEntry, bool]]]:
    """Get all tools grouped by category with install status."""
    result: dict[str, list[tuple[ToolEntry, bool]]] = {}
    for cat_name, tools in CATEGORIES.items():
        result[cat_name] = [(t, check_tool(t.name)) for t in tools]
    return result
