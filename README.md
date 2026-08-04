# ScoutX

```
   ___                _  __  __
  / __| __ ___  _  _| |_\ \/ /
  \__ \/ _/ _ \| || |  _|>  <
  |___/\__\___/ \_,_|\__/_/\_\

  ⚡ Async Reconnaissance Framework
```

**Automated attack surface discovery with methodology-driven reconnaissance, 52-tool auto-installation, AI-powered analysis, and attack chain generation.**

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Plugins](https://img.shields.io/badge/plugins-21-purple)]()
[![Tools](https://img.shields.io/badge/tools-52-orange)]()
[![AI](https://img.shields.io/badge/AI-8%20providers-ff69b4)]()
[![Tests](https://img.shields.io/badge/tests-47%20passed-brightgreen)]()

---

## Table of Contents

- [What is ScoutX?](#what-is-scoutx)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [API Key Configuration](#api-key-configuration)
- [Auto Tool Installation](#auto-tool-installation)
- [All 21 Plugins](#all-21-plugins)
- [All 52 External Tools](#all-52-external-tools)
- [Scan Profiles](#scan-profiles)
- [Attack Chain Engine](#attack-chain-engine)
- [10-Phase Methodology](#10-phase-methodology)
- [CLI Reference](#cli-reference)
- [Output Formats](#output-formats)
- [Ghost Mode (Stealth)](#ghost-mode-stealth)
- [Web Dashboard](#web-dashboard)
- [Python API](#python-api)
- [Docker](#docker)
- [Architecture](#architecture)
- [Writing Custom Plugins](#writing-custom-plugins)
- [Contributing](#contributing)
- [License](#license)

---

## What is ScoutX?

ScoutX is a modular, async-first reconnaissance framework built for security researchers, bug bounty hunters, and penetration testers. It automates the entire recon workflow from subdomain discovery to attack chain generation.

**What makes it different:**

- 🔥 **21 built-in plugins** across 8 execution phases
- 🛠️ **52 external tools** with automatic detection and installation
- 📋 **10-phase methodology** based on Elite Recon standards
- ⛓️ **Attack Chain Engine** — auto-generates step-by-step attack playbooks with CVSS v3.1 scoring
- 🧠 **Intelligence Engine** — risk scoring (0-100), attack campaigns, priority targeting
- 🤖 **AI Integration** — 8 LLM providers (Ollama, OpenAI, Claude, DeepSeek, Groq, Grok, OpenRouter, custom)
- 🎯 **Live TUI** — real-time scan progress with Rich terminal dashboard
- ☁️ **Cloud Recon** — AWS, GCP, Azure, Cloudflare, Heroku, Vercel, Netlify detection
- 🔍 **API Discovery** — OpenAPI/Swagger/GraphQL introspection
- 🐙 **GitHub Dorking** — find leaked credentials in public repos
- 📜 **Historical DNS** — Wayback Machine + SecurityTrails archive mining
- 🛡️ **WAF Bypass DB** — detection signatures + documented bypass techniques for 10 WAFs
- 👻 **Ghost Mode** — adaptive rate limiting, proxy rotation, stealth headers
- 📊 **7 output formats** — HTML, Markdown, CSV, SARIF, PDF, Obsidian, JSON
- 🔄 **Diff Engine + Timeline** — compare scans and visualize attack surface drift
- 📂 **Wordlist Manager** — SecLists, Assetnote, FuzzDB download + custom wordlists
- 🌐 **Cross-platform** — works on Linux, Windows, macOS, and Docker

---

## Quick Start

> **Note:** On some Linux distros (Kali, Debian), `sx` may conflict with lrzsz. Use `scoutx` instead, or remove lrzsz: `sudo apt remove lrzsz`

```bash
# Clone and set up virtual environment
git clone https://github.com/GENESIS-PROKEY/ScoutX.git
cd ScoutX
python -m venv venv && source venv/bin/activate  # Windows: .\venv\Scripts\Activate.ps1

# Install ScoutX + required extras
pip install -e .
pip install playwright && playwright install chromium

# Install Nuclei (vuln scanner) — needs Go installed
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# Check what tools you have
scoutx doctor

# Run your first scan
scoutx scan example.com

# Full power (aggressive mode)
scoutx scan example.com --profile aggressive
```

That's it. ScoutX runs all 21 plugins, discovers subdomains, probes hosts, scans ports, extracts JS endpoints, hunts secrets, detects cloud assets, discovers APIs, takes screenshots, runs Nuclei scans, and generates attack chain playbooks — automatically.

### Quick Modes

```bash
# Passive mode — OSINT only, zero active requests
scoutx scan example.com --passive

# Quick scan — subdomains + probe + ports only (~60s)
scoutx scan example.com --quick

# With AI-powered analysis (uses local Ollama)
scoutx scan example.com --profile balanced
# (set ai.provider=ollama in scoutx.yaml)

# Generate Obsidian vault from scan results
scoutx report example.com --format html,md,obsidian
```

---

## Installation

### Prerequisites

- **Python 3.10+** — [Download here](https://www.python.org/downloads/)
- **Git** — [Download here](https://git-scm.com/downloads)
- **Go 1.21+** (optional, for Go-based tools) — [Download here](https://go.dev/dl/)

### Step 1: Clone & Create Virtual Environment

> ⚠️ **IMPORTANT:** Always use a virtual environment. Installing directly with `pip install` without a venv can cause dependency conflicts and permission errors.

**Linux / macOS:**
```bash
git clone https://github.com/GENESIS-PROKEY/ScoutX.git
cd ScoutX

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install ScoutX
pip install -e .

# Or with all extras (PDF reporting, web dashboard)
pip install -e ".[full]"
```

**Windows (PowerShell):**
```powershell
git clone https://github.com/GENESIS-PROKEY/ScoutX.git
cd ScoutX

# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install ScoutX
pip install -e .

# Or with all extras (PDF reporting, web dashboard)
pip install -e ".[full]"
```

> 💡 **Tip:** Every time you open a new terminal, activate the venv first:
> - Linux/macOS: `source venv/bin/activate`
> - Windows: `.\venv\Scripts\Activate.ps1`

### Step 2: Install Playwright Browsers (Required for Screenshots)

ScoutX uses Playwright for taking screenshots of discovered hosts. Without this step, the screenshots plugin will be skipped.

```bash
# Install Playwright and download browser binaries (~300 MB)
pip install playwright
playwright install chromium
```

This downloads Chromium, FFmpeg, and headless shell binaries to your local app data directory.

### Step 3: Install Nuclei (Required for Vulnerability Scanning)

Nuclei is used for automated vulnerability detection with 9000+ templates. Without it, the nuclei plugin will be skipped.

**Linux / macOS:**
```bash
# Option 1: Using Go (recommended)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Option 2: Download binary
curl -sSL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(uname -s)_$(uname -m).zip -o nuclei.zip
unzip nuclei.zip && sudo mv nuclei /usr/local/bin/
```

**Windows (PowerShell):**
```powershell
# Option 1: Using Go (recommended)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Option 2: Download binary from GitHub Releases
# Go to https://github.com/projectdiscovery/nuclei/releases/latest
# Download nuclei_windows_amd64.zip
# Extract and add to PATH
```

After installing, download the latest vulnerability templates:
```bash
nuclei -update-templates
```

### Step 4: Verify Installation

```bash
# Check ScoutX and all tool status
scoutx doctor

# Auto-install any remaining missing tools
scoutx doctor --install all
```

### Docker (Alternative)

If you prefer Docker, everything is pre-configured:

```bash
docker build -t scoutx .
docker run --rm -v $(pwd)/results:/app/results scoutx scan example.com
```

---

## API Key Configuration

ScoutX works without any API keys — but adding them **dramatically improves** subdomain discovery, historical DNS lookups, and GitHub dorking. Some features are completely disabled without their respective keys.

### How to Set API Keys

Create a `scoutx.yaml` file in your project root (or `~/.scoutx/config.yaml` for global config):

```yaml
# scoutx.yaml — API Key Configuration
api_keys:
  # Subdomain Discovery Sources
  shodan: "YOUR_SHODAN_API_KEY"           # https://account.shodan.io/
  securitytrails: "YOUR_ST_API_KEY"       # https://securitytrails.com/app/account
  virustotal: "YOUR_VT_API_KEY"           # https://www.virustotal.com/gui/my-apikey
  censys_id: "YOUR_CENSYS_API_ID"         # https://search.censys.io/account/api
  censys_secret: "YOUR_CENSYS_SECRET"     # Same page as censys_id
  dnsdb: "YOUR_DNSDB_API_KEY"             # https://www.dnsdb.info/

  # GitHub Dorking (REQUIRED for github_dork plugin)
  github: "ghp_YOUR_GITHUB_TOKEN"         # https://github.com/settings/tokens

  # Other
  chaos: "YOUR_CHAOS_KEY"                 # https://chaos.projectdiscovery.io/
  alienvault: "YOUR_OTX_KEY"              # https://otx.alienvault.com/api
```

### Alternative: Environment Variables

You can also set API keys via environment variables:

```bash
# Linux / macOS
export SX_SHODAN_KEY="your-key-here"
export SX_SECURITYTRAILS_KEY="your-key-here"
export SX_VIRUSTOTAL_KEY="your-key-here"
export SX_GITHUB_TOKEN="ghp_your-token-here"
export SX_CENSYS_ID="your-id"
export SX_CENSYS_SECRET="your-secret"
export SX_DNSDB_KEY="your-key-here"
```

```powershell
# Windows PowerShell
$env:SX_SHODAN_KEY = "your-key-here"
$env:SX_SECURITYTRAILS_KEY = "your-key-here"
$env:SX_VIRUSTOTAL_KEY = "your-key-here"
$env:SX_GITHUB_TOKEN = "ghp_your-token-here"
```

### Which Keys Do What?

| Key | Free Tier? | What It Unlocks |
|-----|-----------|-----------------|
| **Shodan** | ✅ Yes | Subdomain discovery + port/service data from Shodan's index |
| **SecurityTrails** | ✅ Yes (50 queries/mo) | Historical DNS records, subdomain enumeration |
| **VirusTotal** | ✅ Yes (500 req/day) | Subdomain discovery from VT's passive DNS |
| **Censys** | ✅ Yes (250 queries/mo) | Certificate-based subdomain discovery |
| **DNSDB** | ❌ Paid | Passive DNS database (Farsight Security) |
| **GitHub** | ✅ Yes (free PAT) | Search GitHub repos for leaked credentials, config files |
| **Chaos** | ✅ Yes | ProjectDiscovery's chaos subdomain dataset |
| **AlienVault OTX** | ✅ Yes | Passive DNS + URL intelligence |

> 💡 **Recommended minimum:** Shodan + SecurityTrails + VirusTotal + GitHub. All have free tiers.

---

## Auto Tool Installation

ScoutX includes a **52-tool registry** with platform-aware install commands. It can automatically detect which tools are missing and install them for you.

### Check Tool Status

```bash
scoutx doctor
```

This shows every tool categorized by type (core, extended, osint, sast, system) with install status.

### Auto-Install All Missing Tools

```bash
scoutx doctor --install all
```

ScoutX detects your OS (Linux/Windows/macOS) and runs the appropriate install commands:
- **Go tools** → `go install` (subfinder, httpx, nuclei, etc.)
- **Python tools** → `pip install` (semgrep, waymore, arjun, etc.)
- **npm tools** → `npm install -g` (retire, eslint, etc.)
- **System tools** → `apt install` (Linux) or `choco install` (Windows)

### Install by Category

```bash
scoutx doctor --install core       # Essential PD tools (subfinder, httpx, nuclei, etc.)
scoutx doctor --install extended   # Additional Go tools (ffuf, gau, katana, etc.)
scoutx doctor --install osint      # OSINT tools (whois, theHarvester, shodan, etc.)
scoutx doctor --install sast       # Static analysis (semgrep, retire, eslint, etc.)
scoutx doctor --install system     # System tools (nmap, feroxbuster, etc.)
```

### How It Works

1. `scoutx doctor` scans your PATH for each tool using `shutil.which()`
2. Missing tools are listed with their install commands
3. `--install all` runs the async installer which:
   - Detects your platform (Linux/Windows)
   - Checks for Go, pip, npm, apt/choco prerequisites
   - Installs tools in parallel using `asyncio.subprocess`
   - Verifies each installation succeeded

---

## All 21 Plugins

ScoutX ships with 21 built-in plugins organized into 8 execution phases. Plugins in the same phase run **concurrently**. Dependencies are resolved via topological sort.

| Phase | Plugin | Version | Description |
|-------|--------|---------|-------------|
| 1 | `subdomains` | v0.3.0 | Passive enum from 12 sources + active brute-force (aggressive mode) |
| 1 | `osint` | v0.1.0 | WHOIS, DNS records (7 types), ASN discovery, email harvesting, SPF/DMARC |
| 2 | `probe` | v0.2.0 | HTTP probing, tech fingerprint, WAF detection, CDN, favicon MMH3 hash |
| 2 | `ports` | v0.1.0 | Async TCP port scanning (top 100/1000) with service detection |
| 2 | `ssl_analysis` | v0.1.0 | SSL/TLS certificate analysis, expiry, chain validation |
| 3 | `js` | v0.1.0 | JavaScript file discovery, download, and initial analysis |
| 3 | `cors` | v0.1.0 | CORS misconfiguration testing (6 attack scenarios) |
| 3 | `takeover` | v0.1.0 | Subdomain takeover detection (24 services with fingerprints) |
| 3 | `parameters` | v0.1.0 | URL parameter discovery from Wayback Machine & OTX |
| 3 | `screenshots` | v0.1.0 | Full-page screenshots via Playwright |
| 3 | `directories` | v0.1.0 | Directory brute-force (ffuf/feroxbuster/built-in) + sensitive files |
| 3 | `cloud` | v0.1.0 | ☁️ Cloud asset discovery — AWS, GCP, Azure, Cloudflare, Vercel, Netlify |
| 3 | `api_discovery` | v0.1.0 | 🔍 API schema discovery — OpenAPI, Swagger, GraphQL introspection |
| 4 | `endpoints` | v0.1.0 | Endpoint extraction from downloaded JS files |
| 4 | `secrets` | v0.2.0 | 35+ regex patterns, Shannon entropy, JWT decode, S3 verify, GitHub hunting |
| 4 | `js_deep` | v0.1.0 | Source maps, webpack chunks, obfuscation detection, SAST (semgrep/retire) |
| 4 | `historical` | v0.1.0 | 📜 Wayback Machine URLs + SecurityTrails historical DNS records |
| 4 | `github_dork` | v0.1.0 | 🐙 GitHub dorking — find leaked credentials in public repositories |
| 5 | `intelligence` | v0.1.0 | Risk scoring (0-100), attack campaigns, priority queue |
| 5 | `nuclei` | v0.1.0 | Template-based vuln scanning with smart template selection |
| 6 | `attack_chains` | v0.1.0 | ⛓️ Attack chains with CVSS v3.1 scoring + AI narrative generation |

### Plugin Details

#### `subdomains` — Passive + Active Discovery
- **12 passive sources**: crt.sh, AlienVault OTX, URLScan, RapidDNS, HackerTarget, WebArchive, Anubis, SecurityTrails, Shodan, VirusTotal, Censys, DNSDB
- **Active mode** (aggressive profile): DNS brute-force via puredns, permutation generation with gotator/alterx, external subfinder integration
- DNS resolution for all discovered subdomains

#### `osint` — Passive Intelligence Gathering
- WHOIS lookup with registrar, dates, nameservers, org info
- DNS records: A, AAAA, MX, NS, TXT, SOA, CNAME
- ASN discovery via BGPView API
- Email pattern harvesting (common prefixes)
- Email security analysis: SPF, DMARC, DKIM with issue detection

#### `probe` — HTTP Probing & Fingerprinting
- Alive host detection with status codes, titles, content length
- Technology fingerprinting (16 frameworks: nginx, Apache, WordPress, React, Next.js, Laravel, etc.)
- WAF detection (14 WAFs: Cloudflare, AWS WAF, Sucuri, Imperva, Wordfence, etc.)
- CDN identification (Cloudflare, CloudFront, Fastly, etc.)
- Favicon MMH3 hash for Shodan pivoting
- External wafw00f integration for enhanced WAF detection

#### `secrets` — Deep Secret Hunting
- 35+ regex patterns (AWS, Google, GitHub, Stripe, Slack, JWT, private keys, etc.)
- Shannon entropy detection for high-entropy strings
- JWT token automatic decoding with payload extraction
- S3 bucket reference verification (public access check)
- GitHub org secret hunting via `gh` CLI
- Smart false positive suppression

#### `directories` — Path Discovery
- **ffuf** wrapper with built-in wordlist
- **feroxbuster** fallback
- **Built-in async scanner** (no external tools needed)
- Sensitive file detection (.env, .git/config, backup.sql, etc.)
- 70+ built-in path checks covering admin panels, APIs, configs, backups

#### `js_deep` — JavaScript Deep Analysis
- Source map detection and accessibility verification
- Webpack/bundler chunk discovery and entry point identification
- Obfuscation detection (eval, atob, hex variables, bracket notation)
- SAST via semgrep (1000+ JavaScript rules)
- Vulnerable library detection via retire.js
- Deep secret patterns (JWT, internal IPs, S3 buckets, Firebase, connection strings, private keys)

#### `intelligence` — Risk Assessment
- Host scoring (0-100) based on tech stack, open ports, findings
- Attack campaign generation (what to test, in what order)
- Priority queue (which hosts to focus on first)
- Technology intelligence aggregation across all plugins

#### `attack_chains` — Attack Playbook Generation
- 10 attack pattern detectors (see [Attack Chain Engine](#attack-chain-engine))
- 88-check vulnerability checklist across 14 categories
- Markdown/HTML/JSON playbook output
- Step-by-step manual verification instructions

---

## All 52 External Tools

ScoutX integrates with 52 external tools. All are **optional** — ScoutX works with built-in fallbacks, but external tools dramatically improve results.

### Core (9 tools) — ProjectDiscovery Suite
| Tool | Description | Install |
|------|-------------|---------|
| subfinder | Passive subdomain discovery (40+ sources) | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| httpx | Web server probing and fingerprinting | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| nuclei | Template-based vulnerability scanner | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| naabu | Fast port scanner | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| katana | Web crawler | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| dnscoutx | DNS toolkit | `go install github.com/projectdiscovery/dnscoutx/v2/cmd/dnscoutx@latest` |
| tlscoutx | TLS data grabber | `go install github.com/projectdiscovery/tlscoutx/cmd/tlscoutx@latest` |
| alterx | Subdomain wordlist generator | `go install github.com/projectdiscovery/alterx/cmd/alterx@latest` |
| uncover | Shodan/Censys/FOFA search | `go install github.com/projectdiscovery/uncover/cmd/uncover@latest` |

### Extended (16 tools) — Discovery & Analysis
| Tool | Description |
|------|-------------|
| ffuf | Web fuzzer for directory/file discovery |
| puredns | DNS brute-forcing with wildcard filtering |
| gowitness | Screenshot capture |
| hakrawler | Web crawler |
| gotator | Subdomain permutation |
| gau | Fetch URLs from Wayback/OTX/CC |
| waybackurls | Historical URLs |
| anew | Deduplicate lines |
| unfurl | URL parser |
| subjs | JS file extractor |
| jsluice | JS AST parser for URLs and secrets |
| sourcemapper | Reconstruct source from .map files |
| mantra | Regex secret/endpoint extractor |
| assetfinder | Subdomain discovery |
| gospider | Fast web spider |
| getJS | Extract JS file URLs |

### OSINT (13 tools) — Intelligence
| Tool | Description |
|------|-------------|
| theHarvester | Email, subdomain, name harvester |
| dnstwist | Typosquatting domain scanner |
| checkdmarc | SPF/DKIM/DMARC validator |
| waymore | Wayback/URLScan/OTX fetcher |
| arjun | HTTP parameter discovery |
| shodan | Shodan CLI |
| trufflehog | Git secret finder |
| gitleaks | Git repository secret scanner |
| whois | WHOIS lookup |
| dig | DNS query utility |
| gh | GitHub CLI for org recon |
| git-dumper | Dump exposed .git directories |
| LinkFinder | JS endpoint discovery |

### SAST (6 tools) — Static Analysis
| Tool | Description |
|------|-------------|
| semgrep | Lightweight SAST (1000+ rules) |
| retire | Vulnerable JS library detection |
| eslint | JS linter with security plugin |
| nodejsscan | Node.js security scanner |
| graudit | Grep-based source auditing |
| jshint | JS static analysis |

### System (8 tools)
| Tool | Description |
|------|-------------|
| nmap | Network port scanner |
| masscan | High-speed TCP scanner |
| whatweb | Web technology fingerprinter |
| feroxbuster | Recursive directory brute-forcer |
| wafw00f | WAF detection |
| go | Go language runtime (for Go tools) |
| dirsearch | Web path discovery |
| seclists | SecLists wordlists collection |

---

## Scan Profiles

| Profile | Concurrency | Rate Limit | Port Range | Active Recon | Use Case |
|---------|-------------|------------|------------|-------------|----------|
| `safe` | Low | Conservative | Top 100 | ❌ No | Bug bounty programs with strict rules |
| `balanced` | Medium | Standard | Top 100 | ❌ No | General recon (default) |
| `aggressive` | High | Minimal | Top 1000 | ✅ Yes | Authorized pentests only |
| `passive` | None | N/A | N/A | ❌ No | OSINT only — zero active requests |
| `quick` | Low | Standard | Top 100 | ❌ No | Fast ~60s scan: subdomains + probe + ports |

**Aggressive mode** unlocks:
- Active subdomain brute-forcing (puredns + gotator/alterx permutations)
- Higher concurrency limits
- Top 1000 port scanning
- Deeper crawling depth

**Passive mode** runs only: `subdomains`, `osint`, `intelligence`, `historical`, `github_dork`
**Quick mode** runs only: `subdomains`, `probe`, `ports`

```bash
# Safe — for strict bug bounty programs
scoutx scan target.com --profile safe

# Balanced — general purpose (default)
scoutx scan target.com --profile balanced

# Aggressive — authorized pentests only
scoutx scan target.com --profile aggressive

# Passive — OSINT only, zero network touches
scoutx scan target.com --passive

# Quick — fast surface scan (~60s)
scoutx scan target.com --quick
```

---

## Attack Chain Engine

After reconnaissance, ScoutX automatically analyzes findings and generates **attack chains** — step-by-step playbooks with CVSS v3.1 scoring and optional AI-generated narratives.

### How It Works

1. **Pattern Detection** — 13 detectors scan all plugin results for exploitable patterns:

| Detector | What It Finds |
|----------|--------------|
| Subdomain Takeover | Dangling CNAME records pointing to unclaimed services |
| CORS Misconfiguration | Wildcard origins, null origin, credential leaks |
| Exposed Secrets | API keys, JWT tokens, database URLs in JS/HTML |
| Open Databases | MongoDB, Redis, Elasticsearch exposed on public ports |
| Internal Endpoints | Admin panels, debug routes, staging environments |
| Tech Stack CVEs | Known vulnerabilities in detected technologies |
| Nuclei Exploits | Confirmed vulnerabilities from nuclei scan |
| SSRF Candidates | URL parameters accepting external URLs |
| Auth Bypass | Default credentials, JWT with none algorithm |
| SQLi Candidates | Error-based SQL patterns in responses |
| **Cloud Misconfig** | **Exposed S3 buckets, public cloud assets, misconfigured storage** |
| **API Exposure** | **OpenAPI/Swagger docs, GraphQL introspection in production** |
| **GitHub Code Leaks** | **Leaked credentials and configs found via GitHub dorking** |

2. **CVSS v3.1 Scoring** — Each chain gets an auto-calculated CVSS base score and vector string
3. **Chain Building** — Findings are connected into attack chains showing the full exploitation path:
   - Each chain has a severity (critical/high/medium/low) + CVSS score
   - Steps include the technique, target, tool to use, and expected evidence
   - Verification commands are provided for manual confirmation
4. **AI Narration** (optional) — If an AI provider is configured, chains get natural-language exploitation narratives

3. **Vulnerability Checklist** — 88 checks across 14 categories mapped from the master checklist:

| Category | Checks | Examples |
|----------|--------|---------|
| Authentication | 8 | Default creds, JWT bypass, session fixation |
| Authorization | 6 | IDOR, privilege escalation, forced browsing |
| Injection | 7 | SQLi, XSS, SSTI, command injection |
| SSRF | 5 | URL parameters, redirect chains |
| File Upload | 4 | Extension bypass, content-type, path traversal |
| Cryptography | 5 | Weak TLS, missing HSTS, bad algorithms |
| API Security | 6 | Rate limiting, mass assignment, GraphQL introspection |
| Information Disclosure | 8 | Stack traces, .env, .git, debug endpoints |
| Session Management | 5 | Cookie flags, token entropy, fixation |
| CORS | 4 | Origin reflection, null, credentials |
| Business Logic | 5 | Price manipulation, race conditions |
| Cloud/Infra | 6 | S3 buckets, metadata endpoints, open ports |
| Client-Side | 4 | DOM XSS, postMessage, WebSocket |
| Supply Chain | 5 | Outdated libs, subresource integrity |

4. **Playbook Output** — Generated as Markdown, HTML, or JSON in `results/<target>/attack_chains/`

### Example Playbook Output

Each chain in the playbook includes:

- ✅ **Full exploitation commands** in bash code blocks (not truncated)
- ⚖️ **"Is This Real or Informational?"** triage decision table
- 📋 **"Before You Submit"** checklist to prevent false positive reports
- 🛡️ **5-step remediation** guide
- 🔗 **References** to OWASP and KeyHacks

```
### 🟠 Chain #8: [HIGH] Exposed Google API Key → Potential Account Takeover

| Field | Value |
|-------|-------|
| Confidence | **70%** |
| Category | credential_exposure |
| Target | `https://www.example.com/_next/static/chunks/pages/_app.js` |

#### 🔬 Step-by-Step Exploitation & Validation

**Step 1: Locate the Google API Key in source code**

    grep -n 'AIzaSyCF5xmyzDGWYpa2' https://www.example.com/_app.js

✅ Expected if vulnerable: Should find the secret at line 1

**Step 2: Test Google API key validity**

    curl -s 'https://maps.googleapis.com/maps/api/geocode/json?address=test&key=AIzaSyCF...' | python3 -m json.tool

✅ Expected if vulnerable: status: 'OK' = key is live

**Step 3: Enumerate enabled Google APIs**

    curl -s 'https://www.googleapis.com/customsearch/v1?key=AIzaSyCF...&q=test'
    curl -s 'https://translation.googleapis.com/language/translate/v2?key=AIzaSyCF...&q=hello&target=es'

✅ Expected if vulnerable: Any 200 response = billable to key owner

#### ⚖️ Is This Real or Informational?

| Question | If YES → | If NO → |
|----------|----------|---------|
| Does the secret look real? | Likely real — validate | Probably placeholder |
| Can you auth to a service? | CONFIRMED — report HIGH | Revoked/expired — lower |
| Write/admin permissions? | CRITICAL — full compromise | Read-only — lower impact |

#### 📋 Before You Submit

- [ ] Completed all validation steps above
- [ ] Captured screenshots/responses as evidence
- [ ] Confirmed this is NOT a false positive
- [ ] Impact is clear
- [ ] Wrote reproduction steps someone else can follow
```

---

## 10-Phase Methodology

ScoutX follows a structured 10-phase methodology based on the Elite Recon Framework:

| Phase | Name | Plugin | Key Tools |
|-------|------|--------|-----------|
| 01 | OSINT & Passive Intelligence | `osint` | whois, dig, theHarvester, dnstwist, checkdmarc |
| 02 | Infrastructure Mapping | `osint` | shodan, uncover, tlscoutx |
| 03 | Passive Subdomain Discovery | `subdomains` | subfinder, assetfinder, tlscoutx |
| 04 | Active Subdomain Brute-Force | `subdomains` | puredns, gotator, alterx, dnscoutx |
| 05 | HTTP Probing & Tech Fingerprint | `probe` | httpx, whatweb, wafw00f, gowitness |
| 06 | Port Scanning & Service Enum | `ports` | naabu, nmap, masscan |
| 07 | URL & Endpoint Discovery | `endpoints` | gau, waybackurls, katana, hakrawler, gospider, waymore, arjun |
| 08 | JS Deep Analysis | `js_deep` | subjs, getJS, jsluice, sourcemapper, mantra, LinkFinder, semgrep, retire |
| 09 | Directory & File Discovery | `directories` | ffuf, feroxbuster, dirsearch, seclists, git-dumper |
| 10 | Secret & Credential Hunting | `secrets` | trufflehog, gitleaks, gh |

### Check Methodology Readiness

```bash
scoutx doctor
```

This shows which tools are available for each methodology phase and what's missing.

---

## CLI Reference

### Scanning

```bash
scoutx scan <target>                    # Full scan with all plugins
scoutx scan <target> --profile safe     # Conservative scan
scoutx scan <target> --profile aggressive  # Full power with active techniques
scoutx full <target>                    # Alias for scan
scoutx resume <target>                  # Resume interrupted scan
```

### Scope Management

```bash
scoutx scope add <target>               # Add target to scope
scoutx scope list                       # List all scoped targets
scoutx scope remove <target>            # Remove from scope
```

### Tool Management

```bash
scoutx doctor                           # Check all tool status
scoutx doctor --install all             # Install everything
scoutx doctor --install core            # Install core PD tools only
scoutx doctor --install extended        # Install extended tools
```

### Plugin Management

```bash
scoutx plugin list                      # List all 17 plugins with status
scoutx plugin info <name>               # Show plugin details and dependencies
scoutx plugin install <git-url>         # Install community plugin
scoutx plugin uninstall <name>          # Remove installed plugin
```

### Comparison

```bash
scoutx diff <scan_dir_1> <scan_dir_2>   # Compare two scan results
scoutx diff <dir1> <dir2> --format json # JSON diff output
```

### Web Dashboard

```bash
scoutx dashboard                        # Start web dashboard on localhost:8000
```

### Configuration

```bash
scoutx config                           # Show resolved configuration
```

---

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| HTML | `--format html` | Dark-themed interactive report |
| Markdown | `--format md` | Git-friendly, README-compatible |
| CSV | `--format csv` | Spreadsheet analysis |
| SARIF | `--format sarif` | GitHub Security tab integration |
| PDF | `--format pdf` | Professional PDF (requires weasyprint or playwright) |
| **Obsidian** | `--format obsidian` | **Obsidian vault with YAML frontmatter + wiki-links** |
| JSON | `--format json` | Raw structured data |

All outputs are saved to `results/<target>/`:

```
results/example.com/
├── subdomains/
│   ├── subdomains.txt          # One per line
│   ├── subdomains.json         # Full data with sources
│   └── subdomains.jsonl        # Streaming format
├── osint/
│   └── osint.json              # WHOIS, DNS, ASN, email
├── probe/
│   ├── alive.txt               # Alive URLs
│   ├── probe.json              # Full probe data
│   └── probe.jsonl
├── ports/
│   └── ports.json
├── js/
│   ├── js_files/               # Downloaded JS files
│   └── js.json
├── js_deep/
│   ├── js_deep.json            # Source maps, SAST, secrets
│   └── reconstructed/          # Reconstructed source from .map files
├── secrets/
│   ├── secrets.json            # All findings with severity
│   └── secrets.jsonl
├── directories/
│   └── directories.json        # Discovered paths
├── intelligence/
│   ├── intelligence.json       # Risk scores, campaigns
│   └── intelligence.md         # Human-readable report
├── attack_chains/
│   ├── playbook.md             # Attack chain playbook
│   ├── playbook.html           # HTML version
│   ├── chains.json             # Machine-readable
│   └── checklist.md            # 88-check vuln checklist
└── reports/
    ├── report.html
    ├── report.md
    ├── report.csv
    └── report.sarif
```

---

## AI Integration

ScoutX supports **8 LLM providers** for AI-powered analysis narratives. AI is optional — ScoutX works fully without it.

### Supported Providers

| Provider | Config Value | Notes |
|----------|-------------|-------|
| Ollama | `ollama` | Local, private, no API key needed |
| OpenAI | `openai` | GPT-4o, GPT-4, GPT-3.5 |
| Claude | `claude` | Anthropic Claude 3.5/4 |
| DeepSeek | `deepseek` | Cost-effective, via OpenAI-compat |
| Groq | `groq` | Ultra-fast inference |
| Grok | `grok` | xAI's model |
| OpenRouter | `openrouter` | Access 100+ models |
| Custom | `custom` | Any OpenAI-compatible endpoint |

### Configuration

In `scoutx.yaml`:

```yaml
ai:
  provider: ollama          # or openai, claude, deepseek, groq, etc.
  model: llama3.2           # model name
  api_key: ""               # API key (not needed for ollama)
  base_url: ""              # custom endpoint (auto-detected for known providers)
```

Or via environment variables:

```bash
export SCOUTX_AI_PROVIDER=openai
export SCOUTX_AI_MODEL=gpt-4o
export SCOUTX_AI_API_KEY=sk-...
```

When AI is configured, attack chains get **natural-language exploitation narratives** — pentester-style write-ups generated from raw chain data.

---

## Ghost Mode (Stealth)

Built-in stealth engine for responsible scanning:

- **Adaptive rate limiting** — Backs off on 429/503 responses automatically
- **Proxy rotation** — Round-robin proxy support
- **Random user agents** — 20+ real browser fingerprints
- **Realistic headers** — Accept, Accept-Language, Accept-Encoding
- **Per-host throttling** — Independent cooldown per target

```yaml
# scoutx.yaml
stealth:
  rate_limit:
    requests_per_second: 5
    backoff_on_429: true
  proxies:
    - "http://proxy1:8080"
    - "socks5://proxy2:1080"
```

---

## Web Dashboard

ScoutX includes a built-in dark-themed web dashboard for browsing scan results:

```bash
scoutx dashboard
# Opens on http://localhost:8000
```

Features:
- Scan list sidebar with target overview
- Subdomain, port, endpoint, and secret tables
- Risk score display from intelligence
- Real-time scan data loading

---

## Python API

Use ScoutX programmatically:

```python
from scoutx.api import ScoutX

sx = ScoutX(profile="balanced")

# Full scan
result = await sx.scan("example.com")
print(f"Found {result.total_subdomains} subdomains")
print(f"Risk score: {result.risk_score}")

# Specific plugins only
result = await sx.scan_plugins("example.com", plugins=["subdomains", "probe"])

# List available plugins
plugins = sx.list_plugins()
```

---

## Docker

### Build

```bash
docker build -t scoutx .
```

### Run

```bash
docker run --rm -v $(pwd)/results:/app/results scoutx scan example.com
```

### Docker Compose

```bash
docker-compose run scoutx scan example.com
```

The Docker image comes with Go 1.22+ and core ProjectDiscovery tools pre-installed.

---

## Architecture

```
scoutx scan target.com
    │
    ▼
[Phase 1: Discovery]       subdomains (12 sources + active brute-force)
                            osint (WHOIS / DNS / ASN / email)
    │
    ▼
[Phase 2: Enumeration]     probe (tech / WAF / CDN / favicon hash)
                            ports (naabu / nmap)
                            ssl_analysis
    │
    ▼
[Phase 3: Analysis]        js + cors + parameters + takeover
                            screenshots + directories
    │
    ▼
[Phase 4: Deep Analysis]   endpoints + secrets (entropy / JWT / S3 / GitHub)
                            js_deep (sourcemaps / SAST / webpack)
    │
    ▼
[Phase 5: Assessment]      intelligence (risk scoring 0-100)
                            nuclei (template-based vuln scan)
    │
    ▼
[Phase 6: Attack Chains]   attack_chains (10 detectors + 88-check playbook)
    │
    ▼
[Reports]                   HTML + MD + CSV + SARIF + PDF
```

Plugins within the same phase run **concurrently**. Dependencies are resolved via topological sort. The engine manages shared state through `ScanContext` — each plugin reads prior results with `context.result_data("plugin_name")`.

---

## Writing Custom Plugins

See [docs/PLUGINS.md](docs/PLUGINS.md) for the full guide. Quick version:

```python
from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin

class Plugin(ScoutPlugin):
    meta = PluginMeta(
        name="my_scanner",
        description="Does something cool",
        version="1.0.0",
        author="you",
        tags=["analysis"],
    )
    depends_on = ["probe"]  # Runs after probe

    async def run(self, context):
        # Access prior plugin results
        hosts = context.result_data("probe").get("alive_hosts", [])

        findings = []
        for host in hosts:
            # ... your logic ...
            findings.append({"url": host["url"], "issue": "found something"})

        return PluginResult.completed(
            data={"findings": findings},
            findings_count=len(findings),
        )

    def schema(self):
        return ResultSchema(
            fields={"findings": list},
            description="My custom findings",
        )
```

Place your plugin in `scoutx/plugins/builtin/my_scanner/` with an `__init__.py` and it'll be auto-discovered.

### Install Community Plugins

```bash
scoutx plugin install https://github.com/someone/scoutx-plugin-example.git
scoutx plugin list
scoutx plugin uninstall plugin-name
```

---

## Notifications

Configure real-time alerts in `scoutx.yaml`:

```yaml
notifications:
  slack:
    webhook_url: "https://hooks.slack.com/services/..."
    events: [scan_completed, critical_finding, secret_detected]
  discord:
    webhook_url: "https://discord.com/api/webhooks/..."
  webhook:
    url: "https://your-server.com/webhook"
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Dev setup
git clone https://github.com/GENESIS-PROKEY/ScoutX.git
cd ScoutX
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Lint
ruff check scoutx/
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

Built by **GENESIS-PROKEY** ⚡
