# ScoutX Quick Start Guide

Get scanning in under 2 minutes.

---

## 1. Install

### From PyPI (recommended)

```bash
pip install scoutx
```

### From Source

```bash
git clone https://github.com/lo/ScoutX.git
cd ScoutX
pip install -e .
```

### Docker

```bash
docker build -t scoutx .
docker run --rm -v $(pwd)/results:/app/results scoutx scan example.com
```

---

## 2. Verify Installation

```bash
sx doctor
```

This checks Python version, dependencies, Playwright browsers, and external tools.

---

## 3. Your First Scan

```bash
sx scan example.com
```

ScoutX will:
1. Discover subdomains from 7 passive sources
2. Probe hosts and scan ports concurrently
3. Analyze SSL certificates
4. Check for CORS misconfigurations and subdomain takeover
5. Download and analyze JavaScript files
6. Extract endpoints and scan for leaked secrets
7. Generate an intelligence report with risk scores
8. Save HTML + Markdown reports

---

## 4. Understanding Output

Results are saved to `results/<target>/`:

```
results/example.com/
  subdomains/     # Discovered subdomains
  probe/          # HTTP probe results
  ports/          # Open port data
  ssl/            # Certificate analysis
  js/             # Downloaded JS files
  endpoints/      # Extracted endpoints
  secrets/        # Leaked credentials
  cors/           # CORS test results
  takeover/       # Takeover check results
  intelligence/   # Risk scores + campaigns
  reports/        # HTML, MD, CSV, SARIF
```

---

## 5. Scan Profiles

| Profile | Best For | Command |
|---------|----------|---------|
| `safe` | Bug bounty (won't get you banned) | `sx scan target.com --profile safe` |
| `balanced` | General recon | `sx scan target.com --profile balanced` |
| `aggressive` | Authorized pentests only | `sx scan target.com --profile aggressive` |

---

## 6. Common Commands

```bash
# Full scan with reports
sx scan target.com

# Quick subdomain check
sx full target.com --profile safe

# List all plugins
sx plugin list

# Compare two scans
sx diff results/scan1 results/scan2

# Check your setup
sx doctor
```

---

## 7. Configuration

Create a `scoutx.yaml` in your project directory:

```yaml
profiles:
  safe:
    concurrency: 5
    rate_limit: 2

notifications:
  slack:
    webhook_url: "https://hooks.slack.com/services/..."
    events: [scan_completed, critical_finding]
```

---

## Next Steps

- Read the [Plugin Development Guide](docs/PLUGINS.md) to build custom scanners
- Check the [CLI Reference](docs/CLI_REFERENCE.md) for all commands
- See [CONTRIBUTING.md](CONTRIBUTING.md) to contribute
