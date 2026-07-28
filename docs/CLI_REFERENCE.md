# ScoutX CLI Reference
> Both `scoutx` and `sx` are valid command names. Use `scoutx` if `sx` conflicts with other tools on your system.

Complete reference for all `scoutx` commands.

---

## Global Options

```
scoutx [OPTIONS] COMMAND [ARGS]
```

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `--no-banner` | Suppress the ASCII banner |
| `--help` | Show help message |

---

## Recon Commands

### scoutx scan

Run the full reconnaissance pipeline. Alias for `scoutx full`.

```
scoutx scan <TARGET> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--profile` | `safe` | Scan profile: `safe`, `balanced`, `aggressive` |
| `--output` | `results/<target>` | Output directory |
| `--resume / --no-resume` | `false` | Resume interrupted scan |
| `--report / --no-report` | `true` | Auto-generate reports |
| `--format` | `html` | Report format: `html`, `md`, `csv`, `sarif` |
| `--notify / --no-notify` | `false` | Send notifications on completion |

**Examples:**

```bash
scoutx scan example.com
scoutx scan example.com --profile aggressive
scoutx scan example.com --format sarif --no-report
```

### scoutx full

Same as `scoutx scan`. Runs the complete async pipeline.

### scoutx resume

Resume an interrupted scan from the last checkpoint.

```
scoutx resume <TARGET> [OPTIONS]
```

---

## Analysis Commands

### scoutx diff

Compare two scan result directories and show changes.

```
scoutx diff <DIR1> <DIR2> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--format` | `text` | Output format: `text`, `json`, `html` |

**Example:**

```bash
scoutx diff results/example.com_20260101 results/example.com_20260201
```

---

## Management Commands

### scoutx scope

Manage target scope definitions.

```
scoutx scope add <TARGET> [OPTIONS]
scoutx scope list
scoutx scope remove <TARGET>
```

| Option | Description |
|--------|-------------|
| `--wildcard` | Include wildcard subdomains |
| `--exclude` | Patterns to exclude |

### scoutx plugin

Manage scanner plugins.

```
scoutx plugin list
scoutx plugin info <NAME>
```

**Example:**

```bash
scoutx plugin list
scoutx plugin info intelligence
```

### scoutx doctor

Run self-diagnostics on your ScoutX installation.

```
scoutx doctor
```

Checks:
- Python version (3.10+)
- Core dependencies (typer, rich, httpx, etc.)
- Optional dependencies (playwright, sqlalchemy)
- Playwright browser binaries
- External tools (nuclei, nmap)
- Configuration file

### scoutx config

Show the resolved configuration (defaults + overrides).

```
scoutx config
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Scan completed with warnings |
| `2` | Scan failed |
| `3` | Configuration error |
