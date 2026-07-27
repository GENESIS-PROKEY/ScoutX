# ScoutX CLI Reference

Complete reference for all `sx` commands.

---

## Global Options

```
sx [OPTIONS] COMMAND [ARGS]
```

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `--no-banner` | Suppress the ASCII banner |
| `--help` | Show help message |

---

## Recon Commands

### sx scan

Run the full reconnaissance pipeline. Alias for `sx full`.

```
sx scan <TARGET> [OPTIONS]
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
sx scan example.com
sx scan example.com --profile aggressive
sx scan example.com --format sarif --no-report
```

### sx full

Same as `sx scan`. Runs the complete async pipeline.

### sx resume

Resume an interrupted scan from the last checkpoint.

```
sx resume <TARGET> [OPTIONS]
```

---

## Analysis Commands

### sx diff

Compare two scan result directories and show changes.

```
sx diff <DIR1> <DIR2> [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--format` | `text` | Output format: `text`, `json`, `html` |

**Example:**

```bash
sx diff results/example.com_20260101 results/example.com_20260201
```

---

## Management Commands

### sx scope

Manage target scope definitions.

```
sx scope add <TARGET> [OPTIONS]
sx scope list
sx scope remove <TARGET>
```

| Option | Description |
|--------|-------------|
| `--wildcard` | Include wildcard subdomains |
| `--exclude` | Patterns to exclude |

### sx plugin

Manage scanner plugins.

```
sx plugin list
sx plugin info <NAME>
```

**Example:**

```bash
sx plugin list
sx plugin info intelligence
```

### sx doctor

Run self-diagnostics on your ScoutX installation.

```
sx doctor
```

Checks:
- Python version (3.10+)
- Core dependencies (typer, rich, httpx, etc.)
- Optional dependencies (playwright, sqlalchemy)
- Playwright browser binaries
- External tools (nuclei, nmap)
- Configuration file

### sx config

Show the resolved configuration (defaults + overrides).

```
sx config
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Scan completed with warnings |
| `2` | Scan failed |
| `3` | Configuration error |
