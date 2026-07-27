# Plugin Development Guide

ScoutX uses a plugin architecture where every scanner is a self-contained module that implements the `PhantomPlugin` interface. This guide shows you how to build your own.

---

## Plugin Interface

Every plugin must:
1. Subclass `PhantomPlugin`
2. Define metadata (`name`, `description`, `version`, `author`)
3. Declare dependencies (`depends_on`)
4. Implement `async def run(self, context: ScanContext) -> PluginResult`
5. Implement `def schema(self) -> ResultSchema`

```python
from __future__ import annotations
from scoutx.plugins.base import PhantomPlugin, PluginResult, ResultSchema
from scoutx.core.engine import ScanContext

class Plugin(PhantomPlugin):
    name = "my_scanner"
    description = "Scans for something interesting"
    version = "1.0.0"
    author = "your_name"
    depends_on = ["probe"]  # This plugin needs probe results

    async def run(self, context: ScanContext) -> PluginResult:
        # Get data from a dependency
        probe_data = context.result_data("probe")
        hosts = probe_data.get("hosts", [])

        if not hosts:
            return PluginResult.skipped("No hosts to scan")

        # Your scanning logic here
        findings = []
        for host in hosts:
            hostname = host.get("hostname", "")
            # ... do something ...
            findings.append({"host": hostname, "finding": "something"})

        # Save results
        from scoutx.utils.io import write_json
        output_dir = context.output_dir / "my_scanner"
        output_dir.mkdir(parents=True, exist_ok=True)
        write_json(output_dir / "results.json", {"findings": findings})

        return PluginResult.completed(
            data={"findings": findings},
            findings_count=len(findings),
            artifacts=[output_dir / "results.json"],
        )

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={"findings": list},
            description="My scanner findings",
        )
```

---

## Plugin Directory Structure

```
scoutx/plugins/builtin/my_scanner/
    __init__.py       # Exports the Plugin class
    plugin.py         # Plugin implementation
    helpers.py        # Optional helper functions
```

### __init__.py

```python
from scoutx.plugins.builtin.my_scanner.plugin import Plugin

__all__ = ["Plugin"]
```

---

## Plugin Lifecycle

1. **Discovery** — The `PluginManager` scans `scoutx/plugins/builtin/` for directories containing a `Plugin` class
2. **Registration** — Plugins are registered with their metadata and dependencies
3. **Phase Assignment** — The engine builds a dependency graph and assigns plugins to execution phases via topological sort
4. **Execution** — Plugins within the same phase run concurrently
5. **Result Storage** — Results are stored in `context._results` and accessible to downstream plugins

---

## ScanContext API

The `context` object passed to `run()` provides:

| Property | Type | Description |
|----------|------|-------------|
| `context.target` | `str` | Target domain |
| `context.scan_id` | `str` | Unique scan identifier |
| `context.config` | `ScanConfig` | Scan configuration |
| `context.output_dir` | `Path` | Base output directory |
| `context.result_data(plugin_name)` | `dict` | Get another plugin's results |

---

## PluginResult

Three factory methods:

```python
# Success — scan completed, here's the data
PluginResult.completed(data={"key": "value"}, findings_count=5, artifacts=[path])

# Skip — nothing to do (not an error)
PluginResult.skipped("No hosts matched the filter")

# Failure — something went wrong
PluginResult.failed("Connection timeout after 30s")
```

---

## Dependencies

Use `depends_on` to declare which plugins must run before yours:

```python
class Plugin(PhantomPlugin):
    depends_on = ["subdomains", "probe"]  # Needs both
```

The engine automatically:
- Places your plugin in a phase AFTER all dependencies
- Makes dependency data available via `context.result_data()`
- Skips your plugin if a dependency failed

---

## Configuration Access

Plugins can read scan configuration:

```python
async def run(self, context):
    config = context.config
    concurrency = config.get("my_scanner.concurrency", 10)
    timeout = config.get("my_scanner.timeout", 30)
```

Users configure plugins in `scoutx.yaml`:

```yaml
plugins:
  my_scanner:
    concurrency: 20
    timeout: 60
```

---

## Logging and Output

Use the UI helpers for console output:

```python
from scoutx.cli.ui import info, success, warn, error

info("Scanning 10 hosts...")          # >  Scanning 10 hosts...
success("Found 5 findings")          # +  Found 5 findings
warn("Rate limited, backing off")    # !  Rate limited, backing off
error("Connection failed")           # x  Connection failed
```

Use Python's `logging` module for debug output:

```python
import logging
logger = logging.getLogger(__name__)
logger.debug("Processing host: %s", hostname)
```

---

## Testing Your Plugin

```python
import pytest
from scoutx.plugins.builtin.my_scanner.plugin import Plugin

def test_plugin_metadata():
    p = Plugin()
    assert p.name == "my_scanner"
    assert "probe" in p.depends_on

@pytest.mark.asyncio
async def test_plugin_skips_on_no_hosts():
    # Create a mock context
    from unittest.mock import MagicMock
    ctx = MagicMock()
    ctx.result_data.return_value = {"hosts": []}
    result = await Plugin().run(ctx)
    assert result.status == "skipped"
```
