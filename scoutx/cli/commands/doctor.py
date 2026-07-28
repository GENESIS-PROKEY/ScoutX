"""scoutx doctor — Self-diagnostic command with full tool registry integration.

Checks Python environment, dependencies, Playwright, AND all 40+ external
recon tools from the Elite Methodology. Supports --install to auto-install
missing tools.
"""
from __future__ import annotations

import asyncio
import sys
from importlib.metadata import version as pkg_version
from typing import Optional

import typer
from rich import box
from rich.table import Table

from scoutx.cli.ui import BRAND_PRIMARY, console, error, info, success, warn

doctor_app = typer.Typer(help="Diagnose your ScoutX installation.")


def _check_python() -> bool:
    """Verify Python version >= 3.10."""
    major, minor = sys.version_info[:2]
    ver = f"{major}.{minor}.{sys.version_info.micro}"
    if (major, minor) >= (3, 10):
        success(f"Python {ver}")
        return True
    error(f"Python {ver} -- need 3.10+")
    return False


def _check_dependency(name: str, import_name: str | None = None) -> bool:
    """Check if a Python package is installed."""
    try:
        ver = pkg_version(name)
        success(f"{name} {ver}")
        return True
    except Exception:
        try:
            __import__(import_name or name)
            success(f"{name} (version unknown)")
            return True
        except ImportError:
            error(f"{name} -- NOT INSTALLED")
            return False


def _check_playwright_browsers() -> bool:
    """Check if Playwright browsers are installed."""
    try:
        import subprocess

        from playwright.sync_api import sync_playwright  # noqa: F401
        result = subprocess.run(
            [sys.executable, "-m", "playwright", "install", "--dry-run"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            success("Playwright browsers installed")
            return True
        else:
            warn("Playwright browsers not installed -- run: playwright install chromium")
            return False
    except ImportError:
        warn("Playwright not installed -- screenshots will be skipped")
        return False
    except Exception:
        warn("Could not verify Playwright browser status")
        return False


def _show_tool_registry():
    """Display the full tool registry with install status."""
    from scoutx.tools.registry import get_by_category

    categories = get_by_category()
    cat_labels = {
        "core": "Core (ProjectDiscovery)",
        "extended": "Extended Recon",
        "osint": "OSINT & Intelligence",
        "sast": "SAST & Static Analysis",
        "system": "System Tools",
    }

    for cat_name, tools in categories.items():
        label = cat_labels.get(cat_name, cat_name.title())
        installed = sum(1 for _, s in tools if s)
        total = len(tools)

        table = Table(
            title=f"  {label} ({installed}/{total})",
            box=box.SQUARE,
            show_header=True,
            header_style=f"bold {BRAND_PRIMARY}",
            title_style=f"bold {BRAND_PRIMARY}",
            min_width=60,
        )
        table.add_column("Tool", style="bold")
        table.add_column("Status", width=10)
        table.add_column("Description")

        for tool, is_installed in tools:
            status = "[green]OK[/]" if is_installed else "[red]MISSING[/]"
            table.add_row(tool.name, status, tool.description)

        console.print(table)
        console.print()


@doctor_app.callback(invoke_without_command=True)
def doctor(
    install: Optional[str] = typer.Option(
        None, "--install",
        help="Install missing tools. Values: all, core, extended, osint, sast, system"
    ),
):
    """Run self-diagnostics and optionally install missing tools."""
    console.print()
    console.print(
        f"  [{BRAND_PRIMARY}]ScoutX Doctor[/] -- Checking your environment...",
        highlight=False,
    )
    console.print()

    results: list[bool] = []

    # Python
    console.print(f"  [{BRAND_PRIMARY}]Runtime[/]")
    results.append(_check_python())

    # Core dependencies
    console.print()
    console.print(f"  [{BRAND_PRIMARY}]Core Dependencies[/]")
    core_deps = [
        ("typer", None),
        ("rich", None),
        ("httpx", None),
        ("PyYAML", "yaml"),
        ("Jinja2", "jinja2"),
        ("beautifulsoup4", "bs4"),
        ("pydantic", None),
    ]
    for name, imp in core_deps:
        results.append(_check_dependency(name, imp))

    # Optional dependencies
    console.print()
    console.print(f"  [{BRAND_PRIMARY}]Optional Dependencies[/]")
    optional_deps = [
        ("playwright", None),
        ("aiosqlite", None),
        ("sqlalchemy", None),
    ]
    for name, imp in optional_deps:
        _check_dependency(name, imp)

    # Playwright browsers
    console.print()
    console.print(f"  [{BRAND_PRIMARY}]Browsers[/]")
    _check_playwright_browsers()

    # Prerequisites
    console.print()
    console.print(f"  [{BRAND_PRIMARY}]Prerequisites[/]")
    from scoutx.tools.installer import ToolInstaller
    installer = ToolInstaller()
    prereqs = installer.check_prerequisites()
    for name, available in prereqs.items():
        if available:
            success(f"{name} available")
        else:
            warn(f"{name} not found")

    # Full tool registry
    console.print()
    _show_tool_registry()

    # Config check
    console.print(f"  [{BRAND_PRIMARY}]Configuration[/]")
    from pathlib import Path
    config_path = Path("scoutx.yaml")
    if config_path.exists():
        success(f"Config found: {config_path.resolve()}")
    else:
        info("No scoutx.yaml found (using defaults)")

    # Summary
    console.print()
    from scoutx.tools.registry import check_all
    tool_status = check_all()
    installed_count = sum(1 for v in tool_status.values() if v)
    total_tools = len(tool_status)
    console.print(
        f"  [bold]External Tools: {installed_count}/{total_tools} installed[/]"
    )

    passed = sum(results)
    total = len(results)
    if all(results):
        console.print(f"  [bold green]All {total} core checks passed. ScoutX is ready.[/]")
    else:
        failed = total - passed
        console.print(f"  [bold yellow]{passed}/{total} core checks passed, {failed} failed.[/]")
    console.print()

    # Handle --install
    if install:
        console.print(f"  [{BRAND_PRIMARY}]Installing tools...[/]")
        console.print()

        async def _do_install():
            inst = ToolInstaller()
            if install == "all":
                return await inst.install_all()
            else:
                return await inst.install_category(install)

        install_results = asyncio.run(_do_install())
        for name, ok in install_results.items():
            if ok:
                success(f"Installed: {name}")
            else:
                error(f"Failed: {name}")
        console.print()
