"""ScoutX main CLI application.

Defines the Typer app, command groups, and the branded help screen.
Two entry points: ``sx`` (short) and ``scoutx`` (explicit).
"""
from __future__ import annotations

import io
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from typer.core import TyperGroup

from scoutx import __version__
from scoutx.cli.ui import (
    BRAND_PRIMARY,
    banner_renderable,
    console,
    info,
    ui_box,
)

# ── Command group layout ──────────────────────────────────────────────
COMMAND_GROUPS: dict[str, list[tuple[str, str]]] = {
    "Recon": [
        ("scan", "Start a full recon workflow (alias for full)"),
        ("full", "Run the complete async pipeline"),
        ("resume", "Resume an interrupted scan"),
    ],
    "Analysis": [
        ("report", "Generate HTML / Markdown / PDF reports"),
        ("diff", "Compare two scans and show changes"),
    ],
    "Management": [
        ("scope", "Manage target scope (add / remove / list)"),
        ("plugin", "Manage scanner plugins"),
        ("wordlist", "Manage wordlists (list / download)"),
        ("dashboard", "Start the web dashboard"),
        ("doctor", "Check runtime readiness"),
        ("config", "Show resolved configuration"),
    ],
}

BANNER_DISABLED = False


def _should_hide_banner() -> bool:
    return BANNER_DISABLED or "--no-banner" in sys.argv[1:]


def _terminal_safe(text: str) -> str:
    """Return text printable by the current stdout encoding."""
    encoding = sys.stdout.encoding or "utf-8"
    return text.encode(encoding, errors="replace").decode(encoding, errors="replace")


def _render_root_help(no_banner: bool = False) -> str:
    """Render the custom root help screen."""
    help_console = Console(
        width=console.width,
        file=io.StringIO(),
        record=True,
        force_terminal=console.is_terminal,
        color_system=console.color_system,
        legacy_windows=console.legacy_windows,
    )
    border = ui_box()
    if not no_banner:
        help_console.print(banner_renderable(__version__), end="")
        help_console.print()
    help_console.print("[white]Usage:[/] [cyan]scoutx[/] [white][OPTIONS] COMMAND [ARGS]...[/] (or use [cyan]sx[/])")
    help_console.print("[dim]Async-first reconnaissance framework for attack surface discovery.[/]")
    help_console.print()
    help_console.print(f"[{BRAND_PRIMARY}]Quick Start[/]")
    help_console.print("  [white]scoutx doctor[/]")
    help_console.print("  [white]scoutx scan example.com --profile safe[/]")
    help_console.print("  [white]scoutx report example.com[/]")
    help_console.print("[dim]Tip: `scoutx scan` is an alias for `scoutx full`. You can also use the `sx` alias.[/]")
    help_console.print()

    for group_name, commands in COMMAND_GROUPS.items():
        help_console.print(f"[{BRAND_PRIMARY}]{group_name}[/]")
        table = Table(
            border_style="steel_blue1",
            box=border,
            show_header=True,
            header_style=BRAND_PRIMARY,
            padding=(0, 1),
        )
        table.add_column("Command", style="cyan", no_wrap=True)
        table.add_column("Description", style="white", no_wrap=True)
        for command, description in commands:
            table.add_row(command, description)
        help_console.print(table)
        help_console.print()

    help_console.print("[white]Options:[/]")
    help_console.print("  [cyan]--version[/]   Show ScoutX version and exit")
    help_console.print("  [cyan]--help[/]      Show this help screen and exit")
    help_console.print()
    command_count = sum(len(items) for items in COMMAND_GROUPS.values())
    help_console.print(f"[dim]Python {sys.version.split()[0]} | {command_count} Commands | ScoutX v{__version__}[/]")

    return _terminal_safe(help_console.export_text(styles=help_console.is_terminal))


class ScoutXGroup(TyperGroup):
    """Custom root help renderer."""

    def format_help(self, ctx: typer.Context, formatter: object) -> None:  # type: ignore[override]
        formatter.write(_render_root_help(no_banner=_should_hide_banner()))  # type: ignore[attr-defined]


# ── Typer app ─────────────────────────────────────────────────────────
app = typer.Typer(
    help="ScoutX — Async-first reconnaissance framework.",
    cls=ScoutXGroup,
    rich_markup_mode="rich",
    no_args_is_help=False,
)


# ── Sub-apps (mounted below after command modules are ready) ──────────
scope_app = typer.Typer(help="Manage target scope.", no_args_is_help=True)
plugin_app = typer.Typer(help="Manage scanner plugins.", no_args_is_help=True)
app.add_typer(scope_app, name="scope")
app.add_typer(plugin_app, name="plugin")

from scoutx.cli.commands.dashboard import dashboard_app  # noqa: E402
from scoutx.cli.commands.diff import diff_app  # noqa: E402
from scoutx.cli.commands.doctor import doctor_app  # noqa: E402

app.add_typer(doctor_app, name="doctor")
app.add_typer(diff_app, name="diff")
app.add_typer(dashboard_app, name="dashboard")

# Wordlist management
try:
    from scoutx.cli.commands.wordlist import wordlist_app  # noqa: E402
    app.add_typer(wordlist_app, name="wordlist")
except ImportError:
    pass  # wordlist module not available


# ── Root callback ─────────────────────────────────────────────────────
@app.callback(invoke_without_command=True)
def cli(
    ctx: typer.Context,
    version_flag: bool = typer.Option(False, "--version", help="Show ScoutX version and exit."),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress banner.", hidden=True),
) -> None:
    """ScoutX command-line interface."""
    global BANNER_DISABLED
    BANNER_DISABLED = no_banner
    if version_flag:
        from scoutx.cli.ui import print_module_summary

        print_module_summary("ScoutX", {"Version": __version__, "Python": sys.version.split()[0]})
        raise typer.Exit()
    if any(arg in {"--help", "-h"} for arg in sys.argv[1:]):
        return
    if ctx.invoked_subcommand is None:
        sys.stdout.write(_render_root_help(no_banner=no_banner))
        raise typer.Exit()


# ── Import and register command modules ───────────────────────────────
from scoutx.cli.commands.dashboard import register as register_dashboard  # noqa: E402
from scoutx.cli.commands.plugin import register as register_plugin  # noqa: E402
from scoutx.cli.commands.scan import register as register_scan  # noqa: E402
from scoutx.cli.commands.scope import register as register_scope  # noqa: E402

register_scan(app)
register_scope(scope_app)
register_plugin(plugin_app)
register_dashboard(app)


# ── Inline lightweight commands ───────────────────────────────────────
@app.command()
def doctor(
    output: Path = typer.Option(Path("results"), "-o", "--output", help="Output directory"),
) -> None:
    """Check runtime readiness and dependencies."""
    import shutil

    from scoutx.cli.ui import print_module_summary

    checks: dict[str, str] = {}

    # Python version
    py_ver = sys.version.split()[0]
    py_ok = sys.version_info >= (3, 10)
    checks["Python"] = f"{'[OK]' if py_ok else '[FAIL]'} {py_ver} {'' if py_ok else '(need 3.10+)'}"

    # httpx
    try:
        import httpx
        checks["httpx"] = f"[OK] {httpx.__version__}"
    except ImportError:
        checks["httpx"] = "[FAIL] Not installed"

    # Playwright
    try:
        from importlib.metadata import version as pkg_version

        pw_ver = pkg_version("playwright")
        checks["Playwright"] = f"[OK] {pw_ver}"
    except ImportError:
        checks["Playwright"] = "[WARN] Not installed (screenshots will be skipped)"

    # Nuclei
    nuclei_path = shutil.which("nuclei")
    checks["Nuclei"] = f"[OK] {nuclei_path}" if nuclei_path else "[WARN] Not found (nuclei scans will be skipped)"

    # Output directory
    try:
        output.mkdir(parents=True, exist_ok=True)
        checks["Output Directory"] = f"[OK] {output.resolve()}"
    except Exception as exc:
        checks["Output Directory"] = f"[FAIL] {exc}"

    # SQLAlchemy
    try:
        import sqlalchemy
        checks["SQLAlchemy"] = f"[OK] {sqlalchemy.__version__}"
    except ImportError:
        checks["SQLAlchemy"] = "[FAIL] Not installed"

    print_module_summary("ScoutX Doctor", checks)
    info("Health check complete")


@app.command("config")
def show_config(
    config_path: Optional[Path] = typer.Option(None, "--config", "-c", help="Config file path"),
) -> None:
    """Show resolved configuration."""
    from scoutx.core.config import ScoutXConfig

    cfg = ScoutXConfig(config_path=config_path)
    from scoutx.cli.ui import print_module_summary

    # Show a subset of important values
    summary = {
        "Profile": cfg.get("scan_profile", "balanced"),
        "Output": str(cfg.output_dir),
        "Database": str(cfg.database_path),
        "Stealth - Proxy Rotation": cfg.get("stealth.proxy_rotation", False),
        "Stealth - Random UA": cfg.get("stealth.random_user_agent", True),
        "Notifications": cfg.get("notifications.enabled", False),
    }
    print_module_summary("Resolved Configuration", summary)
