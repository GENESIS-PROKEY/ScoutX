"""Rich UI components for ScoutX — banners, styled output, progress bars.

Every line of terminal output goes through here. We don't do boring.
"""
from __future__ import annotations

import os
import sys
import time
from contextlib import contextmanager
from typing import Any, Generator

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

# Force UTF-8 on Windows to avoid cp1252 encoding crashes with Rich
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, OSError):
        pass

console = Console(force_terminal=True)

# ── Brand colours ──────────────────────────────────────────────────────
BRAND_PRIMARY = "cyan"
BRAND_ACCENT = "bright_magenta"
BRAND_SUCCESS = "green"
BRAND_WARN = "yellow"
BRAND_ERROR = "red"
BRAND_DIM = "dim"

BANNER_ART = r"""
   ___                _  __  __
  / __| __ ___  _  _| |_\ \/ /
  \__ \/ _/ _ \| || |  _|>  <
  |___/\__\___/ \_,_|\__/_/\_\
"""


def banner_renderable(version: str) -> Panel:
    """Return the branded ScoutX banner as a Rich Panel."""
    title_text = Text(BANNER_ART, style=f"bold {BRAND_PRIMARY}")
    subtitle = Text(f"  v{version} — Async Recon Framework", style=BRAND_DIM)
    tagline = Text("  Scout deeper. Strike smarter.", style=f"italic {BRAND_ACCENT}")
    combined = Text.assemble(title_text, "\n", subtitle, "\n", tagline)
    return Panel(
        Align.left(combined),
        border_style=BRAND_PRIMARY,
        box=box.SQUARE,
        padding=(0, 2),
    )


def ui_box() -> box.Box:
    """Return the standard box style used across all ScoutX tables."""
    return box.ROUNDED


# ── Styled output helpers ──────────────────────────────────────────────

def info(msg: str) -> None:
    """Print an informational message."""
    console.print(f"  [dim]>[/] {msg}")


def success(msg: str) -> None:
    """Print a success message."""
    console.print(f"  [{BRAND_SUCCESS}]+[/] {msg}")


def warn(msg: str) -> None:
    """Print a warning message."""
    console.print(f"  [{BRAND_WARN}]![/] [yellow]{msg}[/]")


def error(msg: str) -> None:
    """Print an error message."""
    console.print(f"  [{BRAND_ERROR}]x[/] [red]{msg}[/]")


def skip(msg: str) -> None:
    """Print a skip message."""
    console.print(f"  [dim]- {msg}[/]")


def print_module_header(title: str, target: str) -> None:
    """Print a styled header when a module starts."""
    header = Text.assemble(
        (f" {title} ", f"bold {BRAND_PRIMARY}"),
        (" >> ", BRAND_DIM),
        (target, "bold white"),
    )
    console.print()
    console.print(Panel(header, border_style="steel_blue1", box=box.SQUARE, expand=False))


def print_module_summary(title: str, data: dict[str, Any]) -> None:
    """Print a styled table summarising module results."""
    table = Table(
        title=title,
        border_style="steel_blue1",
        box=ui_box(),
        show_header=True,
        header_style=BRAND_PRIMARY,
        padding=(0, 1),
    )
    table.add_column("Metric", style="bold")
    table.add_column("Value", style="white")
    for key, value in data.items():
        table.add_row(str(key), str(value))
    console.print(table)


def print_scan_summary(data: dict[str, Any]) -> None:
    """Print the end-of-scan summary table."""
    table = Table(
        title="Scan Summary",
        border_style=BRAND_ACCENT,
        box=box.SQUARE,
        show_header=True,
        header_style=f"bold {BRAND_ACCENT}",
        padding=(0, 2),
    )
    table.add_column("Metric", style="bold cyan")
    table.add_column("Value", style="white")
    for key, value in data.items():
        table.add_row(str(key), str(value))
    console.print()
    console.print(table)
    console.print()


def finding_badge(severity: str) -> str:
    """Return colored Rich markup badge for severity."""
    badges = {
        "critical": "[bold white on red] CRITICAL [/]",
        "high": "[bold white on dark_red] HIGH [/]",
        "medium": "[bold black on yellow] MEDIUM [/]",
        "low": "[bold white on blue] LOW [/]",
        "info": "[bold white on dim] INFO [/]",
    }
    return badges.get(severity.lower(), f"[{severity}]")

def phase_banner(phase_num: int, name: str, description: str) -> None:
    """Print a phase start banner."""
    console.print(f"\n[{BRAND_PRIMARY}]─── Phase {phase_num}: {name} {'─' * (50 - len(name))}[/]")
    console.print(f"  [dim]{description}[/dim]\n")

def print_scan_summary_card(target: str, duration: float, risk_score: int, findings: dict, chains: list, stats: dict) -> None:
    """Print the beautiful end-of-scan summary card."""
    risk_level = "LOW"
    if risk_score >= 90:
        risk_level = "CRITICAL"
    elif risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"

    bars_total = 20
    filled = int((risk_score / 100) * bars_total)
    empty = bars_total - filled
    bar = f"[red]{'█' * filled}[/][dim]{'░' * empty}[/]"

    crit = findings.get("critical", 0)
    high = findings.get("high", 0)
    med = findings.get("medium", 0)

    sub = stats.get("subdomains", 0)
    alv = stats.get("alive", 0)
    prt = stats.get("ports", 0)

    chain_count = len(chains)
    top_chain = chains[0] if chains else "None"

    card = f"""
 Target:     [bold]{target}[/]
 Duration:   [cyan]{format_duration(duration)}[/]
 Risk Score: {risk_score}/100 {bar} [bold]{risk_level}[/]
 
 Findings:   [red]Critical: {crit}[/]  [dark_red]High: {high}[/]  [yellow]Medium: {med}[/]
 Assets:     [cyan]Subdomains: {sub}[/]  [green]Alive: {alv}[/]  [blue]Ports: {prt}[/]
 Chains:     [magenta]{chain_count} attack chains generated[/]
 
 Top Chain:  [dim]{top_chain}[/]
"""
    console.print(Panel(card.strip(), title="Scan Complete", border_style=BRAND_PRIMARY, expand=False))


def format_duration(seconds: float) -> str:
    """Convert seconds to a human-readable duration string."""
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = seconds % 60
    if minutes < 60:
        return f"{minutes}m {secs:.0f}s"
    hours = minutes // 60
    mins = minutes % 60
    return f"{hours}h {mins}m {secs:.0f}s"


@contextmanager
def progress_bar(
    total: int | None = None,
    description: str = "Working...",
) -> Generator[Progress, None, None]:
    """Context manager that yields a Rich progress bar."""
    columns = [
        SpinnerColumn(style=BRAND_PRIMARY),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=40, style=BRAND_PRIMARY, complete_style=BRAND_ACCENT),
        TextColumn("[dim]{task.completed}/{task.total}[/]"),
        TimeElapsedColumn(),
    ]
    with Progress(*columns, console=console, transient=True) as progress:
        task_id = progress.add_task(description, total=total)
        progress._active_task = task_id  # type: ignore[attr-defined]
        yield progress


class PerformanceMonitor:
    """Lightweight wall-clock + memory tracker for module runs."""

    def __init__(self) -> None:
        self._start: float = 0.0
        self._stop: float = 0.0

    def start(self) -> PerformanceMonitor:
        self._start = time.perf_counter()
        return self

    def stop(self) -> dict[str, Any]:
        self._stop = time.perf_counter()
        return {
            "duration_seconds": round(self._stop - self._start, 3),
            "duration_human": format_duration(self._stop - self._start),
        }
