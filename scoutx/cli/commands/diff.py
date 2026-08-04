import asyncio
from pathlib import Path

import typer

from scoutx.cli.ui import console, error, info, print_module_header, warn
from scoutx.reporting.diff import ScanDiffer, format_diff_text
from scoutx.reporting.visual_diff import VisualDiffGenerator

diff_app = typer.Typer(help="Compare two scan result directories.", no_args_is_help=True)

@diff_app.callback(invoke_without_command=True)
def diff_command(
    dir1: Path = typer.Argument(..., help="First scan directory (older)"),
    dir2: Path = typer.Argument(..., help="Second scan directory (newer)"),
    fmt: str = typer.Option("text", "--format", help="Output format: text, json, html"),
    visual: bool = typer.Option(False, "--visual", help="Generate a visual screenshot diff alongside the text diff"),
) -> None:
    """Compare two scan result directories and show what changed."""
    print_module_header("Scan Diff", f"{dir1.name} -> {dir2.name}")

    if not dir1.exists() or not dir1.is_dir():
        error(f"Directory not found: {dir1}")
        raise typer.Exit(code=1)

    if not dir2.exists() or not dir2.is_dir():
        error(f"Directory not found: {dir2}")
        raise typer.Exit(code=1)

    try:
        differ = ScanDiffer(dir1, dir2)
        result = differ.diff()

        if fmt.lower() == "json":
            console.print_json(data=result.to_dict())
        elif fmt.lower() == "html":
            # Just a basic HTML wrapper for the text output for now
            html_content = f"<html><body><pre>{format_diff_text(result)}</pre></body></html>"
            console.print(html_content)
        else:
            text = format_diff_text(result)
            console.print(text)

        info(f"Total changes: {result.total_changes} ({result.change_velocity} velocity)")
        if result.has_critical_changes:
            warn("Critical changes detected! Review new secrets and open ports.")

        if visual:
            info("Generating visual diff...")
            visual_differ = VisualDiffGenerator()
            out_path = asyncio.run(visual_differ.generate(dir1, dir2, dir2))
            info(f"Visual diff generated at: {out_path}")

    except Exception as exc:
        error(f"Diff failed: {exc}")
        raise typer.Exit(code=1) from exc

def register(app: typer.Typer) -> None:
    """Register diff commands on the given Typer app."""
    app.add_typer(diff_app, name="diff")
