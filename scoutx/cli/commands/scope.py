"""Scope management commands — define what's fair game."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from scoutx.cli.ui import error, info, print_module_summary, success, warn


def register(app: typer.Typer) -> None:
    """Register scope commands on the scope sub-app."""

    @app.command("add")
    def scope_add(
        target: str = typer.Argument(..., help="Domain, wildcard (*.example.com), or CIDR"),
        output: Path = typer.Option(Path("results"), "-o", "--output"),
    ) -> None:
        """Add a target to the scope."""
        from scoutx.core.scope import Scope

        scope_path = output / "scope.yaml"
        scope = Scope.load(scope_path) if scope_path.exists() else Scope()
        scope.add(target)
        scope.save(scope_path)
        success(f"Added to scope: {target}")

    @app.command("remove")
    def scope_remove(
        target: str = typer.Argument(..., help="Target to remove from scope"),
        output: Path = typer.Option(Path("results"), "-o", "--output"),
    ) -> None:
        """Remove a target from the scope."""
        from scoutx.core.scope import Scope

        scope_path = output / "scope.yaml"
        if not scope_path.exists():
            error("No scope file found. Nothing to remove.")
            raise typer.Exit(code=1)
        scope = Scope.load(scope_path)
        scope.remove(target)
        scope.save(scope_path)
        success(f"Removed from scope: {target}")

    @app.command("list")
    def scope_list(
        output: Path = typer.Option(Path("results"), "-o", "--output"),
    ) -> None:
        """Show the current scope."""
        from scoutx.core.scope import Scope

        scope_path = output / "scope.yaml"
        if not scope_path.exists():
            info("No scope file found. Run `sx scope add <target>` to create one.")
            return
        scope = Scope.load(scope_path)
        data: dict[str, str] = {}
        for i, inc in enumerate(scope.includes, 1):
            data[f"Include #{i}"] = inc
        for i, exc in enumerate(scope.excludes, 1):
            data[f"Exclude #{i}"] = exc
        if not data:
            info("Scope is empty.")
            return
        print_module_summary("Current Scope", data)

    @app.command("check")
    def scope_check(
        target: str = typer.Argument(..., help="Target to check against scope"),
        output: Path = typer.Option(Path("results"), "-o", "--output"),
    ) -> None:
        """Check if a target is within the defined scope."""
        from scoutx.core.scope import Scope

        scope_path = output / "scope.yaml"
        if not scope_path.exists():
            warn("No scope file. All targets are in scope by default.")
            return
        scope = Scope.load(scope_path)
        if scope.is_in_scope(target):
            success(f"{target} is IN SCOPE")
        else:
            warn(f"{target} is OUT OF SCOPE")

    @app.command("import")
    def scope_import(
        file: Path = typer.Argument(..., help="Scope file to import (one target per line)"),
        output: Path = typer.Option(Path("results"), "-o", "--output"),
    ) -> None:
        """Import scope from a file (one target per line)."""
        from scoutx.core.scope import Scope

        if not file.exists():
            error(f"File not found: {file}")
            raise typer.Exit(code=1)

        scope_path = output / "scope.yaml"
        scope = Scope.load(scope_path) if scope_path.exists() else Scope()

        added = 0
        for line in file.read_text(encoding="utf-8").splitlines():
            target = line.strip()
            if target and not target.startswith("#"):
                scope.add(target)
                added += 1

        scope.save(scope_path)
        success(f"Imported {added} targets into scope")
