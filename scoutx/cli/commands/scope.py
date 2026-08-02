"""Scope management commands — define what's fair game."""
from __future__ import annotations

from pathlib import Path

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
            info("No scope file found. Run `scoutx scope add <target>` to create one.")
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

    @app.command("save")
    def scope_save(
        name: str = typer.Argument(..., help="Profile name to save as"),
        output: Path = typer.Option(Path("results"), "-o", "--output"),
    ) -> None:
        """Save current scope as a named profile."""
        from scoutx.core.scope import Scope

        scope_path = output / "scope.yaml"
        if not scope_path.exists():
            error("No scope file found. Add targets first with `scoutx scope add`.")
            raise typer.Exit(code=1)

        profiles_dir = output / "scope_profiles"
        profiles_dir.mkdir(parents=True, exist_ok=True)

        scope = Scope.load(scope_path)
        profile_path = profiles_dir / f"{name}.yaml"
        scope.save(profile_path)
        success(f"Scope saved as profile '{name}' at {profile_path}")

    @app.command("load")
    def scope_load(
        name: str = typer.Argument(..., help="Profile name to load"),
        output: Path = typer.Option(Path("results"), "-o", "--output"),
    ) -> None:
        """Load a named scope profile as the active scope."""
        from scoutx.core.scope import Scope

        profiles_dir = output / "scope_profiles"
        profile_path = profiles_dir / f"{name}.yaml"

        if not profile_path.exists():
            # List available profiles
            if profiles_dir.exists():
                available = [p.stem for p in profiles_dir.glob("*.yaml")]
                if available:
                    error(f"Profile '{name}' not found. Available: {', '.join(available)}")
                else:
                    error("No saved profiles. Save one with `scoutx scope save <name>`.")
            else:
                error("No saved profiles. Save one with `scoutx scope save <name>`.")
            raise typer.Exit(code=1)

        scope = Scope.load(profile_path)
        scope_path = output / "scope.yaml"
        scope.save(scope_path)
        success(f"Loaded scope profile '{name}' ({len(scope.includes)} includes, {len(scope.excludes)} excludes)")

    @app.command("profiles")
    def scope_profiles(
        output: Path = typer.Option(Path("results"), "-o", "--output"),
    ) -> None:
        """List all saved scope profiles."""
        profiles_dir = output / "scope_profiles"
        if not profiles_dir.exists():
            info("No saved profiles yet. Save one with `scoutx scope save <name>`.")
            return

        profiles = list(profiles_dir.glob("*.yaml"))
        if not profiles:
            info("No saved profiles yet.")
            return

        data: dict[str, str] = {}
        for p in sorted(profiles):
            from scoutx.core.scope import Scope
            s = Scope.load(p)
            data[p.stem] = f"{len(s.includes)} includes, {len(s.excludes)} excludes"
        print_module_summary("Saved Scope Profiles", data)
