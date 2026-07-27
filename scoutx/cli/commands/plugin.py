"""Plugin management commands — list, enable, disable."""
from __future__ import annotations

import typer

from scoutx.cli.ui import info, print_module_summary, success, warn


def register(app: typer.Typer) -> None:
    """Register plugin commands on the plugin sub-app."""

    @app.command("list")
    def plugin_list() -> None:
        """List all discovered plugins."""
        from scoutx.core.config import ScoutXConfig
        from scoutx.plugins.manager import PluginManager

        config = ScoutXConfig()
        manager = PluginManager(config)
        manager.discover_builtin()

        plugins = manager.get_all()
        if not plugins:
            info("No plugins discovered.")
            return

        data: dict[str, str] = {}
        for plugin in plugins:
            status = "[ON]" if plugin.enabled else "[OFF]"
            deps = ", ".join(plugin.depends_on) if plugin.depends_on else "none"
            data[plugin.meta.name] = f"{status} | v{plugin.meta.version} | depends: {deps}"
        print_module_summary("Installed Plugins", data)

    @app.command("info")
    def plugin_info(
        name: str = typer.Argument(..., help="Plugin name"),
    ) -> None:
        """Show details for a specific plugin."""
        from scoutx.core.config import ScoutXConfig
        from scoutx.plugins.manager import PluginManager

        config = ScoutXConfig()
        manager = PluginManager(config)
        manager.discover_builtin()

        plugin = manager.get(name)
        if not plugin:
            warn(f"Plugin '{name}' not found.")
            raise typer.Exit(code=1)

        data = {
            "Name": plugin.meta.name,
            "Description": plugin.meta.description,
            "Version": plugin.meta.version,
            "Author": plugin.meta.author,
            "Tags": ", ".join(plugin.meta.tags) if plugin.meta.tags else "none",
            "Dependencies": ", ".join(plugin.depends_on) if plugin.depends_on else "none",
            "Concurrent With": ", ".join(plugin.concurrent_with) if plugin.concurrent_with else "auto",
            "Enabled": "Yes" if plugin.enabled else "No",
        }
        print_module_summary(f"Plugin: {name}", data)

    @app.command("enable")
    def plugin_enable(
        name: str = typer.Argument(..., help="Plugin to enable"),
    ) -> None:
        """Enable a plugin."""
        from scoutx.core.config import ScoutXConfig
        from scoutx.plugins.manager import PluginManager

        config = ScoutXConfig()
        manager = PluginManager(config)
        manager.discover_builtin()
        manager.enable(name)
        success(f"Plugin '{name}' enabled")

    @app.command("disable")
    def plugin_disable(
        name: str = typer.Argument(..., help="Plugin to disable"),
    ) -> None:
        """Disable a plugin."""
        from scoutx.core.config import ScoutXConfig
        from scoutx.plugins.manager import PluginManager

        config = ScoutXConfig()
        manager = PluginManager(config)
        manager.discover_builtin()
        manager.disable(name)
        success(f"Plugin '{name}' disabled")

    @app.command("install")
    def plugin_install(
        name: str = typer.Argument(..., help="Plugin name"),
        source: str = typer.Argument(..., help="Git repository URL"),
    ) -> None:
        """Install a third-party plugin from a Git repository."""
        import asyncio

        from scoutx.cli.ui import error
        from scoutx.plugins.marketplace import PluginMarketplace

        marketplace = PluginMarketplace()
        success_install = asyncio.run(marketplace.install(name, source))
        if success_install:
            success(f"Plugin '{name}' installed successfully.")
        else:
            error(f"Failed to install plugin '{name}'.")
            raise typer.Exit(code=1)

    @app.command("uninstall")
    def plugin_uninstall(
        name: str = typer.Argument(..., help="Plugin name to uninstall"),
    ) -> None:
        """Uninstall a third-party plugin."""
        import asyncio

        from scoutx.cli.ui import error
        from scoutx.plugins.marketplace import PluginMarketplace

        marketplace = PluginMarketplace()
        success_uninstall = asyncio.run(marketplace.uninstall(name))
        if success_uninstall:
            success(f"Plugin '{name}' uninstalled successfully.")
        else:
            error(f"Failed to uninstall plugin '{name}'.")
            raise typer.Exit(code=1)
