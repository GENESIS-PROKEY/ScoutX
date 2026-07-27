"""Plugin marketplace — download, install, and manage third-party plugins."""
from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any
import subprocess

logger = logging.getLogger("scoutx.plugins.marketplace")


class PluginMarketplace:
    """Manages downloading and installing plugins from Git repositories."""

    def __init__(self, plugins_dir: Path | None = None) -> None:
        if plugins_dir is None:
            self.plugins_dir = Path.home() / ".scoutx" / "plugins"
        else:
            self.plugins_dir = plugins_dir
        
        self.plugins_dir.mkdir(parents=True, exist_ok=True)

    async def search(self, query: str) -> list[dict[str, Any]]:
        """Search for plugins in the global registry (placeholder)."""
        # In the future, this will query a central registry or GitHub topics.
        logger.info(f"Searching for '{query}' - returning empty list (not implemented yet)")
        return []

    async def install(self, name: str, source: str) -> bool:
        """Install a plugin from a Git URL to ~/.scoutx/plugins/{name}/."""
        target_dir = self.plugins_dir / name
        if target_dir.exists():
            logger.warning(f"Plugin {name} already exists at {target_dir}. Uninstall first.")
            return False

        try:
            logger.info(f"Cloning {source} to {target_dir}")
            # Run git clone
            subprocess.run(
                ["git", "clone", "--depth", "1", source, str(target_dir)],
                check=True,
                capture_output=True,
                text=True
            )
            
            # Validate the plugin
            plugin_file = target_dir / "plugin.py"
            if not plugin_file.exists():
                logger.error(f"Invalid plugin repository: missing plugin.py at {plugin_file}")
                shutil.rmtree(target_dir)
                return False
                
            with open(plugin_file, "r", encoding="utf-8") as f:
                content = f.read()
                if "class Plugin" not in content:
                    logger.error("Invalid plugin repository: missing Plugin class in plugin.py")
                    shutil.rmtree(target_dir)
                    return False
                    
            logger.info(f"Successfully installed plugin {name}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Git clone failed: {e.stderr}")
            if target_dir.exists():
                shutil.rmtree(target_dir)
            return False
        except Exception as e:
            logger.error(f"Failed to install plugin {name}: {e}")
            if target_dir.exists():
                shutil.rmtree(target_dir)
            return False

    async def uninstall(self, name: str) -> bool:
        """Remove an installed plugin directory."""
        target_dir = self.plugins_dir / name
        if not target_dir.exists():
            logger.warning(f"Plugin {name} is not installed.")
            return False
            
        try:
            shutil.rmtree(target_dir)
            logger.info(f"Successfully uninstalled plugin {name}")
            return True
        except Exception as e:
            logger.error(f"Failed to uninstall plugin {name}: {e}")
            return False

    def list_installed(self) -> list[dict[str, Any]]:
        """List locally installed plugins from the plugin directory."""
        installed = []
        for child in self.plugins_dir.iterdir():
            if child.is_dir() and (child / "plugin.py").exists():
                installed.append({
                    "name": child.name,
                    "path": str(child)
                })
        return installed
