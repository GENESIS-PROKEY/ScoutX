"""Tool Auto-Installer — detects platform and installs missing tools.

Handles Go, Python, NPM, and system package installations with
subprocess-based execution and per-tool success/failure tracking.
"""
from __future__ import annotations

import asyncio
import logging
import sys

from scoutx.tools.registry import ToolEntry, check_tool

logger = logging.getLogger("scoutx.tools.installer")

IS_LINUX = sys.platform.startswith("linux")
IS_WINDOWS = sys.platform == "win32"


class ToolInstaller:
    """Install missing external tools with platform detection."""

    async def install_tool(self, tool: ToolEntry) -> bool:
        """Install a single tool. Returns True on success."""
        if check_tool(tool.name):
            logger.info("%s is already installed", tool.name)
            return True

        install_cmd = tool.install_linux if IS_LINUX else tool.install_windows
        if not install_cmd:
            logger.warning("No install command for %s on this platform", tool.name)
            return False

        logger.info("Installing %s: %s", tool.name, install_cmd)

        try:
            if IS_WINDOWS:
                proc = await asyncio.create_subprocess_shell(
                    install_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                proc = await asyncio.create_subprocess_shell(
                    install_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=300
            )

            if proc.returncode == 0:
                logger.info("Successfully installed %s", tool.name)
                return True
            else:
                err = stderr.decode("utf-8", errors="replace")[:500]
                logger.warning("Failed to install %s: %s", tool.name, err)
                return False

        except asyncio.TimeoutError:
            logger.warning("Installation of %s timed out", tool.name)
            return False
        except Exception as exc:
            logger.warning("Error installing %s: %s", tool.name, exc)
            return False

    async def install_category(self, category: str) -> dict[str, bool]:
        """Install all tools in a category. Returns {name: success}."""
        from scoutx.tools.registry import CATEGORIES

        tools = CATEGORIES.get(category, [])
        results: dict[str, bool] = {}

        for tool in tools:
            results[tool.name] = await self.install_tool(tool)

        return results

    async def install_all(self) -> dict[str, bool]:
        """Install all missing tools. Returns {name: success}."""
        from scoutx.tools.registry import TOOL_REGISTRY

        results: dict[str, bool] = {}
        for tool in TOOL_REGISTRY:
            if not check_tool(tool.name):
                results[tool.name] = await self.install_tool(tool)
            else:
                results[tool.name] = True

        return results

    def check_prerequisites(self) -> dict[str, bool]:
        """Check if prerequisite runtimes are available."""
        import shutil
        return {
            "python3": shutil.which("python3") is not None or shutil.which("python") is not None,
            "go": shutil.which("go") is not None,
            "npm": shutil.which("npm") is not None,
            "pip": shutil.which("pip") is not None or shutil.which("pip3") is not None,
            "git": shutil.which("git") is not None,
        }
