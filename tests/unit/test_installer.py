"""Tests for the tool registry and installer."""
from __future__ import annotations

import pytest

from scoutx.tools.registry import (
    CATEGORIES,
    TOOL_REGISTRY,
    ToolEntry,
    check_all,
    check_tool,
    get_by_category,
    get_installed,
    get_missing,
)


class TestToolRegistry:
    def test_registry_not_empty(self):
        assert len(TOOL_REGISTRY) > 30

    def test_all_categories_exist(self):
        expected = {"core", "extended", "osint", "sast", "system"}
        assert set(CATEGORIES.keys()) == expected

    def test_core_tools_present(self):
        core_names = {t.name for t in CATEGORIES["core"]}
        assert "subfinder" in core_names
        assert "nuclei" in core_names
        assert "httpx-pd" in core_names

    def test_tool_entry_fields(self):
        for tool in TOOL_REGISTRY:
            assert isinstance(tool, ToolEntry)
            assert tool.name
            assert tool.check_cmd
            assert tool.install_linux
            assert tool.category in CATEGORIES
            assert tool.description

    def test_check_all_returns_dict(self):
        result = check_all()
        assert isinstance(result, dict)
        assert len(result) == len(TOOL_REGISTRY)
        # Python should be available
        assert check_tool("python3") or check_tool("python")

    def test_get_by_category_structure(self):
        result = get_by_category()
        assert isinstance(result, dict)
        for cat, tools in result.items():
            assert isinstance(tools, list)
            for tool, status in tools:
                assert isinstance(tool, ToolEntry)
                assert isinstance(status, bool)

    def test_get_missing_returns_list(self):
        missing = get_missing()
        assert isinstance(missing, list)

    def test_get_missing_by_category(self):
        missing = get_missing("core")
        assert isinstance(missing, list)
        for tool in missing:
            assert tool.category == "core"

    def test_get_installed_returns_list(self):
        installed = get_installed()
        assert isinstance(installed, list)


class TestToolInstaller:
    def test_installer_prerequisites(self):
        from scoutx.tools.installer import ToolInstaller
        installer = ToolInstaller()
        prereqs = installer.check_prerequisites()
        assert isinstance(prereqs, dict)
        assert "python3" in prereqs
        assert "git" in prereqs
        assert "go" in prereqs
        assert "npm" in prereqs
