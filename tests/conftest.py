import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from scoutx.core.config import ScoutXConfig
from scoutx.core.engine import ScanContext
from scoutx.core.events import EventBus
from scoutx.core.scope import Scope
from scoutx.core.state import ScanState
from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin


class DummyPlugin(ScoutPlugin):
    """A minimal mock plugin for tests."""

    def __init__(self, name="dummy", depends_on=None, concurrent_with=None):
        self.meta = PluginMeta(
            name=name,
            description="Dummy for testing",
        )
        self.depends_on = depends_on or []
        self.concurrent_with = concurrent_with or []
        self.enabled = True
        self.run_mock = AsyncMock(return_value=PluginResult.completed({"status": "ok"}))

    async def run(self, context):
        return await self.run_mock(context)

    def schema(self):
        return ResultSchema(fields={}, description="dummy schema")


@pytest.fixture
def config():
    """Provides a fresh ScoutXConfig with default settings."""
    return ScoutXConfig(overrides={"database.path": ":memory:"})


@pytest.fixture
def dummy_context(config, tmp_path):
    """Provides a dummy ScanContext."""
    return ScanContext(
        scan_id="test-scan-123",
        target="example.com",
        scope=Scope(includes=["*.example.com"], excludes=[]),
        config=config,
        output_dir=tmp_path,
        profile="balanced",
        state=ScanState(scan_id="test-scan-123", target="example.com", profile="balanced"),
        db=AsyncMock(),
        events=EventBus(),
    )


@pytest.fixture
def make_plugin():
    """Factory to create DummyPlugin instances easily."""
    def _make(name="test_plugin", depends_on=None):
        return DummyPlugin(name=name, depends_on=depends_on)
    return _make
