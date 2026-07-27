import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from scoutx.core.engine import ScanEngine
from scoutx.plugins.base import PluginResult
from scoutx.plugins.manager import PluginManager


@pytest.fixture
def engine(config, dummy_context, make_plugin):
    manager = PluginManager(config)
    manager.register(make_plugin("p1"))
    manager.register(make_plugin("p2", depends_on=["p1"]))
    
    return ScanEngine(
        config=config,
        scope=dummy_context.scope,
        plugin_manager=manager,
        db=dummy_context.db,
        event_bus=dummy_context.events
    )


@pytest.mark.asyncio
async def test_execute_plugin_completed(engine, dummy_context, make_plugin):
    plugin = make_plugin("test_plugin")
    
    # Needs dependencies met if any.
    # Plugin has none, so it should run.
    result = await engine._execute_plugin(plugin, dummy_context)
    
    assert result.status == "completed"
    assert dummy_context.state.is_completed("test_plugin")
    assert result.duration_seconds > 0


@pytest.mark.asyncio
async def test_execute_plugin_skipped_deps(engine, dummy_context, make_plugin):
    # Missing dependencies
    plugin = make_plugin("test_plugin", depends_on=["missing_dep"])
    
    result = await engine._execute_plugin(plugin, dummy_context)
    
    assert result.status == "skipped"
    assert result.reason.startswith("Missing dependencies:")
    assert not dummy_context.state.is_completed("test_plugin")


@pytest.mark.asyncio
async def test_execute_plugin_failed(engine, dummy_context, make_plugin):
    plugin = make_plugin("failing_plugin")
    plugin.run_mock.side_effect = Exception("Crash bang!")
    
    result = await engine._execute_plugin(plugin, dummy_context)
    
    assert result.status == "failed"
    assert "Crash bang!" in result.reason


@pytest.mark.asyncio
async def test_execute_plugin_timeout(engine, dummy_context, make_plugin):
    plugin = make_plugin("timeout_plugin")
    
    async def slow_run(ctx):
        await asyncio.sleep(0.5)
        return PluginResult.completed()
        
    plugin.run_mock = slow_run
    
    # Override timeout for the module in context
    dummy_context.config._data["timeouts"]["module"] = 0.1
    
    result = await engine._execute_plugin(plugin, dummy_context)
    
    assert result.status == "timeout"
    assert "timed out" in result.reason.lower()


@pytest.mark.asyncio
async def test_resolve_execution_plan(engine):
    # Same algorithm as PluginManager, engine handles it internally sometimes
    enabled_plugins = engine._plugin_manager.get_enabled()
    phases = engine._resolve_execution_plan(enabled_plugins)
    
    assert len(phases) == 2
    assert phases[0][0].meta.name == "p1"
    assert phases[1][0].meta.name == "p2"


@pytest.mark.asyncio
@patch("scoutx.core.engine.ScanEngine._execute_phase")
async def test_engine_run(mock_execute_phase, engine, tmp_path):
    mock_execute_phase.return_value = {"p1": PluginResult.completed()}
    
    result = await engine.run(target="example.com", output_dir=tmp_path)
    
    assert result.target == "example.com"
    assert result.status in ["completed", "partial"]
    assert mock_execute_phase.called
