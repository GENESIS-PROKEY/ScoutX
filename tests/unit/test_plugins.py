from unittest.mock import patch
import pytest

from scoutx.plugins.manager import PluginManager


def test_plugin_registration(config, make_plugin):
    manager = PluginManager(config)
    plugin = make_plugin("p1")
    
    manager.register(plugin)
    assert manager.get("p1") == plugin
    assert len(manager.get_all()) == 1
    
    manager.unregister("p1")
    assert manager.get("p1") is None
    assert len(manager.get_all()) == 0


def test_plugin_enable_disable(config, make_plugin):
    manager = PluginManager(config)
    plugin = make_plugin("p1")
    manager.register(plugin)
    
    manager.disable("p1")
    assert not manager.get("p1").enabled
    assert len(manager.get_enabled()) == 0
    
    manager.enable("p1")
    assert manager.get("p1").enabled
    assert len(manager.get_enabled()) == 1


def test_resolve_execution_order_linear(config, make_plugin):
    manager = PluginManager(config)
    # Dependency chain: p1 -> p2 -> p3
    manager.register(make_plugin("p3", depends_on=["p2"]))
    manager.register(make_plugin("p1"))
    manager.register(make_plugin("p2", depends_on=["p1"]))
    
    phases = manager.resolve_execution_order()
    
    assert len(phases) == 3
    assert phases[0][0].meta.name == "p1"
    assert phases[1][0].meta.name == "p2"
    assert phases[2][0].meta.name == "p3"


def test_resolve_execution_order_concurrent(config, make_plugin):
    manager = PluginManager(config)
    # p1 and p2 have no dependencies, p3 depends on both
    manager.register(make_plugin("p1"))
    manager.register(make_plugin("p2"))
    manager.register(make_plugin("p3", depends_on=["p1", "p2"]))
    
    phases = manager.resolve_execution_order()
    
    assert len(phases) == 2
    
    # Phase 1 should have p1 and p2
    phase_1_names = [p.meta.name for p in phases[0]]
    assert "p1" in phase_1_names
    assert "p2" in phase_1_names
    assert len(phase_1_names) == 2
    
    # Phase 2 should have p3
    assert phases[1][0].meta.name == "p3"


def test_resolve_execution_order_cycles(config, make_plugin):
    manager = PluginManager(config)
    # Cycle: p1 -> p2 -> p3 -> p1
    manager.register(make_plugin("p1", depends_on=["p3"]))
    manager.register(make_plugin("p2", depends_on=["p1"]))
    manager.register(make_plugin("p3", depends_on=["p2"]))
    
    # Also add an independent one
    manager.register(make_plugin("independent"))
    
    phases = manager.resolve_execution_order()
    
    # Independent should be resolved normally
    assert phases[0][0].meta.name == "independent"
    
    # The cycle should be dumped into the final phase
    final_phase = [p.meta.name for p in phases[-1]]
    assert set(final_phase) == {"p1", "p2", "p3"}
