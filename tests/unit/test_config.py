import pytest

from scoutx.core.config import ScoutXConfig, _deep_merge, _dot_get, _dot_set


def test_deep_merge():
    base = {"a": 1, "b": {"c": 2, "d": 3}}
    override = {"b": {"c": 99}, "e": 4}
    merged = _deep_merge(base, override)
    
    assert merged["a"] == 1
    assert merged["b"]["d"] == 3
    assert merged["b"]["c"] == 99
    assert merged["e"] == 4


def test_dot_get_and_set():
    data = {"stealth": {"proxy": "http://127.0.0.1:8080"}}
    
    # dot_get
    assert _dot_get(data, "stealth.proxy") == "http://127.0.0.1:8080"
    assert _dot_get(data, "stealth.unknown", "fallback") == "fallback"
    
    # dot_set
    _dot_set(data, "stealth.proxy_rotation", True)
    assert data["stealth"]["proxy_rotation"] is True
    
    _dot_set(data, "new.nested.key", 42)
    assert data["new"]["nested"]["key"] == 42


def test_config_defaults(config):
    assert config.get("output_dir") == "results"
    assert config.get("scan_profile") == "balanced"
    assert config.get("stealth.random_user_agent") is True


def test_config_env_vars(monkeypatch):
    monkeypatch.setenv("SCOUTX_OUTPUT_DIR", "/tmp/results")
    monkeypatch.setenv("SCOUTX_STEALTH__PROXY_ROTATION", "true")
    monkeypatch.setenv("SCOUTX_CONCURRENCY__PROBE", "250")
    
    config = ScoutXConfig()
    
    assert config.get("output_dir") == "/tmp/results"
    assert config.get("stealth.proxy_rotation") is True
    assert config.get("concurrency.probe") == 250


def test_config_overrides():
    config = ScoutXConfig(overrides={
        "output_dir": "/custom/path",
        "stealth.user_agent": "Mozilla/Badass"
    })
    
    assert config.output_dir.name == "path"
    assert config.get("output_dir") == "/custom/path"
    assert config.get("stealth.user_agent") == "Mozilla/Badass"


def test_get_profiled(config):
    # 'safe' profile overrides concurrency.probe
    safe_val = config.get_profiled("concurrency.probe", "safe")
    assert safe_val == 8
    
    # 'aggressive' profile overrides concurrency.probe
    agg_val = config.get_profiled("concurrency.probe", "aggressive")
    assert agg_val == 100
    
    # Fallback when missing from profile
    # Let's say random_user_agent is not in safety_profiles
    assert config.get_profiled("stealth.random_user_agent", "safe") is True
