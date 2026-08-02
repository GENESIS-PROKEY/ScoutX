"""Configuration management — layered config with dot-notation access.

Resolution order: defaults → YAML file → env vars (SCOUTX_ prefix) → CLI overrides.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

# ── Sane defaults ──────────────────────────────────────────────────────
DEFAULT_CONFIG: dict[str, Any] = {
    "output_dir": "results",
    "scan_profile": "balanced",
    "api_keys": {
        "shodan": "",
        "securitytrails": "",
        "virustotal": "",
        "censys": "",
        "chaos": "",
        "alienvault": "",
        "github": "",
    },
    "sources": {
        "crtsh": True,
        "alienvault": True,
        "chaos": True,
        "shodan": True,
        "securitytrails": True,
        "virustotal": True,
        "bufferover": True,
        "urlscan": True,
        "rapiddns": True,
        "hackertarget": True,
        "censys": True,
        "anubis": True,
        "webarchive": True,
    },
    "concurrency": {
        "probe": 50,
        "js": 10,
        "screenshots": 4,
        "nuclei": 25,
        "dns": 50,
        "ports": 100,
    },
    "rate_limits": {
        "probe": 12,
        "js": 6,
        "screenshots": 1,
        "nuclei": 25,
        "ports": 0,
    },
    "request_ceilings": {
        "probe": 500,
        "js_html": 40,
        "js_downloads": 150,
        "screenshots": 25,
        "nuclei_targets": 250,
        "historical_urls": 1000,
        "content_discovery": 80,
    },
    "timeouts": {
        "http": 10,
        "nuclei": 300,
        "screenshot": 20,
        "source": 30,
        "port": 3,
        "module": 600,
    },
    "safety_profiles": {
        "safe": {
            "concurrency": {"probe": 8, "js": 3, "screenshots": 1, "nuclei": 8, "dns": 20, "ports": 25},
            "rate_limits": {"probe": 4, "js": 2, "screenshots": 0.5, "nuclei": 8},
            "request_ceilings": {"probe": 120, "js_html": 20, "screenshots": 10, "nuclei_targets": 80},
        },
        "balanced": {
            "concurrency": {"probe": 50, "js": 10, "screenshots": 4, "nuclei": 25, "dns": 50, "ports": 100},
            "rate_limits": {"probe": 12, "js": 6, "screenshots": 1, "nuclei": 25},
            "request_ceilings": {"probe": 500, "js_html": 40, "screenshots": 25, "nuclei_targets": 250},
        },
        "aggressive": {
            "concurrency": {"probe": 100, "js": 20, "screenshots": 8, "nuclei": 50, "dns": 80, "ports": 250},
            "rate_limits": {"probe": 30, "js": 15, "screenshots": 3, "nuclei": 50},
            "request_ceilings": {"probe": 1500, "js_html": 100, "screenshots": 75, "nuclei_targets": 750},
        },
        "passive": {
            "concurrency": {"probe": 0, "js": 0, "screenshots": 0, "nuclei": 0, "dns": 30, "ports": 0},
            "rate_limits": {"probe": 0, "js": 0, "screenshots": 0, "nuclei": 0},
            "request_ceilings": {"probe": 0, "js_html": 0, "screenshots": 0, "nuclei_targets": 0},
            "plugin_whitelist": ["subdomains", "osint", "intelligence", "historical", "github_dork"],
        },
        "quick": {
            "concurrency": {"probe": 30, "js": 0, "screenshots": 0, "nuclei": 0, "dns": 50, "ports": 50},
            "rate_limits": {"probe": 10, "js": 0, "screenshots": 0, "nuclei": 0},
            "request_ceilings": {"probe": 200, "js_html": 0, "screenshots": 0, "nuclei_targets": 0},
            "plugin_whitelist": ["subdomains", "probe", "ports"],
            "timeout_override": 60,
        },
    },
    "stealth": {
        "proxy": "",
        "proxy_rotation": False,
        "proxy_list": [],
        "random_user_agent": True,
        "adaptive_rate_limit": True,
        "user_agent": "",
    },
    "notifications": {
        "enabled": False,
        "slack_webhook": "",
        "discord_webhook": "",
        "generic_webhooks": [],
    },
    "database": {
        "path": "results/scoutx.db",
    },
    "scope": {
        "includes": [],
        "excludes": [],
        "wildcard": True,
    },
    "ai": {
        "provider": "none",  # ollama|openai|claude|deepseek|groq|grok|openrouter|custom|none
        "model": "",         # Provider-specific model name (uses default if empty)
        "api_key": "",       # API key (not needed for Ollama)
        "base_url": "",      # Custom endpoint URL (for self-hosted/custom providers)
    },
    "wordlists": {
        "directories": "",   # Path to custom directory wordlist
        "subdomains": "",    # Path to custom subdomain wordlist
        "parameters": "",    # Path to custom parameter wordlist
    },
}

ENV_PREFIX = "SCOUTX_"


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base dict."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _dot_get(data: dict, key: str, default: Any = None) -> Any:
    """Access nested dict values with dot notation: 'concurrency.probe'."""
    parts = key.split(".")
    current: Any = data
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return default
    return current


def _dot_set(data: dict, key: str, value: Any) -> None:
    """Set nested dict values with dot notation."""
    parts = key.split(".")
    current = data
    for part in parts[:-1]:
        if part not in current or not isinstance(current[part], dict):
            current[part] = {}
        current = current[part]
    current[parts[-1]] = value


class ScoutXConfig:
    """Layered configuration: defaults → YAML → env vars → CLI overrides."""

    def __init__(
        self,
        config_path: Path | None = None,
        overrides: dict[str, Any] | None = None,
    ) -> None:
        self._data: dict[str, Any] = DEFAULT_CONFIG.copy()
        self._data = _deep_merge(DEFAULT_CONFIG, {})

        # Layer 2: YAML file
        if config_path is None:
            for candidate in [Path("scoutx.yaml"), Path("scoutx.yml"), Path("config.yaml")]:
                if candidate.exists():
                    config_path = candidate
                    break
        if config_path and config_path.exists():
            self._load_yaml(config_path)

        # Layer 3: Environment variables
        self._load_env_vars()

        # Layer 4: CLI overrides
        if overrides:
            self._apply_overrides(overrides)

    def _load_yaml(self, path: Path) -> None:
        """Load and merge a YAML config file."""
        try:
            text = path.read_text(encoding="utf-8-sig")
            data = yaml.safe_load(text) or {}
            if isinstance(data, dict):
                self._data = _deep_merge(self._data, data)
        except Exception:
            pass  # Gracefully ignore bad config files

    def _load_env_vars(self) -> None:
        """Override config from SCOUTX_ prefixed env vars."""
        for key, value in os.environ.items():
            if not key.startswith(ENV_PREFIX):
                continue
            config_key = key[len(ENV_PREFIX):].lower().replace("__", ".")
            # Type coercion for common patterns
            if value.lower() in ("true", "1", "yes"):
                _dot_set(self._data, config_key, True)
            elif value.lower() in ("false", "0", "no"):
                _dot_set(self._data, config_key, False)
            else:
                try:
                    _dot_set(self._data, config_key, int(value))
                except ValueError:
                    try:
                        _dot_set(self._data, config_key, float(value))
                    except ValueError:
                        _dot_set(self._data, config_key, value)

    def _apply_overrides(self, overrides: dict[str, Any]) -> None:
        """Apply explicit overrides from CLI arguments."""
        for key, value in overrides.items():
            if value is not None:
                _dot_set(self._data, key, value)

    def get(self, key: str, default: Any = None) -> Any:
        """Get config value using dot notation."""
        return _dot_get(self._data, key, default)

    def get_profiled(self, key: str, profile: str) -> Any:
        """Get a profile-aware value with fallback to base config."""
        profile_value = _dot_get(self._data, f"safety_profiles.{profile}.{key}")
        if profile_value is not None:
            return profile_value
        return self.get(key)

    @property
    def api_keys(self) -> dict[str, str]:
        keys = self.get("api_keys", {})
        return keys if isinstance(keys, dict) else {}

    @property
    def output_dir(self) -> Path:
        return Path(self.get("output_dir", "results"))

    @property
    def database_path(self) -> Path:
        return Path(self.get("database.path", "results/scoutx.db"))

    @property
    def raw(self) -> dict[str, Any]:
        """Return the raw config dict for serialization."""
        return self._data.copy()
