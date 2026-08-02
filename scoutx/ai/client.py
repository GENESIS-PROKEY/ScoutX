"""Universal LLM client interface and provider factory.

Supports: Ollama, OpenAI, Claude, DeepSeek, Groq, Grok, OpenRouter,
and any OpenAI-compatible endpoint.
"""
from __future__ import annotations

import logging
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger("scoutx.ai")


@runtime_checkable
class LLMClient(Protocol):
    """Universal interface for all LLM providers."""

    async def generate(
        self, prompt: str, system_prompt: str = "", max_tokens: int = 4096
    ) -> str: ...

    def provider_name(self) -> str: ...


# Provider configs — base URLs and whether they need API keys
PROVIDER_CONFIGS: dict[str, dict[str, Any]] = {
    "ollama": {"base_url": "http://localhost:11434", "needs_key": False},
    "openai": {"base_url": "https://api.openai.com/v1", "needs_key": True},
    "claude": {"base_url": "https://api.anthropic.com", "needs_key": True},
    "deepseek": {"base_url": "https://api.deepseek.com/v1", "needs_key": True},
    "groq": {"base_url": "https://api.groq.com/openai/v1", "needs_key": True},
    "grok": {"base_url": "https://api.x.ai/v1", "needs_key": True},
    "openrouter": {"base_url": "https://openrouter.ai/api/v1", "needs_key": True},
}

# Default models per provider
DEFAULT_MODELS: dict[str, str] = {
    "ollama": "llama3.2",
    "openai": "gpt-4o-mini",
    "claude": "claude-sonnet-4-20250514",
    "deepseek": "deepseek-chat",
    "groq": "llama-3.3-70b-versatile",
    "grok": "grok-3-mini",
    "openrouter": "meta-llama/llama-3-8b-instruct",
}


def create_client(
    provider: str,
    model: str = "",
    api_key: str = "",
    base_url: str = "",
) -> LLMClient | None:
    """Factory — create the right LLM client based on provider name.

    Returns None if the provider can't be initialized (missing key, etc).
    """
    if provider == "none" or not provider:
        return None

    if provider == "ollama":
        from scoutx.ai.providers.ollama import OllamaClient

        return OllamaClient(
            model=model or DEFAULT_MODELS["ollama"],
            base_url=base_url or PROVIDER_CONFIGS["ollama"]["base_url"],
        )

    if provider == "claude":
        from scoutx.ai.providers.claude import ClaudeClient

        if not api_key:
            logger.warning("Claude requires an API key. Set ai.api_key in config.")
            return None
        return ClaudeClient(
            model=model or DEFAULT_MODELS["claude"],
            api_key=api_key,
        )

    # Everything else is OpenAI-compatible (OpenAI, Groq, Grok, OpenRouter, DeepSeek, custom)
    if provider in ("openai", "deepseek", "groq", "grok", "openrouter", "custom"):
        from scoutx.ai.providers.openai_compat import OpenAICompatClient

        config = PROVIDER_CONFIGS.get(provider, {})
        url = base_url or config.get("base_url", "")

        if not url and provider == "custom":
            logger.warning("Custom provider requires ai.base_url in config.")
            return None

        if config.get("needs_key") and not api_key:
            logger.warning(f"{provider} requires an API key. Set ai.api_key in config.")
            return None

        return OpenAICompatClient(
            model=model or DEFAULT_MODELS.get(provider, "gpt-4o-mini"),
            api_key=api_key,
            base_url=url,
            provider_label=provider,
        )

    logger.warning(f"Unknown AI provider: {provider}")
    return None
