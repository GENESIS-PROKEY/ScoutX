"""OpenAI-compatible LLM provider.

Covers: OpenAI, Groq, Grok (xAI), OpenRouter, DeepSeek,
and any custom endpoint that speaks the OpenAI chat format.
"""
from __future__ import annotations

import logging

import httpx

logger = logging.getLogger("scoutx.ai.openai_compat")


class OpenAICompatClient:
    """OpenAI-compatible chat completions client."""

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        api_key: str = "",
        base_url: str = "https://api.openai.com/v1",
        provider_label: str = "openai",
    ):
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._label = provider_label

    def provider_name(self) -> str:
        return f"{self._label} ({self.model})"

    async def generate(
        self, prompt: str, system_prompt: str = "", max_tokens: int = 4096
    ) -> str:
        """Generate via OpenAI-compatible /chat/completions."""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        # OpenRouter-specific headers
        if self._label == "openrouter":
            headers["HTTP-Referer"] = "https://github.com/GENESIS-PROKEY/ScoutX"
            headers["X-Title"] = "ScoutX"

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.7,
        }

        try:
            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                choices = data.get("choices", [])
                if choices:
                    return choices[0].get("message", {}).get("content", "")
                return ""

        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            if status == 401:
                logger.warning(f"{self._label}: Invalid API key.")
            elif status == 429:
                logger.warning(f"{self._label}: Rate limited. Try again later.")
            else:
                logger.warning(f"{self._label} error {status}: {e.response.text[:200]}")
            return ""
        except httpx.ConnectError:
            logger.warning(f"{self._label}: Connection failed to {self.base_url}")
            return ""
        except httpx.TimeoutException:
            logger.warning(f"{self._label}: Request timed out.")
            return ""
