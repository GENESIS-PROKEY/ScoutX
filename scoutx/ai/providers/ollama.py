"""Ollama LLM provider — local, free, private.

Connects to a locally running Ollama instance via HTTP.
No API key needed. Perfect for sensitive recon data.
"""
from __future__ import annotations

import logging

import httpx

logger = logging.getLogger("scoutx.ai.ollama")


class OllamaClient:
    """Ollama provider — talks to localhost:11434."""

    def __init__(self, model: str = "llama3.2", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url.rstrip("/")

    def provider_name(self) -> str:
        return f"ollama ({self.model})"

    async def generate(
        self, prompt: str, system_prompt: str = "", max_tokens: int = 4096
    ) -> str:
        """Generate text via Ollama's /api/generate endpoint."""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"num_predict": max_tokens},
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                return data.get("response", "")

        except httpx.ConnectError:
            logger.warning(
                "Ollama not running. Start it with: ollama serve"
            )
            return ""
        except httpx.HTTPStatusError as e:
            logger.warning(f"Ollama error {e.response.status_code}: {e.response.text[:200]}")
            return ""
        except httpx.TimeoutException:
            logger.warning("Ollama request timed out. Model may be loading.")
            return ""
