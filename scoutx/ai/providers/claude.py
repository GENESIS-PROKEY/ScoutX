"""Anthropic Claude LLM provider.

Uses the Anthropic Messages API with native Claude formatting.
"""
from __future__ import annotations

import logging

import httpx

logger = logging.getLogger("scoutx.ai.claude")


class ClaudeClient:
    """Anthropic Claude provider."""

    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        api_key: str = "",
        base_url: str = "https://api.anthropic.com",
    ):
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    def provider_name(self) -> str:
        return f"claude ({self.model})"

    async def generate(
        self, prompt: str, system_prompt: str = "", max_tokens: int = 4096
    ) -> str:
        """Generate via Anthropic Messages API."""
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

        payload: dict = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(
                    f"{self.base_url}/v1/messages",
                    headers=headers,
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                content_blocks = data.get("content", [])
                if content_blocks:
                    return content_blocks[0].get("text", "")
                return ""

        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            if status == 401:
                logger.warning("Claude: Invalid API key.")
            elif status == 429:
                logger.warning("Claude: Rate limited.")
            else:
                logger.warning(f"Claude error {status}: {e.response.text[:200]}")
            return ""
        except httpx.ConnectError:
            logger.warning(f"Claude: Connection failed to {self.base_url}")
            return ""
        except httpx.TimeoutException:
            logger.warning("Claude: Request timed out.")
            return ""
