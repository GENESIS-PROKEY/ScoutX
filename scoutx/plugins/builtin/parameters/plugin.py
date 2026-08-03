"""Parameter Discovery Plugin — historical URL parameters from Wayback/CommonCrawl.

Finds URL parameters that have been historically associated with the target.
These are gold for fuzzing, injection testing, and IDOR discovery.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

import httpx

from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin
from scoutx.utils.io import atomic_write_text, write_json, write_jsonl

if TYPE_CHECKING:
    from scoutx.core.engine import ScanContext

logger = logging.getLogger("scoutx.plugins.parameters")

INTERESTING_PARAMS = {
    "id", "page", "url", "redirect", "next", "return", "rurl", "callback",
    "file", "path", "include", "dir", "search", "query", "q",
    "token", "key", "api_key", "apikey", "secret", "password", "pass",
    "user", "username", "email", "admin", "debug", "test",
    "cmd", "exec", "command", "action", "do", "func", "function",
    "template", "view", "render", "lang", "locale",
    "dest", "destination", "continue", "target", "site",
}


class Plugin(ScoutPlugin):
    """URL parameter discovery via Wayback Machine and CommonCrawl."""

    meta = PluginMeta(
        name="parameters",
        description="Historical URL parameter discovery for fuzzing targets",
        version="0.1.0",
        author="ScoutX",
        tags=["analysis", "parameters", "fuzzing"],
    )
    depends_on: list[str] = ["probe"]
    concurrent_with: list[str] = ["js"]

    async def run(self, context: ScanContext) -> PluginResult:
        from scoutx.cli.ui import info, success

        output_dir = context.output_dir / "parameters"
        output_dir.mkdir(parents=True, exist_ok=True)

        config = context.config
        ceiling = int(config.get_profiled("request_ceilings.historical_urls", context.profile) or 1000)

        target = context.target
        info(f"Fetching historical URLs for {target}...")

        all_urls: set[str] = set()
        all_params: dict[str, set[str]] = {}  # param_name -> set of example values
        parameterized_urls: list[dict[str, Any]] = []

        # Source 1: Wayback Machine (with retry — this API is flaky)
        for attempt in range(3):
            try:
                async with httpx.AsyncClient(
                    trust_env=False, follow_redirects=True, verify=False,
                    timeout=httpx.Timeout(45.0, connect=15.0),
                ) as client:
                    resp = await client.get(
                        "https://web.archive.org/cdx/search/cdx",
                        params={
                            "url": f"*.{target}/*",
                            "output": "text",
                            "fl": "original",
                            "collapse": "urlkey",
                            "filter": "statuscode:200",
                            "limit": ceiling,
                        },
                    )
                    if resp.status_code == 200:
                        for line in resp.text.splitlines():
                            url = line.strip()
                            if url and "?" in url:
                                all_urls.add(url)
                        info(f"  Wayback: {len(all_urls)} parameterized URLs")
                        break
                    elif resp.status_code in (429, 503):
                        wait = 2 ** (attempt + 1)
                        logger.info("Wayback returned %d, retrying in %ds...", resp.status_code, wait)
                        await asyncio.sleep(wait)
                    else:
                        break
            except Exception as exc:
                if attempt < 2:
                    wait = 2 ** (attempt + 1)
                    logger.info("Wayback fetch failed (attempt %d): %s, retrying in %ds", attempt + 1, exc, wait)
                    await asyncio.sleep(wait)
                else:
                    logger.warning("Wayback parameter fetch failed after 3 attempts: %s", exc)

        # Source 2: AlienVault OTX URL list
        try:
            async with httpx.AsyncClient(
                trust_env=False, follow_redirects=True, verify=False,
                timeout=httpx.Timeout(20.0, connect=10.0),
            ) as client:
                resp = await client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/url_list",
                    params={"limit": 500},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data.get("url_list", []):
                        url = entry.get("url", "")
                        if url and "?" in url:
                            all_urls.add(url)
                    info("  OTX: fetched additional URLs")
        except Exception as exc:
            logger.debug("OTX URL fetch failed: %s", exc)

        # Extract unique parameters
        for url in all_urls:
            try:
                parsed = urlparse(url)
                if not parsed.query:
                    continue
                params = parse_qs(parsed.query, keep_blank_values=True)
                hostname = (parsed.hostname or "").lower()

                for param_name, values in params.items():
                    clean_name = param_name.strip()
                    if clean_name:
                        if clean_name not in all_params:
                            all_params[clean_name] = set()
                        for v in values[:3]:  # Keep a few example values
                            all_params[clean_name].add(v[:100])

                is_interesting = bool(set(params.keys()) & INTERESTING_PARAMS)
                parameterized_urls.append({
                    "url": url,
                    "hostname": hostname,
                    "path": parsed.path,
                    "params": list(params.keys()),
                    "interesting": is_interesting,
                })

            except Exception:
                continue

        # Sort params by frequency (most common first)
        param_freq = sorted(
            [(name, len(vals)) for name, vals in all_params.items()],
            key=lambda x: x[1],
            reverse=True,
        )

        interesting_params = [p for p, _ in param_freq if p.lower() in INTERESTING_PARAMS]
        info(f"Found {len(all_params)} unique parameters ({len(interesting_params)} interesting)")

        # Write outputs
        param_lines = [f"{name} ({count})" for name, count in param_freq]
        atomic_write_text(output_dir / "parameters.txt", "\n".join(param_lines) + "\n")

        write_jsonl(output_dir / "parameters.jsonl", [
            {"name": name, "frequency": count, "interesting": name.lower() in INTERESTING_PARAMS,
             "examples": sorted(list(all_params[name]))[:5]}
            for name, count in param_freq
        ])

        write_json(output_dir / "parameters.json", {
            "target": target,
            "total_urls": len(all_urls),
            "total_params": len(all_params),
            "interesting_params": interesting_params,
            "param_frequency": dict(param_freq[:100]),
            "parameterized_urls_count": len(parameterized_urls),
        })

        success(f"Parameter discovery: {len(all_params)} params from {len(all_urls)} URLs")

        return PluginResult.completed(
            data={
                "params": dict(param_freq),
                "interesting_params": interesting_params,
                "parameterized_urls": parameterized_urls[:500],
            },
            findings_count=len(all_params),
            artifacts=[output_dir / "parameters.txt"],
        )

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={"params": dict, "interesting_params": list},
            description="URL parameters with frequency and interest scoring",
        )
