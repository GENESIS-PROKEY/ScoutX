"""JavaScript Discovery Plugin — find and download JS assets.

Crawls alive hosts, extracts <script src> tags and inline JS references,
downloads the JS files, and stores them for endpoint/secret analysis.
"""
from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path
from typing import Any, TYPE_CHECKING
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin
from scoutx.utils.io import atomic_write_text, write_json, write_jsonl
from scoutx.utils.crypto import fingerprint

if TYPE_CHECKING:
    from scoutx.core.engine import ScanContext

logger = logging.getLogger("scoutx.plugins.js")

JS_EXTENSIONS = (".js", ".mjs", ".jsx", ".ts", ".tsx")
SCRIPT_SRC_RE = re.compile(r"""(?:src|href)\s*=\s*["']([^"']*\.(?:js|mjs)(?:\?[^"']*)?)["']""", re.IGNORECASE)
JS_MAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)", re.IGNORECASE)


class Plugin(ScoutPlugin):
    """JavaScript file discovery and download."""

    meta = PluginMeta(
        name="js",
        description="Discover and download JavaScript assets from alive hosts",
        version="0.1.0",
        author="ScoutX",
        tags=["analysis", "javascript", "assets"],
    )
    depends_on: list[str] = ["probe"]
    concurrent_with: list[str] = ["parameters"]

    async def run(self, context: ScanContext) -> PluginResult:
        from scoutx.cli.ui import info, success

        probe_data = context.result_data("probe")
        alive_hosts = probe_data.get("alive_hosts", [])
        if not alive_hosts:
            return PluginResult.skipped("No alive hosts to analyze")

        output_dir = context.output_dir / "js"
        output_dir.mkdir(parents=True, exist_ok=True)
        downloads_dir = output_dir / "downloads"
        downloads_dir.mkdir(parents=True, exist_ok=True)

        config = context.config
        concurrency = int(config.get_profiled("concurrency.js", context.profile) or 10)
        html_ceiling = int(config.get_profiled("request_ceilings.js_html", context.profile) or 40)
        dl_ceiling = int(config.get_profiled("request_ceilings.js_downloads", context.profile) or 150)

        # Only probe a subset of alive hosts for JS
        hosts_to_crawl = alive_hosts[:html_ceiling]
        info(f"Crawling {len(hosts_to_crawl)} hosts for JavaScript references...")

        semaphore = asyncio.Semaphore(concurrency)
        all_js_urls: set[str] = set()
        js_by_host: dict[str, list[str]] = {}

        async def extract_js_from_host(host_data: dict[str, Any]) -> None:
            async with semaphore:
                url = host_data.get("final_url") or host_data.get("url", "")
                hostname = host_data.get("hostname", "")
                if not url:
                    return

                try:
                    async with httpx.AsyncClient(
                        follow_redirects=True, verify=False,
                        timeout=httpx.Timeout(10.0, connect=5.0),
                    ) as client:
                        resp = await client.get(url)
                        if resp.status_code != 200:
                            return

                        html = resp.text[:200_000]  # Cap parsing at 200KB
                        base_url = str(resp.url)

                        # Parse with BeautifulSoup
                        soup = BeautifulSoup(html, "html.parser")
                        found: list[str] = []

                        # <script src="...">
                        for tag in soup.find_all("script", src=True):
                            src = tag["src"].strip()
                            if src:
                                absolute = urljoin(base_url, src)
                                found.append(absolute)
                                all_js_urls.add(absolute)

                        # Regex fallback for dynamically loaded JS
                        for match in SCRIPT_SRC_RE.finditer(html):
                            src = match.group(1).strip()
                            if src and not src.startswith("data:"):
                                absolute = urljoin(base_url, src)
                                found.append(absolute)
                                all_js_urls.add(absolute)

                        if found:
                            js_by_host[hostname] = list(set(found))

                except Exception as exc:
                    logger.debug("JS extraction failed for %s: %s", url, exc)

        tasks = [extract_js_from_host(h) for h in hosts_to_crawl]
        await asyncio.gather(*tasks, return_exceptions=True)

        info(f"Found {len(all_js_urls)} unique JS URLs across {len(js_by_host)} hosts")

        # Download JS files
        js_to_download = list(all_js_urls)[:dl_ceiling]
        info(f"Downloading {len(js_to_download)} JS files...")

        downloaded: list[dict[str, Any]] = []
        seen_hashes: set[str] = set()

        async def download_js(js_url: str) -> None:
            async with semaphore:
                try:
                    async with httpx.AsyncClient(
                        follow_redirects=True, verify=False,
                        timeout=httpx.Timeout(15.0, connect=5.0),
                    ) as client:
                        resp = await client.get(js_url)
                        if resp.status_code != 200:
                            return
                        content = resp.text
                        if not content or len(content) < 10:
                            return

                        # Dedup by content hash
                        content_fp = fingerprint(content)
                        if content_fp in seen_hashes:
                            return
                        seen_hashes.add(content_fp)

                        # Save to disk
                        parsed = urlparse(js_url)
                        safe_name = re.sub(r"[^\w\-.]", "_", parsed.path.split("/")[-1] or "index.js")
                        safe_name = f"{content_fp[:8]}_{safe_name}"
                        file_path = downloads_dir / safe_name
                        atomic_write_text(file_path, content)

                        downloaded.append({
                            "url": js_url,
                            "file": str(file_path),
                            "size": len(content),
                            "hash": content_fp,
                            "hostname": parsed.hostname or "",
                        })

                except Exception as exc:
                    logger.debug("JS download failed for %s: %s", js_url, exc)

        dl_tasks = [download_js(url) for url in js_to_download]
        await asyncio.gather(*dl_tasks, return_exceptions=True)

        info(f"Downloaded {len(downloaded)} unique JS files ({sum(d['size'] for d in downloaded) / 1024:.0f} KB)")

        # Write outputs
        atomic_write_text(output_dir / "js_urls.txt", "\n".join(sorted(all_js_urls)) + "\n")
        write_jsonl(output_dir / "js_files.jsonl", downloaded)
        write_json(output_dir / "js_files.json", {
            "target": context.target,
            "total_urls": len(all_js_urls),
            "downloaded": len(downloaded),
            "by_host": {k: len(v) for k, v in js_by_host.items()},
            "files": downloaded,
        })

        success(f"JS discovery complete: {len(all_js_urls)} URLs, {len(downloaded)} downloaded")

        return PluginResult.completed(
            data={
                "js_urls": sorted(all_js_urls),
                "downloaded_files": downloaded,
                "js_by_host": js_by_host,
            },
            findings_count=len(downloaded),
            artifacts=[output_dir / "js_urls.txt", output_dir / "js_files.jsonl"],
        )

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={"js_urls": list, "downloaded_files": list},
            description="JavaScript URLs and downloaded file metadata",
        )
