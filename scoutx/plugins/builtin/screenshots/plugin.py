"""Screenshots plugin — Playwright-based full-page screenshot capture.

Captures each alive host in a headless Chromium browser with anti-detection
flags. Screenshots are saved as PNGs and referenced in reports.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin

logger = logging.getLogger("scoutx.plugins.screenshots")


class Plugin(ScoutPlugin):
    """Capture full-page screenshots of alive hosts using Playwright."""

    meta = PluginMeta(
        name="screenshots",
        description="Full-page screenshots of alive hosts via Playwright",
        version="0.1.0",
        author="ScoutX",
        tags=["visual", "screenshots", "browser"],
    )
    depends_on: list[str] = ["probe"]
    concurrent_with: list[str] = ["endpoints", "secrets"]

    async def run(self, context) -> PluginResult:
        """Screenshot all alive hosts."""
        from scoutx.cli.ui import info, success, warn

        config = context.config
        probe_data = context.result_data("probe")

        # Probe data can come in two shapes:
        # 1. In-memory (PluginResult.data): {"alive_hosts": ["host1", ...], "alive_urls": [...]}
        # 2. From JSON file: {"hosts": [{hostname, url, status_code, ...}, ...]}
        hosts = probe_data.get("hosts", [])

        # If we got the in-memory shape, build targets from alive_hosts
        if not hosts:
            alive_hostnames = probe_data.get("alive_hosts", [])
            alive_urls = probe_data.get("alive_urls", [])
            if alive_hostnames:
                hosts = []
                for i, hostname in enumerate(alive_hostnames):
                    url = alive_urls[i] if i < len(alive_urls) else f"https://{hostname}"
                    hosts.append({
                        "hostname": hostname,
                        "final_url": url,
                        "status_code": 200,
                    })

        if not hosts:
            return PluginResult.skipped("No alive hosts to screenshot")

        # Only screenshot hosts with successful status codes
        targets = []
        for h in hosts:
            url = h.get("final_url") or f"https://{h.get('hostname', '')}"
            status = h.get("status_code", 0)
            if 200 <= status < 400:
                targets.append({
                    "hostname": h.get("hostname", ""),
                    "url": url,
                    "status_code": status,
                })

        if not targets:
            return PluginResult.skipped("No hosts with valid status codes to screenshot")


        info(f"Screenshotting {len(targets)} hosts...")

        # Import playwright
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.warning("Playwright not installed, skipping screenshots")
            return PluginResult.skipped(
                "Playwright not installed. Run: pip install playwright && playwright install chromium"
            )

        out_dir = context.output_dir / "screenshots"
        out_dir.mkdir(parents=True, exist_ok=True)

        viewport = {
            "width": config.get("screenshots.viewport_width", 1440),
            "height": config.get("screenshots.viewport_height", 900),
        }
        timeout_ms = config.get("screenshots.timeout", 15) * 1000
        concurrency = config.get("screenshots.concurrency", 3)

        screenshots: list[dict[str, Any]] = []
        semaphore = asyncio.Semaphore(concurrency)

        async def _capture(target: dict, pw_browser) -> dict[str, Any] | None:
            async with semaphore:
                hostname = target["hostname"]
                url = target["url"]
                safe_name = hostname.replace(".", "_").replace(":", "_")
                file_path = out_dir / f"{safe_name}.png"

                try:
                    page = await pw_browser.new_page(
                        viewport=viewport,
                        user_agent=(
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/120.0.0.0 Safari/537.36"
                        ),
                        ignore_https_errors=True,
                    )

                    # Anti-detection
                    await page.add_init_script("""
                        Object.defineProperty(navigator, 'webdriver', {get: () => false});
                    """)

                    await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)

                    # Wait a bit for dynamic content
                    await asyncio.sleep(1)

                    await page.screenshot(
                        path=str(file_path),
                        full_page=True,
                        type="png",
                    )
                    await page.close()

                    logger.info("Screenshot captured: %s -> %s", url, file_path.name)
                    return {
                        "hostname": hostname,
                        "url": url,
                        "file": file_path.name,
                        "path": str(file_path),
                        "success": True,
                    }

                except Exception as exc:
                    logger.warning("Screenshot failed for %s: %s", url, exc)
                    try:
                        await page.close()
                    except Exception:
                        pass
                    return {
                        "hostname": hostname,
                        "url": url,
                        "success": False,
                        "error": str(exc)[:200],
                    }

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-blink-features=AutomationControlled",
                    ],
                )

                tasks = [_capture(t, browser) for t in targets]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for r in results:
                    if isinstance(r, dict):
                        screenshots.append(r)
                    elif isinstance(r, Exception):
                        logger.warning("Screenshot task error: %s", r)

                await browser.close()

        except Exception as exc:
            err_msg = str(exc)
            if "Executable doesn't exist" in err_msg or "playwright install" in err_msg.lower():
                logger.warning("Playwright browsers not installed, skipping screenshots")
                warn(f"Failed screenshots: {exc}")
                return PluginResult.skipped(
                    "Playwright browsers not installed. Run: playwright install chromium"
                )
            logger.error("Browser launch failed: %s", exc)
            return PluginResult.failed(f"Browser launch failed: {exc}")

        captured = sum(1 for s in screenshots if s.get("success"))
        failed = len(screenshots) - captured

        data = {
            "total": len(targets),
            "captured": captured,
            "failed": failed,
            "screenshots": screenshots,
        }

        # Write results
        from scoutx.utils.io import write_json
        write_json(out_dir / "screenshots.json", data)

        success(f"Screenshots captured: {captured}/{len(targets)} ({failed} failed)")

        return PluginResult.completed(
            data=data,
            findings_count=captured,
            artifacts=[out_dir / "screenshots.json"],
        )

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={"screenshots": list, "captured": int, "failed": int},
            description="Full-page screenshots of alive hosts",
        )
