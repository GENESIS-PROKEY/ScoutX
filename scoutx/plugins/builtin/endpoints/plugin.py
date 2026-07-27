"""Endpoint Extraction Plugin — mine API routes and paths from JavaScript.

Parses downloaded JS files with regex patterns to extract API endpoints,
internal URLs, paths, and route definitions. Categorizes them by type
(API, admin, auth, file, etc.) for targeted testing.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, TYPE_CHECKING

from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin
from scoutx.utils.io import atomic_write_text, write_json, write_jsonl

if TYPE_CHECKING:
    from scoutx.core.engine import ScanContext

logger = logging.getLogger("scoutx.plugins.endpoints")

# Regex patterns for endpoint extraction
ENDPOINT_PATTERNS = [
    # Quoted paths: "/api/v1/users"
    re.compile(r"""["'](/[a-zA-Z0-9_\-./]+(?:\?[a-zA-Z0-9_&=]*)?)["']"""),
    # fetch/axios/XMLHttpRequest URLs
    re.compile(r"""(?:fetch|axios|\.get|\.post|\.put|\.delete|\.patch|\.request)\s*\(\s*["'`]([^"'`]+)["'`]""", re.IGNORECASE),
    # Route definitions: path: "/api/users"
    re.compile(r"""(?:path|route|url|endpoint|uri|href|action|src)\s*[:=]\s*["'`](/[^"'`\s]+)["'`]""", re.IGNORECASE),
    # Template literals: `${baseUrl}/api/users`
    re.compile(r"""`[^`]*(/[a-zA-Z0-9_\-./]+(?:\?[^`]*)?)`"""),
    # API version patterns
    re.compile(r"""["']((?:/api/|/v[0-9]+/|/rest/|/graphql|/webhook)[a-zA-Z0-9_\-./]*)["']""", re.IGNORECASE),
]

# Paths to filter out (noise)
NOISE_PATTERNS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".min.", "node_modules",
    "webpack", "chunk", "bundle", "vendor", "polyfill",
}

# Category patterns
CATEGORY_PATTERNS: dict[str, re.Pattern[str]] = {
    "api": re.compile(r"/api/|/v[0-9]+/|/rest/|/graphql|/webhook", re.IGNORECASE),
    "admin": re.compile(r"/admin|/manage|/dashboard|/panel|/control", re.IGNORECASE),
    "auth": re.compile(r"/auth|/login|/logout|/signup|/register|/password|/oauth|/token|/session", re.IGNORECASE),
    "upload": re.compile(r"/upload|/file|/attachment|/media|/image|/document", re.IGNORECASE),
    "debug": re.compile(r"/debug|/test|/dev|/staging|/internal|/health|/status|/info|/env", re.IGNORECASE),
    "config": re.compile(r"/config|/settings|/setup|/install|\.env|\.conf|\.xml|\.json|\.yaml", re.IGNORECASE),
    "data": re.compile(r"/export|/import|/download|/backup|/dump|/report", re.IGNORECASE),
}


class Plugin(ScoutPlugin):
    """Endpoint extraction from downloaded JavaScript files."""

    meta = PluginMeta(
        name="endpoints",
        description="Extract API endpoints and paths from JavaScript files",
        version="0.1.0",
        author="ScoutX",
        tags=["analysis", "endpoints", "api"],
    )
    depends_on: list[str] = ["js"]
    concurrent_with: list[str] = ["secrets"]

    async def run(self, context: ScanContext) -> PluginResult:
        from scoutx.cli.ui import info, success

        js_data = context.result_data("js")
        downloaded_files = js_data.get("downloaded_files", [])
        if not downloaded_files:
            return PluginResult.skipped("No JS files to analyze")

        output_dir = context.output_dir / "endpoints"
        output_dir.mkdir(parents=True, exist_ok=True)

        info(f"Analyzing {len(downloaded_files)} JS files for endpoints...")

        all_endpoints: dict[str, dict[str, Any]] = {}  # path -> metadata
        endpoints_by_file: dict[str, list[str]] = {}

        for js_file in downloaded_files:
            file_path = Path(js_file.get("file", ""))
            js_url = js_file.get("url", "")

            if not file_path.exists():
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            found_in_file: set[str] = set()

            for pattern in ENDPOINT_PATTERNS:
                for match in pattern.finditer(content):
                    endpoint = match.group(1).strip()
                    if _is_valid_endpoint(endpoint):
                        found_in_file.add(endpoint)

            for endpoint in found_in_file:
                if endpoint not in all_endpoints:
                    categories = _categorize(endpoint)
                    all_endpoints[endpoint] = {
                        "path": endpoint,
                        "categories": categories,
                        "sources": [js_url],
                        "interesting": bool(categories),
                    }
                else:
                    if js_url not in all_endpoints[endpoint]["sources"]:
                        all_endpoints[endpoint]["sources"].append(js_url)

            if found_in_file:
                endpoints_by_file[js_url] = sorted(found_in_file)

        # Sort by interest level — categorized endpoints first
        sorted_endpoints = sorted(
            all_endpoints.values(),
            key=lambda e: (not e["interesting"], e["path"]),
        )

        # Stats
        total = len(sorted_endpoints)
        interesting = sum(1 for e in sorted_endpoints if e["interesting"])
        by_category: dict[str, int] = {}
        for ep in sorted_endpoints:
            for cat in ep["categories"]:
                by_category[cat] = by_category.get(cat, 0) + 1

        info(f"Found {total} endpoints ({interesting} interesting)")
        for cat, count in sorted(by_category.items(), key=lambda x: x[1], reverse=True):
            info(f"  {cat}: {count}")

        # Write outputs
        all_paths = [ep["path"] for ep in sorted_endpoints]
        atomic_write_text(output_dir / "endpoints.txt", "\n".join(all_paths) + "\n")

        write_jsonl(output_dir / "endpoints.jsonl", sorted_endpoints)
        write_json(output_dir / "endpoints.json", {
            "target": context.target,
            "total": total,
            "interesting": interesting,
            "by_category": by_category,
            "endpoints": sorted_endpoints,
        })

        # Store interesting endpoints as findings
        try:
            if context.db:
                for ep in sorted_endpoints:
                    if ep["interesting"]:
                        await context.db.add_finding(
                            context.scan_id,
                            plugin_name="endpoints",
                            finding_type="endpoint",
                            severity="info",
                            confidence="medium",
                            title=f"Interesting endpoint: {ep['path']}",
                            description=f"Categories: {', '.join(ep['categories'])}",
                            target_url=ep["path"],
                            raw_data=ep,
                        )
        except Exception as exc:
            logger.warning("Failed to store endpoints: %s", exc)

        success(f"Endpoint extraction complete: {total} endpoints, {interesting} interesting")

        return PluginResult.completed(
            data={"endpoints": sorted_endpoints, "by_category": by_category},
            findings_count=total,
            artifacts=[output_dir / "endpoints.txt"],
        )

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={"endpoints": list, "by_category": dict},
            description="Extracted endpoints with categorization",
        )


def _is_valid_endpoint(endpoint: str) -> bool:
    """Filter out noise and invalid endpoints."""
    if not endpoint or len(endpoint) < 2 or len(endpoint) > 300:
        return False
    if not endpoint.startswith("/"):
        return False
    # Filter out static assets and noise
    lower = endpoint.lower()
    for noise in NOISE_PATTERNS:
        if noise in lower:
            return False
    # Filter out pure numbers after slash
    if re.match(r"^/\d+$", endpoint):
        return False
    return True


def _categorize(endpoint: str) -> list[str]:
    """Categorize an endpoint based on path patterns."""
    categories = []
    for category, pattern in CATEGORY_PATTERNS.items():
        if pattern.search(endpoint):
            categories.append(category)
    return categories
