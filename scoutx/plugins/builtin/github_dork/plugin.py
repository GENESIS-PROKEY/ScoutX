"""GitHub Dorking Plugin — search GitHub for target-related code exposure.

Uses the GitHub Code Search API to find leaked credentials, configs,
internal documentation, and sensitive data in public repositories.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

import httpx

from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin
from scoutx.utils.io import write_json

if TYPE_CHECKING:
    from scoutx.core.engine import ScanContext

logger = logging.getLogger("scoutx.plugins.github_dork")

# Dork query templates — {domain} gets replaced with target
DORK_QUERIES = [
    '"{domain}" password',
    '"{domain}" api_key',
    '"{domain}" apikey',
    '"{domain}" secret',
    '"{domain}" token',
    '"{domain}" aws_secret',
    '"{domain}" private_key',
    '"{domain}" jdbc:',
    '"{domain}" smtp',
    '"{domain}" mongodb://',
    '"{domain}" redis://',
    '"{domain}" BEGIN RSA',
    '"{domain}" BEGIN OPENSSH',
    '"{domain}" Authorization: Bearer',
    '"{domain}" internal',
    '"{domain}" staging',
    '"{domain}" admin',
    '"{domain}" config',
    '"{domain}" .env',
    '"{domain}" credentials',
]

# Org-specific dorks (if org name is known)
ORG_DORKS = [
    "org:{org} password",
    "org:{org} secret",
    "org:{org} api_key",
    "org:{org} token",
    "org:{org} BEGIN RSA",
    "org:{org} .env",
    "org:{org} internal",
]

GITHUB_API = "https://api.github.com"


class Plugin(ScoutPlugin):
    """Search GitHub for target-related code exposure and leaked secrets."""

    meta = PluginMeta(
        name="github_dork",
        description="GitHub dorking — find leaked credentials and configs in public repos",
        version="0.1.0",
        author="ScoutX",
        tags=["github", "osint", "secrets", "dorking", "leaks"],
    )
    depends_on: list[str] = ["osint"]
    concurrent_with: list[str] = ["historical"]

    async def run(self, context: ScanContext) -> PluginResult:
        from scoutx.cli.ui import info, success, warn

        # Check for GitHub API token
        api_key = context.config.get("api_keys.github", "")
        if not api_key:
            return PluginResult.skipped(
                "GitHub API token required. Set api_keys.github in config."
            )

        output_dir = context.output_dir / "github_dork"
        output_dir.mkdir(parents=True, exist_ok=True)

        domain = context.target
        info(f"GitHub dorking for: {domain}")

        headers = {
            "Authorization": f"token {api_key}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "ScoutX/2.0",
        }

        findings: list[dict[str, Any]] = []

        # Get org name from OSINT data if available
        osint_data = context.result_data("osint")
        org_name = osint_data.get("github_org", "")

        # Build query list
        queries = [q.format(domain=domain) for q in DORK_QUERIES]
        if org_name:
            queries.extend(q.format(org=org_name) for q in ORG_DORKS)

        # Rate limit: GitHub allows 30 search requests/min with token
        # Use 2-second delay between requests
        async with httpx.AsyncClient(trust_env=False, timeout=15, headers=headers) as client:
            for query in queries:
                try:
                    resp = await client.get(
                        f"{GITHUB_API}/search/code",
                        params={"q": query, "per_page": 5},
                    )

                    if resp.status_code == 403:
                        warn("GitHub rate limit hit. Stopping dork search.")
                        break

                    if resp.status_code == 401:
                        warn("GitHub token invalid.")
                        return PluginResult.skipped("Invalid GitHub API token")

                    if resp.status_code == 200:
                        data = resp.json()
                        items = data.get("items", [])
                        total = data.get("total_count", 0)

                        if total > 0:
                            for item in items[:5]:
                                finding = {
                                    "query": query,
                                    "repository": item.get("repository", {}).get("full_name", ""),
                                    "file_path": item.get("path", ""),
                                    "file_name": item.get("name", ""),
                                    "html_url": item.get("html_url", ""),
                                    "score": item.get("score", 0),
                                    "total_matches": total,
                                }
                                findings.append(finding)

                    # Respect rate limits
                    await asyncio.sleep(2.5)

                except httpx.HTTPError as e:
                    logger.warning(f"GitHub search error for '{query}': {e}")
                    continue

        result = {
            "findings": findings,
            "total_findings": len(findings),
            "queries_executed": len(queries),
            "domain": domain,
            "org_name": org_name,
        }

        write_json(output_dir / "github_findings.json", result)

        if findings:
            success(f"Found {len(findings)} GitHub code exposure results")
        else:
            info("No GitHub code exposure found")

        return PluginResult.completed(data=result, findings_count=len(findings))

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={"findings": list, "total_findings": int, "queries_executed": int},
            description="GitHub code search results for the target domain",
        )
