"""Directory & File Brute-Force Plugin — wraps ffuf/feroxbuster with built-in fallback.

Covers methodology Phase 09.4. Discovers hidden paths, admin panels,
backup files, config files, and API endpoints via directory fuzzing.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin
from scoutx.utils.io import write_json

if TYPE_CHECKING:
    from scoutx.core.engine import ScanContext

logger = logging.getLogger("scoutx.plugins.directories")

# Built-in wordlist for fallback (top sensitive paths)
BUILTIN_PATHS = [
    # Admin panels
    "/admin", "/admin/", "/administrator", "/admin/login", "/wp-admin",
    "/dashboard", "/manage", "/management", "/panel", "/cpanel",
    # Config / Backup
    "/.env", "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.svn/entries", "/.htaccess", "/.htpasswd",
    "/web.config", "/wp-config.php.bak", "/config.php.bak",
    "/config.yml", "/config.json", "/settings.json",
    "/backup.sql", "/backup.zip", "/backup.tar.gz",
    "/db.sql", "/database.sql", "/dump.sql",
    # API / Debug
    "/api", "/api/v1", "/api/v2", "/api/docs", "/api/swagger",
    "/swagger", "/swagger.json", "/swagger-ui",
    "/graphql", "/graphiql",
    "/debug", "/debug/pprof", "/trace", "/metrics", "/healthz",
    "/server-status", "/server-info", "/.well-known/security.txt",
    # Common CMS
    "/wp-login.php", "/wp-json", "/xmlrpc.php",
    "/wp-content/uploads", "/wp-includes",
    "/sitemap.xml", "/robots.txt", "/crossdomain.xml",
    # Technology specific
    "/actuator", "/actuator/env", "/actuator/health",
    "/elmah.axd", "/trace.axd",
    "/phpinfo.php", "/info.php",
    "/console", "/jmx-console",
    "/manager/html", "/status",
    # Backup extensions
    "/index.php.bak", "/index.php.old", "/index.php~",
    "/index.html.bak", "/index.html.old",
    "/.DS_Store", "/Thumbs.db",
]


class Plugin(ScoutPlugin):
    """Directory brute-force — ffuf/feroxbuster wrapper with built-in fallback."""

    meta = PluginMeta(
        name="directories",
        description="Directory and file discovery via fuzzing (ffuf/feroxbuster/built-in)",
        version="0.1.0",
        author="ScoutX",
        tags=["directories", "fuzzing", "brute-force", "discovery"],
    )
    depends_on: list[str] = ["probe"]
    concurrent_with: list[str] = ["cors", "js", "parameters", "takeover", "screenshots"]

    async def run(self, context: ScanContext) -> PluginResult:
        from scoutx.cli.ui import info, success

        output_dir = context.output_dir / "directories"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Get alive hosts from probe
        probe_data = context.result_data("probe")
        alive_urls = self._get_alive_urls(probe_data)

        if not alive_urls:
            return PluginResult.skipped("No alive hosts from probe")

        # Pick top targets (don't fuzz everything)
        targets = alive_urls[:5]

        all_findings: list[dict[str, Any]] = []

        # Try external tools first
        if shutil.which("ffuf"):
            info("Using ffuf for directory discovery...")
            findings = await self._run_ffuf(targets, output_dir)
            all_findings.extend(findings)
        elif shutil.which("feroxbuster"):
            info("Using feroxbuster for directory discovery...")
            findings = await self._run_feroxbuster(targets, output_dir)
            all_findings.extend(findings)
        else:
            info("Using built-in directory scanner (install ffuf/feroxbuster for better results)...")
            findings = await self._builtin_scan(targets, context.config)
            all_findings.extend(findings)

        # Always run backup file check
        info("Checking for backup and sensitive files...")
        backup_findings = await self._check_sensitive_files(targets)
        all_findings.extend(backup_findings)

        # Deduplicate
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for f in all_findings:
            key = f.get("url", "") + str(f.get("status", ""))
            if key not in seen:
                seen.add(key)
                unique.append(f)

        data = {
            "targets_scanned": len(targets),
            "findings": unique,
            "findings_count": len(unique),
            "method": "ffuf" if shutil.which("ffuf") else (
                "feroxbuster" if shutil.which("feroxbuster") else "builtin"
            ),
        }

        write_json(output_dir / "directories.json", data)
        success(f"Directory scan: {len(unique)} paths found across {len(targets)} targets")

        return PluginResult.completed(data=data, findings_count=len(unique))

    def _get_alive_urls(self, probe_data: dict[str, Any]) -> list[str]:
        """Extract alive URLs from probe results."""
        hosts = probe_data.get("hosts", [])
        urls: list[str] = []
        for h in hosts:
            if isinstance(h, dict):
                url = h.get("url", h.get("input", ""))
                if url:
                    urls.append(url)
            elif isinstance(h, str):
                urls.append(h)
        return urls

    async def _run_ffuf(self, targets: list[str], output_dir: Path) -> list[dict]:
        """Run ffuf against targets."""
        findings: list[dict] = []
        for target in targets[:3]:
            try:
                out_file = output_dir / f"ffuf_{target.replace('://', '_').replace('/', '_')[:40]}.json"
                proc = await asyncio.create_subprocess_exec(
                    "ffuf", "-u", f"{target.rstrip('/')}/FUZZ",
                    "-w", "-",  # stdin wordlist
                    "-mc", "200,301,302,403",
                    "-t", "20",
                    "-timeout", "5",
                    "-o", str(out_file),
                    "-of", "json",
                    "-s",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                wordlist = "\n".join(p.lstrip("/") for p in BUILTIN_PATHS)
                await asyncio.wait_for(
                    proc.communicate(input=wordlist.encode()),
                    timeout=60,
                )
                if out_file.exists():
                    data = json.loads(out_file.read_text(encoding="utf-8"))
                    for result in data.get("results", []):
                        findings.append({
                            "url": result.get("url", ""),
                            "status": result.get("status", 0),
                            "length": result.get("length", 0),
                            "words": result.get("words", 0),
                            "source": "ffuf",
                        })
            except Exception as exc:
                logger.warning("ffuf failed for %s: %s", target, exc)
        return findings

    async def _run_feroxbuster(self, targets: list[str], output_dir: Path) -> list[dict]:
        """Run feroxbuster against targets."""
        findings: list[dict] = []
        for target in targets[:3]:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "feroxbuster", "-u", target,
                    "--depth", "1", "--threads", "20",
                    "--timeout", "5", "--quiet", "--json",
                    "--status-codes", "200,301,302,403",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
                for line in stdout.decode("utf-8", errors="replace").splitlines():
                    try:
                        entry = json.loads(line)
                        if entry.get("type") == "response":
                            findings.append({
                                "url": entry.get("url", ""),
                                "status": entry.get("status", 0),
                                "length": entry.get("content_length", 0),
                                "source": "feroxbuster",
                            })
                    except json.JSONDecodeError:
                        pass
            except Exception as exc:
                logger.warning("feroxbuster failed for %s: %s", target, exc)
        return findings

    async def _builtin_scan(self, targets: list[str], config: Any) -> list[dict]:
        """Built-in async HTTP directory scanner."""
        findings: list[dict] = []
        async with httpx.AsyncClient(
            trust_env=False, timeout=8, follow_redirects=False, verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        ) as client:
            for target in targets[:3]:
                tasks = []
                for path in BUILTIN_PATHS:
                    url = target.rstrip("/") + path
                    tasks.append(self._check_path(client, url))

                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, dict):
                        findings.append(r)
        return findings

    async def _check_path(self, client: httpx.AsyncClient, url: str) -> dict | None:
        """Check a single path."""
        try:
            r = await client.get(url)
            if r.status_code in (200, 301, 302, 403):
                return {
                    "url": url,
                    "status": r.status_code,
                    "length": len(r.content),
                    "source": "builtin",
                }
        except Exception:
            pass
        return None

    async def _check_sensitive_files(self, targets: list[str]) -> list[dict]:
        """Check for common backup and sensitive files."""
        sensitive = [
            "/.env", "/.git/config", "/.git/HEAD",
            "/backup.sql", "/backup.zip", "/.htpasswd",
            "/web.config", "/wp-config.php.bak",
            "/.DS_Store", "/crossdomain.xml",
        ]
        findings: list[dict] = []
        async with httpx.AsyncClient(
            trust_env=False, timeout=5, follow_redirects=False, verify=False,
        ) as client:
            for target in targets[:3]:
                for path in sensitive:
                    try:
                        r = await client.get(target.rstrip("/") + path)
                        if r.status_code == 200 and len(r.content) > 10:
                            findings.append({
                                "url": target.rstrip("/") + path,
                                "status": 200,
                                "length": len(r.content),
                                "type": "sensitive_file",
                                "source": "builtin_sensitive",
                            })
                    except Exception:
                        pass
        return findings

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={"findings": list, "findings_count": int, "method": str},
            description="Discovered directories, files, and sensitive paths",
        )
