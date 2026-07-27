"""JS Deep Analysis Plugin — source maps, webpack chunks, SAST, deobfuscation.

Covers methodology Phase 09 deep JS workflow. Runs after the base JS
plugin and performs deeper analysis including source map extraction,
webpack chunk discovery, multi-engine SAST, and secret pattern scanning.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin
from scoutx.utils.io import write_json

if TYPE_CHECKING:
    from scoutx.core.engine import ScanContext

logger = logging.getLogger("scoutx.plugins.js_deep")

# Patterns for detecting obfuscation
OBFUSCATION_INDICATORS = [
    r'eval\s*\(',
    r'atob\s*\(',
    r'String\.fromCharCode',
    r'\bvar\s+_0x[a-f0-9]+',
    r'\\x[0-9a-f]{2}',
    r'\[["\']\w+["\']\]\s*\(',  # bracket notation calls
]

# Webpack chunk patterns
WEBPACK_PATTERNS = [
    r'webpackJsonp',
    r'__webpack_require__',
    r'webpack/runtime',
    r'chunks?\s*[=:]\s*\{',
    r'chunkId',
]


class Plugin(ScoutPlugin):
    """JS Deep Analysis — source maps, SAST, webpack, deobfuscation detection."""

    meta = PluginMeta(
        name="js_deep",
        description="Deep JS analysis: source maps, webpack, SAST, deobfuscation detection",
        version="0.1.0",
        author="ScoutX",
        tags=["javascript", "sast", "sourcemap", "webpack", "secrets"],
    )
    depends_on: list[str] = ["js"]
    concurrent_with: list[str] = ["endpoints"]

    async def run(self, context: ScanContext) -> PluginResult:
        from scoutx.cli.ui import info, success

        output_dir = context.output_dir / "js_deep"
        output_dir.mkdir(parents=True, exist_ok=True)

        js_data = context.result_data("js")
        js_files = js_data.get("js_files", [])

        if not js_files:
            return PluginResult.skipped("No JS files from base JS plugin")

        data: dict[str, Any] = {
            "total_js_files": len(js_files),
            "source_maps": [],
            "webpack_chunks": [],
            "obfuscated_files": [],
            "sast_findings": [],
            "deep_secrets": [],
        }

        # Source map detection and extraction
        info("Scanning for JS source maps...")
        source_maps = await self._detect_source_maps(js_files)
        data["source_maps"] = source_maps

        # Webpack chunk discovery
        info("Analyzing webpack/bundler chunks...")
        webpack = await self._detect_webpack(js_files)
        data["webpack_chunks"] = webpack

        # Obfuscation detection
        info("Checking for obfuscation patterns...")
        obfuscated = self._detect_obfuscation(js_files)
        data["obfuscated_files"] = obfuscated

        # Deep secret patterns (beyond basic regex)
        info("Running deep secret pattern analysis...")
        deep_secrets = self._deep_secret_scan(js_files)
        data["deep_secrets"] = deep_secrets

        # External SAST (if available)
        if shutil.which("semgrep"):
            info("Running semgrep SAST analysis...")
            sast = await self._run_semgrep(js_files, output_dir)
            data["sast_findings"].extend(sast)

        if shutil.which("retire"):
            info("Running retire.js vulnerability check...")
            retire = await self._run_retire(js_files, output_dir)
            data["sast_findings"].extend(retire)

        # Try sourcemapper if available
        if shutil.which("sourcemapper") and source_maps:
            info("Reconstructing source from source maps...")
            await self._run_sourcemapper(source_maps, output_dir)

        total_findings = (
            len(source_maps)
            + len(webpack)
            + len(obfuscated)
            + len(deep_secrets)
            + len(data["sast_findings"])
        )

        write_json(output_dir / "js_deep.json", data)
        success(f"JS deep analysis: {total_findings} findings across {len(js_files)} files")

        return PluginResult.completed(data=data, findings_count=total_findings)

    async def _detect_source_maps(self, js_files: list[dict]) -> list[dict]:
        """Detect and validate source map URLs."""
        source_maps: list[dict] = []
        map_pattern = re.compile(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)')

        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            for js in js_files:
                content = js.get("content", "")
                url = js.get("url", "")

                match = map_pattern.search(content)
                if match:
                    map_url = match.group(1)
                    # Resolve relative URLs
                    if not map_url.startswith("http"):
                        base = url.rsplit("/", 1)[0] if "/" in url else url
                        map_url = f"{base}/{map_url}"

                    # Verify it's accessible
                    accessible = False
                    try:
                        r = await client.head(map_url)
                        accessible = r.status_code == 200
                    except Exception:
                        pass

                    source_maps.append({
                        "js_url": url,
                        "map_url": map_url,
                        "accessible": accessible,
                        "severity": "high" if accessible else "info",
                    })

                # Also check for .map file by convention
                if url.endswith(".js"):
                    map_url = url + ".map"
                    try:
                        r = await client.head(map_url)
                        if r.status_code == 200:
                            source_maps.append({
                                "js_url": url,
                                "map_url": map_url,
                                "accessible": True,
                                "severity": "high",
                                "note": "Source map found by convention (.js.map)",
                            })
                    except Exception:
                        pass

        return source_maps

    async def _detect_webpack(self, js_files: list[dict]) -> list[dict]:
        """Detect webpack/bundler chunk patterns."""
        webpack_files: list[dict] = []
        compiled_patterns = [re.compile(p) for p in WEBPACK_PATTERNS]

        for js in js_files:
            content = js.get("content", "")
            url = js.get("url", "")
            matches = []
            for pat in compiled_patterns:
                if pat.search(content):
                    matches.append(pat.pattern)

            if matches:
                # Try to extract chunk names/IDs
                chunk_ids = re.findall(r'"([a-f0-9]{8,})":\s*["\(]', content)
                webpack_files.append({
                    "url": url,
                    "patterns_found": matches,
                    "chunk_ids": chunk_ids[:20],
                    "is_entry_point": "webpackJsonp" in content or "__webpack_require__" in content,
                })

        return webpack_files

    def _detect_obfuscation(self, js_files: list[dict]) -> list[dict]:
        """Detect obfuscated JS files."""
        obfuscated: list[dict] = []
        compiled_indicators = [re.compile(p) for p in OBFUSCATION_INDICATORS]

        for js in js_files:
            content = js.get("content", "")
            url = js.get("url", "")
            indicators_found = []

            for ind in compiled_indicators:
                if ind.search(content):
                    indicators_found.append(ind.pattern)

            # Also check entropy / variable name patterns
            hex_vars = re.findall(r'\b_0x[a-f0-9]{4,}\b', content)

            if len(indicators_found) >= 2 or len(hex_vars) > 5:
                obfuscated.append({
                    "url": url,
                    "indicators": indicators_found,
                    "hex_variables": len(hex_vars),
                    "confidence": min(1.0, (len(indicators_found) + len(hex_vars)) / 10),
                })

        return obfuscated

    def _deep_secret_scan(self, js_files: list[dict]) -> list[dict]:
        """Advanced secret patterns beyond basic regex."""
        deep_patterns = {
            "jwt_token": re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
            "base64_cred": re.compile(r'(?:password|passwd|secret|token)\s*[=:]\s*["\']([A-Za-z0-9+/]{20,}={0,2})["\']', re.I),
            "internal_ip": re.compile(r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})'),
            "s3_bucket": re.compile(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3[.-](?:us|eu|ap|sa|ca|me|af)'),
            "firebase_url": re.compile(r'https?://[a-z0-9-]+\.firebaseio\.com'),
            "hardcoded_password": re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']', re.I),
            "private_key_marker": re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----'),
            "connection_string": re.compile(r'(?:mongodb|postgres|mysql|redis|amqp)://[^\s"\']+'),
        }

        findings: list[dict] = []
        for js in js_files:
            content = js.get("content", "")
            url = js.get("url", "")

            for secret_type, pattern in deep_patterns.items():
                matches = pattern.findall(content)
                for match in matches[:5]:
                    findings.append({
                        "url": url,
                        "type": secret_type,
                        "match": match[:100] if isinstance(match, str) else str(match)[:100],
                        "severity": "critical" if secret_type in ("jwt_token", "private_key_marker", "connection_string") else "high",
                    })

        return findings

    async def _run_semgrep(self, js_files: list[dict], output_dir: Path) -> list[dict]:
        """Run semgrep SAST on JS files."""
        findings: list[dict] = []
        try:
            # Write JS content to temp files for semgrep
            js_dir = output_dir / "js_tmp"
            js_dir.mkdir(exist_ok=True)
            for i, js in enumerate(js_files[:20]):
                (js_dir / f"file_{i}.js").write_text(
                    js.get("content", ""), encoding="utf-8"
                )

            proc = await asyncio.create_subprocess_exec(
                "semgrep", "--config", "p/javascript",
                "--json", "--quiet", str(js_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            data = json.loads(stdout.decode("utf-8", errors="replace"))
            for result in data.get("results", []):
                findings.append({
                    "rule": result.get("check_id", ""),
                    "message": result.get("extra", {}).get("message", ""),
                    "severity": result.get("extra", {}).get("severity", "WARNING").lower(),
                    "file": result.get("path", ""),
                    "line": result.get("start", {}).get("line", 0),
                    "source": "semgrep",
                })
        except Exception as exc:
            logger.warning("semgrep failed: %s", exc)

        return findings

    async def _run_retire(self, js_files: list[dict], output_dir: Path) -> list[dict]:
        """Run retire.js on JS files."""
        findings: list[dict] = []
        try:
            js_dir = output_dir / "js_tmp"
            proc = await asyncio.create_subprocess_exec(
                "retire", "--jspath", str(js_dir),
                "--outputformat", "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            data = json.loads(stdout.decode("utf-8", errors="replace"))
            for entry in data if isinstance(data, list) else []:
                for vuln in entry.get("vulnerabilities", []):
                    findings.append({
                        "component": entry.get("component", ""),
                        "version": entry.get("version", ""),
                        "severity": vuln.get("severity", "medium"),
                        "summary": vuln.get("identifiers", {}).get("summary", ""),
                        "source": "retire.js",
                    })
        except Exception as exc:
            logger.debug("retire.js failed: %s", exc)
        return findings

    async def _run_sourcemapper(self, source_maps: list[dict], output_dir: Path) -> None:
        """Reconstruct source from accessible source maps."""
        for sm in source_maps:
            if not sm.get("accessible"):
                continue
            try:
                out = output_dir / "reconstructed"
                out.mkdir(exist_ok=True)
                proc = await asyncio.create_subprocess_exec(
                    "sourcemapper", "-url", sm["map_url"],
                    "-output", str(out),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=30)
            except Exception as exc:
                logger.debug("sourcemapper failed: %s", exc)

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={
                "source_maps": list, "webpack_chunks": list,
                "obfuscated_files": list, "sast_findings": list,
                "deep_secrets": list,
            },
            description="Deep JS analysis: source maps, webpack, SAST, obfuscation, secrets",
        )
