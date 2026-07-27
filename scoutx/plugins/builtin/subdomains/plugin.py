"""Subdomain Enumeration Plugin — passive + active discovery.

Passive: Queries 12 sources concurrently.
Active (--profile aggressive): DNS brute-force via puredns, permutation
via gotator/alterx. Deduplicates, validates with DNS, writes output.
Every other plugin depends on what we find here.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import time
from pathlib import Path
from typing import Any, TYPE_CHECKING

import httpx

from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin
from scoutx.utils.io import atomic_write_text, write_json, write_jsonl

if TYPE_CHECKING:
    from scoutx.core.engine import ScanContext

logger = logging.getLogger("scoutx.plugins.subdomains")

# All available sources — imported dynamically
SOURCE_MODULES = [
    "scoutx.plugins.builtin.subdomains.sources.crtsh",
    "scoutx.plugins.builtin.subdomains.sources.alienvault",
    "scoutx.plugins.builtin.subdomains.sources.urlscan",
    "scoutx.plugins.builtin.subdomains.sources.rapiddns",
    "scoutx.plugins.builtin.subdomains.sources.hackertarget",
    "scoutx.plugins.builtin.subdomains.sources.webarchive",
    "scoutx.plugins.builtin.subdomains.sources.anubis",
    "scoutx.plugins.builtin.subdomains.sources.securitytrails",
    "scoutx.plugins.builtin.subdomains.sources.shodan",
    "scoutx.plugins.builtin.subdomains.sources.virustotal",
    "scoutx.plugins.builtin.subdomains.sources.censys",
    "scoutx.plugins.builtin.subdomains.sources.dnsdb",
]


class Plugin(ScoutPlugin):
    """Passive subdomain enumeration from 12 sources."""

    meta = PluginMeta(
        name="subdomains",
        description="Passive + active subdomain enumeration from 12+ sources",
        version="0.3.0",
        author="ScoutX",
        tags=["discovery", "passive", "active", "subdomains", "brute-force"],
    )
    depends_on: list[str] = []
    concurrent_with: list[str] = ["osint"]

    async def run(self, context: ScanContext) -> PluginResult:
        """Query all enabled sources concurrently and merge results."""
        from scoutx.cli.ui import info, success, warn
        from scoutx.core.events import Event, EventType

        target = context.target
        output_dir = context.output_dir / "subdomains"
        output_dir.mkdir(parents=True, exist_ok=True)

        config = context.config
        enabled_sources = config.get("sources", {})

        # Load source modules
        sources = []
        for module_path in SOURCE_MODULES:
            try:
                import importlib
                mod = importlib.import_module(module_path)
                source_name = getattr(mod, "SOURCE_NAME", module_path.split(".")[-1])
                # Check if source is enabled in config
                if enabled_sources.get(source_name, True):
                    sources.append(mod)
                    logger.debug("Loaded source: %s", source_name)
            except ImportError as exc:
                logger.warning("Failed to load source %s: %s", module_path, exc)

        info(f"Querying {len(sources)} passive sources...")

        # Query all sources concurrently
        all_subdomains: set[str] = set()
        source_results: dict[str, int] = {}
        source_errors: dict[str, str] = {}

        async with httpx.AsyncClient(
            follow_redirects=True,
            verify=False,
            timeout=httpx.Timeout(30.0, connect=10.0),
            headers={"User-Agent": "ScoutX/0.1.0"},
        ) as client:
            tasks = []
            task_names = []
            for source_mod in sources:
                source_name = getattr(source_mod, "SOURCE_NAME", "unknown")
                task_names.append(source_name)
                tasks.append(source_mod.fetch(target, client))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for source_name, result in zip(task_names, results):
                if isinstance(result, Exception):
                    error_msg = str(result)
                    source_errors[source_name] = error_msg
                    source_results[source_name] = 0
                    warn(f"  {source_name}: error - {error_msg}")
                else:
                    found = result
                    source_results[source_name] = len(found)
                    all_subdomains.update(found)
                    if found:
                        info(f"  {source_name}: {len(found)} subdomains")
                    else:
                        info(f"  {source_name}: 0 subdomains")

        # Always include the root domain
        all_subdomains.add(target)

        # Sort for deterministic output
        sorted_subs = sorted(all_subdomains)
        total = len(sorted_subs)
        info(f"Total unique subdomains: {total}")

        # DNS resolution (optional, lightweight)
        dns_results: dict[str, list[str]] = {}
        try:
            from scoutx.utils.dns import resolve_bulk
            concurrency = config.get_profiled("concurrency.dns", context.profile)
            if isinstance(concurrency, (int, float)):
                concurrency = int(concurrency)
            else:
                concurrency = 50
            info(f"Resolving DNS for {total} subdomains (concurrency: {concurrency})...")
            dns_results = await resolve_bulk(sorted_subs, concurrency=concurrency)
            resolved_count = sum(1 for ips in dns_results.values() if ips)
            info(f"DNS resolved: {resolved_count}/{total}")
        except Exception as exc:
            logger.warning("DNS resolution failed: %s", exc)

        # --- Active subdomain discovery (aggressive profile only) ---
        if context.profile == "aggressive":
            info("[AGGRESSIVE] Running active subdomain discovery...")
            active_found = await self._active_brute_force(
                target, sorted_subs, output_dir
            )
            if active_found:
                pre_count = len(sorted_subs)
                all_subdomains.update(active_found)
                sorted_subs = sorted(all_subdomains)
                total = len(sorted_subs)
                new_count = total - pre_count
                if new_count > 0:
                    info(f"Active discovery found {new_count} new subdomains (total: {total})")
                    # Re-resolve new ones
                    try:
                        from scoutx.utils.dns import resolve_bulk
                        new_subs = [s for s in active_found if s not in dns_results]
                        new_dns = await resolve_bulk(new_subs, concurrency=50)
                        dns_results.update(new_dns)
                    except Exception:
                        pass

        # Write output files
        # subdomains.txt — one per line
        atomic_write_text(output_dir / "subdomains.txt", "\n".join(sorted_subs) + "\n")

        # subdomains.jsonl — detailed records
        records = []
        for sub in sorted_subs:
            record: dict[str, Any] = {
                "hostname": sub,
                "sources": [name for name, subs in zip(task_names, results)
                            if not isinstance(subs, Exception) and sub in subs],
                "ips": dns_results.get(sub, []),
                "resolved": bool(dns_results.get(sub)),
            }
            records.append(record)
        write_jsonl(output_dir / "subdomains.jsonl", records)

        # subdomains.json — summary
        write_json(output_dir / "subdomains.json", {
            "target": target,
            "total": total,
            "resolved": sum(1 for r in records if r["resolved"]),
            "sources": source_results,
            "errors": source_errors,
            "subdomains": sorted_subs,
        })

        # Emit events for each subdomain found
        for sub in sorted_subs:
            await context.events.emit(Event(
                type=EventType.SUBDOMAIN_FOUND,
                data={"hostname": sub, "ips": dns_results.get(sub, [])},
                scan_id=context.scan_id,
                source="subdomains",
            ))

        # Store in database
        try:
            if context.db:
                hosts_data = [
                    {
                        "hostname": sub,
                        "ip_address": dns_results.get(sub, [""])[0] if dns_results.get(sub) else None,
                        "source": ",".join(r["sources"]) if r["sources"] else "unknown",
                    }
                    for sub, r in zip(sorted_subs, records)
                ]
                await context.db.add_hosts_bulk(context.scan_id, hosts_data)
        except Exception as exc:
            logger.warning("Failed to store subdomains in DB: %s", exc)

        success(f"Discovered {total} unique subdomains from {len(sources)} sources")

        return PluginResult.completed(
            data={
                "subdomains": sorted_subs,
                "total": total,
                "source_counts": source_results,
                "dns_results": {k: v for k, v in dns_results.items() if v},
            },
            findings_count=total,
            artifacts=[output_dir / "subdomains.txt", output_dir / "subdomains.jsonl"],
        )

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={"subdomains": list, "total": int, "source_counts": dict},
            description="Discovered subdomains with source attribution and DNS resolution",
        )

    async def _active_brute_force(
        self, domain: str, known_subs: list[str], output_dir: Path
    ) -> set[str]:
        """Active subdomain brute-force using puredns/gotator/alterx."""
        new_subs: set[str] = set()

        # Write known subs to file for permutation tools
        known_file = output_dir / "known_subs.txt"
        known_file.write_text("\n".join(known_subs) + "\n", encoding="utf-8")

        # 1. Permutation generation with gotator or alterx
        permutation_file = output_dir / "permutations.txt"
        if shutil.which("gotator"):
            try:
                proc = await asyncio.create_subprocess_exec(
                    "gotator", "-sub", str(known_file),
                    "-perm", "-depth", "1", "-numbers", "3",
                    "-md",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
                perms = stdout.decode("utf-8", errors="replace").strip().split("\n")
                permutation_file.write_text("\n".join(perms), encoding="utf-8")
                logger.info("gotator generated %d permutations", len(perms))
            except Exception as exc:
                logger.warning("gotator failed: %s", exc)
        elif shutil.which("alterx"):
            try:
                proc = await asyncio.create_subprocess_exec(
                    "alterx", "-l", str(known_file),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
                perms = stdout.decode("utf-8", errors="replace").strip().split("\n")
                permutation_file.write_text("\n".join(perms), encoding="utf-8")
                logger.info("alterx generated %d permutations", len(perms))
            except Exception as exc:
                logger.warning("alterx failed: %s", exc)

        # 2. DNS brute-force with puredns
        if shutil.which("puredns") and permutation_file.exists():
            resolved_file = output_dir / "puredns_resolved.txt"
            try:
                proc = await asyncio.create_subprocess_exec(
                    "puredns", "resolve", str(permutation_file),
                    "--rate-limit", "300",
                    "-w", str(resolved_file),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=300)
                if resolved_file.exists():
                    resolved = resolved_file.read_text(encoding="utf-8").strip().split("\n")
                    new_subs.update(s.strip() for s in resolved if s.strip())
                    logger.info("puredns resolved %d permutations", len(new_subs))
            except Exception as exc:
                logger.warning("puredns failed: %s", exc)

        # 3. Also run subfinder if available (external tool catches sources we miss)
        if shutil.which("subfinder"):
            try:
                proc = await asyncio.create_subprocess_exec(
                    "subfinder", "-d", domain, "-silent",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
                ext_subs = stdout.decode("utf-8", errors="replace").strip().split("\n")
                new_subs.update(s.strip() for s in ext_subs if s.strip())
            except Exception as exc:
                logger.debug("subfinder external run failed: %s", exc)

        # Filter: only keep subdomains of the target domain
        valid_subs = {s for s in new_subs if s.endswith(f".{domain}") or s == domain}
        return valid_subs - set(known_subs)
