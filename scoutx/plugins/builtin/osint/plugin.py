"""OSINT Plugin — WHOIS, DNS deep dive, ASN discovery, email harvesting.

Covers methodology Phase 01-02B. Runs in Phase 1 alongside subdomains
with no dependencies — pure passive intelligence gathering.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from typing import TYPE_CHECKING, Any

import httpx

from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin
from scoutx.utils.io import write_json

if TYPE_CHECKING:
    from scoutx.core.engine import ScanContext

logger = logging.getLogger("scoutx.plugins.osint")


class Plugin(ScoutPlugin):
    """OSINT intelligence gathering — WHOIS, DNS, ASN, email patterns."""

    meta = PluginMeta(
        name="osint",
        description="Passive OSINT: WHOIS, DNS records, ASN discovery, email harvesting",
        version="0.1.0",
        author="ScoutX",
        tags=["osint", "whois", "dns", "asn", "email"],
    )
    depends_on: list[str] = []
    concurrent_with: list[str] = ["subdomains"]

    async def run(self, context: ScanContext) -> PluginResult:
        from scoutx.cli.ui import info, success

        output_dir = context.output_dir / "osint"
        output_dir.mkdir(parents=True, exist_ok=True)

        domain = context.target
        data: dict[str, Any] = {"domain": domain}

        # WHOIS
        info("Running WHOIS lookup...")
        whois_data = await self._whois_lookup(domain)
        data["whois"] = whois_data

        # DNS Records
        info("Querying DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME)...")
        dns_data = await self._dns_records(domain)
        data["dns"] = dns_data

        # ASN Discovery
        info("Discovering ASN information...")
        asn_data = await self._asn_lookup(domain)
        data["asn"] = asn_data

        # Email patterns
        info("Harvesting email patterns...")
        email_data = await self._email_harvest(domain)
        data["email_patterns"] = email_data

        # SPF/DMARC/DKIM
        info("Checking email security records...")
        email_sec = self._check_email_security(dns_data)
        data["email_security"] = email_sec

        write_json(output_dir / "osint.json", data)

        findings = sum([
            1 if whois_data else 0,
            len(dns_data.get("records", {})),
            1 if asn_data.get("asn") else 0,
            len(email_data.get("patterns", [])),
        ])

        success(f"OSINT complete: {findings} data points gathered")
        return PluginResult.completed(data=data, findings_count=findings)

    async def _whois_lookup(self, domain: str) -> dict[str, Any]:
        """WHOIS lookup via python-whois or fallback to API."""
        try:
            import whois as python_whois
            w = python_whois.whois(domain)
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "name_servers": list(w.name_servers) if w.name_servers else [],
                "org": w.org,
                "emails": list(w.emails) if w.emails else [],
                "country": w.country,
                "status": list(w.status) if w.status else [],
            }
        except ImportError:
            logger.debug("python-whois not installed, trying API fallback")
        except Exception as exc:
            logger.warning("WHOIS lookup failed: %s", exc)

        # Fallback to free API
        try:
            async with httpx.AsyncClient(trust_env=False, timeout=15) as client:
                r = await client.get(f"https://api.api-ninjas.com/v1/whois?domain={domain}")
                if r.status_code == 200:
                    return r.json()
        except Exception:
            pass
        return {}

    async def _dns_records(self, domain: str) -> dict[str, Any]:
        """Query all DNS record types."""
        records: dict[str, list[str]] = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]

        for rtype in record_types:
            try:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, self._resolve_dns, domain, rtype
                )
                if result:
                    records[rtype] = result
            except Exception as exc:
                logger.debug("DNS %s lookup failed for %s: %s", rtype, domain, exc)

        # Zone transfer attempt
        zone_transfer = await self._try_zone_transfer(domain, records.get("NS", []))

        return {
            "records": records,
            "zone_transfer_possible": zone_transfer,
            "total_records": sum(len(v) for v in records.values()),
        }

    def _resolve_dns(self, domain: str, rtype: str) -> list[str]:
        """Resolve DNS records using socket/subprocess."""
        import subprocess
        try:
            result = subprocess.run(
                ["nslookup", "-type=" + rtype, domain],
                capture_output=True, text=True, timeout=10,
            )
            lines = result.stdout.split("\n")
            results = []
            for line in lines:
                line = line.strip()
                if "=" in line and domain.lower() in line.lower():
                    parts = line.split("=")
                    if len(parts) > 1:
                        results.append(parts[-1].strip())
                elif rtype == "A" and "Address" in line and "." in line:
                    addr = line.split(":")[-1].strip() if ":" in line else line.split()[-1]
                    if addr and not addr.startswith("127.") and addr != domain:
                        results.append(addr)
            return results
        except Exception:
            return []

    async def _try_zone_transfer(self, domain: str, nameservers: list[str]) -> bool:
        """Attempt AXFR zone transfer (aggressive only)."""
        return False  # Disabled by default — active technique

    async def _asn_lookup(self, domain: str) -> dict[str, Any]:
        """ASN discovery via BGPView API."""
        try:
            # Resolve domain to IP first
            ip = socket.gethostbyname(domain)
            async with httpx.AsyncClient(trust_env=False, timeout=15) as client:
                r = await client.get(f"https://api.bgpview.io/ip/{ip}")
                if r.status_code == 200:
                    data = r.json().get("data", {})
                    data.get("rir_allocation", {})
                    ptr = data.get("ptr_record")
                    asn_info = {}
                    related = data.get("related_prefixes", [])
                    if related:
                        first = related[0] if isinstance(related, list) else {}
                        asn_info = {
                            "asn": first.get("asn", {}).get("asn"),
                            "asn_name": first.get("asn", {}).get("name"),
                            "prefix": first.get("prefix"),
                            "ip": ip,
                            "ptr": ptr,
                        }
                    return asn_info
        except Exception as exc:
            logger.debug("ASN lookup failed: %s", exc)
        return {}

    async def _email_harvest(self, domain: str) -> dict[str, Any]:
        """Discover email patterns for the domain."""
        patterns: list[str] = []
        common_prefixes = [
            "admin", "info", "support", "contact", "hello",
            "sales", "hr", "security", "abuse", "postmaster",
            "webmaster", "noc", "billing", "legal",
        ]
        # These are common patterns — not verified
        for prefix in common_prefixes:
            patterns.append(f"{prefix}@{domain}")

        return {
            "patterns": patterns,
            "domain": domain,
            "format_guess": "first.last@" + domain,
        }

    def _check_email_security(self, dns_data: dict) -> dict[str, Any]:
        """Analyze SPF, DMARC, DKIM from TXT records."""
        txt_records = dns_data.get("records", {}).get("TXT", [])
        result: dict[str, Any] = {
            "spf": {"found": False, "record": None, "issues": []},
            "dmarc": {"found": False, "record": None, "issues": []},
        }

        for txt in txt_records:
            if "v=spf1" in txt.lower():
                result["spf"]["found"] = True
                result["spf"]["record"] = txt
                if "+all" in txt:
                    result["spf"]["issues"].append("SPF uses +all (allows everything)")
                if "~all" in txt:
                    result["spf"]["issues"].append("SPF uses ~all (softfail, not enforced)")
            if "v=dmarc1" in txt.lower():
                result["dmarc"]["found"] = True
                result["dmarc"]["record"] = txt
                if "p=none" in txt.lower():
                    result["dmarc"]["issues"].append("DMARC policy is none (not enforced)")

        if not result["spf"]["found"]:
            result["spf"]["issues"].append("No SPF record found — email spoofing possible")
        if not result["dmarc"]["found"]:
            result["dmarc"]["issues"].append("No DMARC record found — no email authentication policy")

        return result

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={"whois": dict, "dns": dict, "asn": dict, "email_patterns": dict},
            description="OSINT intelligence: WHOIS, DNS, ASN, email patterns",
        )
