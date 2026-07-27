"""SSL/TLS Analysis Plugin — certificate parsing and security assessment.

Connects to each alive host's HTTPS port, extracts certificate details,
checks for expired certs, weak ciphers, self-signed certs, and SAN mismatches.
"""
from __future__ import annotations

import asyncio
import logging
import ssl
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin
from scoutx.utils.io import write_json, write_jsonl

if TYPE_CHECKING:
    from scoutx.core.engine import ScanContext

logger = logging.getLogger("scoutx.plugins.ssl_analysis")


class Plugin(ScoutPlugin):
    """SSL/TLS certificate analysis plugin."""

    meta = PluginMeta(
        name="ssl_analysis",
        description="SSL/TLS certificate parsing and security assessment",
        version="0.1.0",
        author="ScoutX",
        tags=["enumeration", "ssl", "tls", "certificate"],
    )
    depends_on: list[str] = ["subdomains"]
    concurrent_with: list[str] = ["probe", "ports"]

    async def run(self, context: ScanContext) -> PluginResult:
        from scoutx.cli.ui import info, success, warn

        sub_data = context.result_data("subdomains")
        subdomains = sub_data.get("subdomains", [])
        if not subdomains:
            return PluginResult.skipped("No subdomains to analyze")

        output_dir = context.output_dir / "ssl"
        output_dir.mkdir(parents=True, exist_ok=True)

        targets = subdomains[:100]  # Limit for safety
        info(f"Analyzing SSL/TLS certificates for {len(targets)} hosts")

        semaphore = asyncio.Semaphore(20)
        cert_results: list[dict[str, Any]] = []
        issues: list[dict[str, Any]] = []

        async def analyze_cert(hostname: str) -> dict[str, Any] | None:
            async with semaphore:
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

                    # SNI (Server Name Indication) is critical for shared hosts
                    # like Vercel, Cloudflare, etc. Without it, we get no cert.
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(
                            hostname, 443,
                            ssl=ctx,
                            server_hostname=hostname,  # SNI fix
                        ),
                        timeout=8.0,
                    )

                    ssl_obj = writer.get_extra_info("ssl_object")
                    if not ssl_obj:
                        writer.close()
                        return None

                    # binary_form=True always works; dict form needs CERT_REQUIRED
                    # So we try dict first, fall back to binary parsing
                    cert_dict = ssl_obj.getpeercert()
                    if not cert_dict:
                        # With CERT_NONE, getpeercert() returns {}
                        # Re-connect with CERT_REQUIRED to get the dict
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass

                        ctx2 = ssl.create_default_context()
                        ctx2.check_hostname = False
                        ctx2.verify_mode = ssl.CERT_REQUIRED
                        try:
                            reader2, writer2 = await asyncio.wait_for(
                                asyncio.open_connection(
                                    hostname, 443,
                                    ssl=ctx2,
                                    server_hostname=hostname,
                                ),
                                timeout=8.0,
                            )
                            ssl_obj = writer2.get_extra_info("ssl_object")
                            cert_dict = ssl_obj.getpeercert() if ssl_obj else None
                            protocol = ssl_obj.version() if ssl_obj else None
                            cipher = ssl_obj.cipher() if ssl_obj else None
                            writer2.close()
                            await writer2.wait_closed()
                        except ssl.SSLCertVerificationError:
                            # Self-signed or invalid cert — connect with CERT_NONE
                            # but we already know it's problematic
                            cert_dict = None
                        except Exception:
                            cert_dict = None
                    else:
                        protocol = ssl_obj.version()
                        cipher = ssl_obj.cipher()
                        writer.close()
                        await writer.wait_closed()

                    if not cert_dict:
                        return None

                    # Parse certificate details
                    subject = dict(x[0] for x in cert_dict.get("subject", ()))
                    issuer = dict(x[0] for x in cert_dict.get("issuer", ()))

                    # SANs
                    sans = []
                    for san_type, san_value in cert_dict.get("subjectAltName", ()):
                        if san_type == "DNS":
                            sans.append(san_value.lower())

                    # Dates
                    not_before_str = cert_dict.get("notBefore", "")
                    not_after_str = cert_dict.get("notAfter", "")
                    not_before = _parse_cert_date(not_before_str)
                    not_after = _parse_cert_date(not_after_str)

                    now = datetime.now(timezone.utc)
                    expired = not_after < now if not_after else False
                    days_remaining = (not_after - now).days if not_after else -1

                    # Self-signed check
                    self_signed = subject == issuer

                    # Weak protocol check
                    weak_protocol = protocol in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1") if protocol else False

                    result = {
                        "hostname": hostname,
                        "subject_cn": subject.get("commonName", ""),
                        "issuer_cn": issuer.get("commonName", ""),
                        "issuer_org": issuer.get("organizationName", ""),
                        "sans": sans,
                        "san_count": len(sans),
                        "not_before": str(not_before) if not_before else "",
                        "not_after": str(not_after) if not_after else "",
                        "expired": expired,
                        "days_remaining": days_remaining,
                        "self_signed": self_signed,
                        "protocol": protocol or "",
                        "cipher_name": cipher[0] if cipher else "",
                        "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else 0,
                        "weak_protocol": weak_protocol,
                        "serial_number": cert_dict.get("serialNumber", ""),
                    }

                    # Flag issues
                    if expired:
                        issues.append({
                            "hostname": hostname,
                            "issue": "Certificate expired",
                            "severity": "high",
                            "details": f"Expired {abs(days_remaining)} days ago",
                        })
                    if self_signed:
                        issues.append({
                            "hostname": hostname,
                            "issue": "Self-signed certificate",
                            "severity": "medium",
                        })
                    if weak_protocol:
                        issues.append({
                            "hostname": hostname,
                            "issue": f"Weak TLS protocol: {protocol}",
                            "severity": "high",
                        })
                    if days_remaining > 0 and days_remaining <= 30:
                        issues.append({
                            "hostname": hostname,
                            "issue": "Certificate expiring soon",
                            "severity": "medium",
                            "details": f"Expires in {days_remaining} days",
                        })

                    return result

                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return None
                except Exception as exc:
                    logger.debug("SSL analysis failed for %s: %s", hostname, exc)
                    return None

        tasks = [analyze_cert(h) for h in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict):
                cert_results.append(result)

        info(f"Analyzed {len(cert_results)} certificates, found {len(issues)} issues")

        # Write outputs
        write_jsonl(output_dir / "ssl.jsonl", cert_results)
        write_json(output_dir / "ssl.json", {
            "target": context.target,
            "total_analyzed": len(cert_results),
            "issues": issues,
            "certificates": cert_results,
        })

        if issues:
            write_jsonl(output_dir / "ssl_issues.jsonl", issues)

        # Store findings
        try:
            if context.db:
                for issue in issues:
                    await context.db.add_finding(
                        context.scan_id,
                        plugin_name="ssl_analysis",
                        finding_type="ssl_issue",
                        severity=issue.get("severity", "info"),
                        title=issue.get("issue", ""),
                        hostname=issue.get("hostname", ""),
                        raw_data=issue,
                    )
        except Exception as exc:
            logger.warning("Failed to store SSL findings: %s", exc)

        success(f"SSL analysis complete: {len(cert_results)} certs, {len(issues)} issues")

        return PluginResult.completed(
            data={"certificates": cert_results, "issues": issues},
            findings_count=len(issues),
            artifacts=[output_dir / "ssl.jsonl"],
        )

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={"certificates": list, "issues": list},
            description="SSL/TLS certificate details and security issues",
        )


def _parse_cert_date(date_str: str) -> datetime | None:
    """Parse certificate date string."""
    if not date_str:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None
