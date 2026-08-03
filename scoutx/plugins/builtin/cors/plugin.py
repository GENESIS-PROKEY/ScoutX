"""CORS Misconfiguration Testing Plugin — detect dangerous cross-origin policies.

Tests each alive host for common CORS misconfigurations that could allow
cross-site data theft: reflected origins, null origin bypass, wildcard
with credentials, subdomain/prefix trust issues.
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

logger = logging.getLogger("scoutx.plugins.cors")


# CORS test definitions
CORS_TESTS = [
    {
        "name": "reflected_origin",
        "description": "Origin reflected in ACAO header",
        "severity": "critical",
        "origin_template": "https://evil-{target}",
    },
    {
        "name": "null_origin",
        "description": "Null origin accepted",
        "severity": "high",
        "origin_template": "null",
    },
    {
        "name": "subdomain_trust",
        "description": "Evil subdomain of target accepted",
        "severity": "high",
        "origin_template": "https://evil.{target}",
    },
    {
        "name": "prefix_match",
        "description": "Target name as prefix accepted",
        "severity": "medium",
        "origin_template": "https://{target}.evil.com",
    },
    {
        "name": "http_downgrade",
        "description": "HTTP origin accepted on HTTPS host",
        "severity": "medium",
        "origin_template": "http://{target}",
    },
]


class Plugin(ScoutPlugin):
    """Test alive hosts for CORS misconfigurations."""

    meta = PluginMeta(
        name="cors",
        description="CORS misconfiguration detection across alive hosts",
        version="0.1.0",
        author="ScoutX",
        tags=["cors", "security", "headers", "web"],
    )
    depends_on: list[str] = ["probe"]
    concurrent_with: list[str] = ["endpoints", "secrets"]

    async def run(self, context: ScanContext) -> PluginResult:
        from scoutx.cli.ui import info, success, warn

        output_dir = context.output_dir / "cors"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Get alive hosts from probe
        probe_data = context.result_data("probe")
        hosts = probe_data.get("hosts", [])

        # Handle in-memory probe shape
        if not hosts:
            alive_hosts = probe_data.get("alive_hosts", [])
            alive_urls = probe_data.get("alive_urls", [])
            if alive_hosts:
                hosts = []
                for i, hostname in enumerate(alive_hosts):
                    url = alive_urls[i] if i < len(alive_urls) else f"https://{hostname}"
                    hosts.append({"hostname": hostname, "final_url": url, "status_code": 200})

        if not hosts:
            return PluginResult.skipped("No alive hosts to test")

        # Build target list
        targets = []
        for h in hosts:
            hostname = h.get("hostname", "")
            url = h.get("final_url") or h.get("url") or f"https://{hostname}"
            if hostname:
                targets.append({"hostname": hostname, "url": url})

        info(f"Testing {len(targets)} hosts for CORS misconfigurations...")

        concurrency = int(context.config.get_profiled("concurrency.cors", context.profile) or 5)
        semaphore = asyncio.Semaphore(concurrency)
        all_findings: list[dict[str, Any]] = []

        async def test_host(target: dict) -> list[dict[str, Any]]:
            """Run all CORS tests against one host."""
            async with semaphore:
                hostname = target["hostname"]
                url = target["url"]
                host_findings: list[dict[str, Any]] = []

                async with httpx.AsyncClient(
                    trust_env=False,
                    verify=False,
                    follow_redirects=True,
                    timeout=httpx.Timeout(10.0, connect=5.0),
                ) as client:
                    # Test 1-5: Origin-based tests
                    for test in CORS_TESTS:
                        origin = test["origin_template"].format(target=hostname)
                        finding = await _test_cors(
                            client, url, hostname, origin,
                            test["name"], test["description"], test["severity"],
                        )
                        if finding:
                            host_findings.append(finding)

                    # Test 6: Check for wildcard ACAO (baseline)
                    wildcard_finding = await _test_wildcard(client, url, hostname)
                    if wildcard_finding:
                        host_findings.append(wildcard_finding)

                return host_findings

        tasks = [test_host(t) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                all_findings.extend(result)
            elif isinstance(result, Exception):
                logger.debug("CORS test error: %s", result)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
        all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 4))

        vulnerable_count = sum(1 for f in all_findings if f.get("vulnerable"))
        critical_count = sum(1 for f in all_findings if f.get("severity") == "critical")

        data = {
            "target": context.target,
            "total_tested": len(targets),
            "total_findings": len(all_findings),
            "vulnerable": vulnerable_count,
            "by_severity": {
                "critical": critical_count,
                "high": sum(1 for f in all_findings if f.get("severity") == "high"),
                "medium": sum(1 for f in all_findings if f.get("severity") == "medium"),
                "info": sum(1 for f in all_findings if f.get("severity") == "info"),
            },
            "findings": all_findings,
        }

        write_json(output_dir / "cors.json", data)

        if critical_count > 0:
            warn(f"CORS: {critical_count} critical misconfigurations found!")
        elif vulnerable_count > 0:
            warn(f"CORS: {vulnerable_count} misconfigurations found")
        else:
            success(f"CORS: No misconfigurations detected across {len(targets)} hosts")

        return PluginResult.completed(
            data=data,
            findings_count=vulnerable_count,
            artifacts=[output_dir / "cors.json"],
        )

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={
                "findings": list,
                "total_findings": int,
                "vulnerable": int,
            },
            description="CORS misconfiguration test results",
        )


async def _test_cors(
    client: httpx.AsyncClient,
    url: str,
    hostname: str,
    origin: str,
    test_name: str,
    description: str,
    severity: str,
) -> dict[str, Any] | None:
    """Send a request with an Origin header and analyze the CORS response."""
    try:
        resp = await client.get(url, headers={"Origin": origin})

        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")

        vulnerable = False

        if test_name == "null_origin":
            # Null origin: ACAO should not be "null"
            if acao.lower() == "null":
                vulnerable = True
        elif origin != "null" and acao == origin:
            # Origin was reflected back
            vulnerable = True

        # Credentials amplify the risk
        has_credentials = acac.lower() == "true"

        if vulnerable:
            return {
                "hostname": hostname,
                "url": url,
                "test": test_name,
                "description": description,
                "severity": "critical" if (vulnerable and has_credentials) else severity,
                "vulnerable": True,
                "origin_sent": origin,
                "acao": acao,
                "acac": acac,
                "credentials": has_credentials,
            }

    except Exception as exc:
        logger.debug("CORS test %s failed on %s: %s", test_name, hostname, exc)

    return None


async def _test_wildcard(
    client: httpx.AsyncClient,
    url: str,
    hostname: str,
) -> dict[str, Any] | None:
    """Check for wildcard ACAO."""
    try:
        resp = await client.get(url)
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")

        if acao == "*":
            has_credentials = acac.lower() == "true"
            return {
                "hostname": hostname,
                "url": url,
                "test": "wildcard_acao",
                "description": "Wildcard ACAO" + (" with credentials!" if has_credentials else ""),
                "severity": "high" if has_credentials else "info",
                "vulnerable": has_credentials,
                "origin_sent": "(none)",
                "acao": "*",
                "acac": acac,
                "credentials": has_credentials,
            }
    except Exception:
        pass

    return None
