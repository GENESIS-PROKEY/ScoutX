"""HTTP Probe Plugin — alive detection, tech fingerprint, WAF, CDN, favicon hash.

Probes every subdomain with HEAD/GET requests, extracts status codes,
titles, server headers, technology hints, CDN/WAF detection.
Enhanced with favicon MMH3 hashing for Shodan pivoting.
This is Phase 2 — runs concurrently with ports and SSL.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import shutil
from typing import TYPE_CHECKING, Any

import httpx

from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin
from scoutx.utils.io import atomic_write_text, write_json, write_jsonl

if TYPE_CHECKING:
    from scoutx.core.engine import ScanContext

logger = logging.getLogger("scoutx.plugins.probe")

# Technology fingerprints — header/body patterns
TECH_FINGERPRINTS: dict[str, list[tuple[str, str]]] = {
    # (location, pattern) — location is 'header:name' or 'body'
    "nginx": [("header:server", "nginx")],
    "Apache": [("header:server", "apache")],
    "IIS": [("header:server", "microsoft-iis")],
    "Cloudflare": [("header:server", "cloudflare"), ("header:cf-ray", "")],
    "AWS CloudFront": [("header:x-amz-cf-id", ""), ("header:via", "cloudfront")],
    "Akamai": [("header:x-akamai-transformed", "")],
    "Fastly": [("header:x-served-by", "cache-"), ("header:via", "varnish")],
    "Varnish": [("header:via", "varnish"), ("header:x-varnish", "")],
    "WordPress": [("body", "wp-content"), ("header:x-powered-by", "wordpress")],
    "React": [("body", "__NEXT_DATA__"), ("body", "react-root"), ("body", "_reactRoot")],
    "Next.js": [("body", "__NEXT_DATA__"), ("header:x-powered-by", "next.js")],
    "PHP": [("header:x-powered-by", "php")],
    "ASP.NET": [("header:x-powered-by", "asp.net"), ("header:x-aspnet-version", "")],
    "Express": [("header:x-powered-by", "express")],
    "Django": [("header:x-frame-options", ""), ("body", "csrfmiddlewaretoken")],
    "Laravel": [("body", "laravel"), ("header:set-cookie", "laravel_session")],
    "Spring": [("header:x-application-context", "")],
}

WAF_FINGERPRINTS: dict[str, list[tuple[str, str]]] = {
    "Cloudflare WAF": [("header:cf-ray", ""), ("header:server", "cloudflare")],
    "AWS WAF": [("header:x-amzn-waf-action", "")],
    "Sucuri": [("header:x-sucuri-id", ""), ("header:server", "sucuri")],
    "Imperva": [("header:x-iinfo", "")],
    "F5 BIG-IP": [("header:server", "big-ip"), ("header:set-cookie", "bigipserver")],
    "ModSecurity": [("header:server", "mod_security")],
    "Wordfence": [("body", "wordfence"), ("header:server", "wordfence")],
    "Barracuda": [("header:server", "barracuda")],
    "DenyAll": [("header:server", "denyall")],
    "FortiWeb": [("header:server", "fortiweb")],
    "SonicWALL": [("header:server", "sonicwall")],
}

TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,200})</title>", re.IGNORECASE | re.DOTALL)


class Plugin(ScoutPlugin):
    """HTTP probe — alive detection with technology fingerprinting."""

    meta = PluginMeta(
        name="probe",
        description="HTTP probing with tech fingerprint, WAF/CDN detection, favicon hash",
        version="0.2.0",
        author="ScoutX",
        tags=["enumeration", "probe", "fingerprint", "waf", "favicon"],
    )
    depends_on: list[str] = ["subdomains"]
    concurrent_with: list[str] = ["ports", "ssl_analysis"]

    async def run(self, context: ScanContext) -> PluginResult:
        from scoutx.cli.ui import info, success

        # Get subdomains from prior results
        sub_data = context.result_data("subdomains")
        subdomains = sub_data.get("subdomains", [])
        if not subdomains:
            return PluginResult.skipped("No subdomains to probe")

        output_dir = context.output_dir / "probe"
        output_dir.mkdir(parents=True, exist_ok=True)

        config = context.config
        concurrency = int(config.get_profiled("concurrency.probe", context.profile) or 50)
        ceiling = int(config.get_profiled("request_ceilings.probe", context.profile) or 500)

        # Limit to ceiling
        targets = subdomains[:ceiling]
        info(f"Probing {len(targets)} hosts (concurrency: {concurrency})")

        semaphore = asyncio.Semaphore(concurrency)
        alive_hosts: list[dict[str, Any]] = []
        dead_count = 0

        http_timeout = httpx.Timeout(
            float(config.get("timeouts.http", 15)),
            connect=8.0,
        )

        # Shared client — avoids creating a new TCP pool per host
        # trust_env=False prevents proxy env vars from breaking connections
        async with httpx.AsyncClient(
            follow_redirects=True,
            verify=False,
            timeout=http_timeout,
            trust_env=False,
            limits=httpx.Limits(
                max_connections=concurrency,
                max_keepalive_connections=concurrency // 2,
            ),
        ) as shared_client:

            async def probe_host(hostname: str) -> dict[str, Any] | None:
                async with semaphore:
                    # Try HTTP first (cheaper, most hosts respond on 80)
                    for scheme in ("http", "https"):
                        url = f"{scheme}://{hostname}"
                        for attempt in range(2):  # 1 retry
                            try:
                                resp = await shared_client.get(url)

                                # Extract info
                                title = ""
                                body_text = resp.text[:5000] if resp.text else ""
                                title_match = TITLE_RE.search(body_text)
                                if title_match:
                                    title = title_match.group(1).strip()

                                headers = {k.lower(): v for k, v in resp.headers.items()}
                                server = headers.get("server", "")
                                content_length = len(resp.content)
                                final_url = str(resp.url)

                                # Fingerprinting — wrapped so crashes don't kill alive hosts
                                technologies: list[str] = []
                                waf = ""
                                cdn = ""
                                favicon_hash = ""
                                try:
                                    technologies = _detect_tech(headers, body_text)
                                    waf = _detect_waf(headers)
                                    cdn = _detect_cdn(headers)
                                    favicon_hash = await _get_favicon_hash(shared_client, url)
                                except Exception as fp_exc:
                                    logger.debug("Fingerprint error for %s: %s", url, fp_exc)

                                return {
                                    "hostname": hostname,
                                    "url": url,
                                    "final_url": final_url,
                                    "scheme": scheme,
                                    "status_code": resp.status_code,
                                    "title": title,
                                    "server": server,
                                    "content_length": content_length,
                                    "technologies": technologies,
                                    "waf": waf,
                                    "cdn": cdn,
                                    "favicon_hash": favicon_hash,
                                    "headers": dict(headers),
                                    "alive": True,
                                    "redirect": final_url != url,
                                }
                            except (httpx.TimeoutException, httpx.ConnectError,
                                    httpx.ReadError, httpx.RemoteProtocolError,
                                    ConnectionError, OSError) as net_exc:
                                logger.debug("Probe %s: %s: %s", url, type(net_exc).__name__, net_exc)
                                if attempt == 0:
                                    await asyncio.sleep(0.5)
                                    continue
                                break  # Move to next scheme
                            except Exception as exc:
                                logger.debug("Probe %s failed: %s: %s", url, type(exc).__name__, exc)
                                break
                    logger.debug("Host dead: %s", hostname)
                    return None

            # Run probes concurrently
            tasks = [probe_host(h) for h in targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.debug("Probe task exception: %s", result)
                dead_count += 1
            elif result is not None:
                alive_hosts.append(result)
            else:
                dead_count += 1



        # Sort by status code
        alive_hosts.sort(key=lambda h: (h.get("status_code", 999), h["hostname"]))

        info(f"Alive: {len(alive_hosts)} | Dead: {dead_count}")

        # Run external wafw00f if available
        if shutil.which("wafw00f"):
            info("Running wafw00f for enhanced WAF detection...")
            await self._run_wafw00f(alive_hosts)

        # Enrich WAF detections with bypass suggestions from our DB
        waf_summary: dict[str, int] = {}
        try:
            from scoutx.plugins.builtin.probe.waf_bypasses import (
                detect_waf_from_headers,
                get_bypass_suggestions,
            )
            for host in alive_hosts:
                headers = host.get("headers", {})
                # Enhanced detection via our signature DB
                detected_wafs = detect_waf_from_headers(headers)
                if detected_wafs and not host.get("waf"):
                    host["waf"] = detected_wafs[0]
                # Add bypass suggestions
                waf_name = host.get("waf", "")
                if waf_name:
                    # Normalize WAF name for lookup
                    waf_key = waf_name.lower().replace(" waf", "").replace(" ", "_").strip()
                    bypass_data = get_bypass_suggestions(waf_key)
                    if bypass_data.get("techniques"):
                        host["waf_bypass_techniques"] = bypass_data["techniques"]
                        host["waf_bypass_headers"] = bypass_data.get("headers", {})
                    waf_summary[waf_name] = waf_summary.get(waf_name, 0) + 1
        except ImportError:
            logger.debug("WAF bypass module not available")
        except Exception as waf_exc:
            logger.debug("WAF bypass enrichment failed: %s", waf_exc)

        if waf_summary:
            waf_str = ", ".join(f"{name}: {count}" for name, count in waf_summary.items())
            info(f"WAF detected: {waf_str}")

        # Write outputs
        alive_urls = [h["final_url"] for h in alive_hosts]
        atomic_write_text(output_dir / "alive.txt", "\n".join(alive_urls) + "\n")
        write_jsonl(output_dir / "probe.jsonl", alive_hosts)
        write_json(output_dir / "probe.json", {
            "target": context.target,
            "total_probed": len(targets),
            "alive": len(alive_hosts),
            "dead": dead_count,
            "waf_summary": waf_summary,
            "hosts": alive_hosts,
        })

        # Store alive hosts in DB
        try:
            if context.db:
                for host in alive_hosts:
                    await context.db.add_host(
                        context.scan_id,
                        hostname=host["hostname"],
                        status_code=host.get("status_code"),
                        title=host.get("title"),
                        server=host.get("server"),
                        technologies=host.get("technologies"),
                        cdn=host.get("cdn"),
                        waf=host.get("waf"),
                        alive=True,
                    )
        except Exception as exc:
            logger.warning("Failed to store probe results in DB: %s", exc)

        success(f"Found {len(alive_hosts)} alive hosts out of {len(targets)} probed")

        return PluginResult.completed(
            data={
                "hosts": alive_hosts,
                "alive_hosts": alive_hosts,  # Legacy alias
                "alive_urls": alive_urls,
                "total_probed": len(targets),
                "alive_count": len(alive_hosts),
                "alive": len(alive_hosts),
                "dead": dead_count,
                "waf_summary": waf_summary,
            },
            findings_count=len(alive_hosts),
            artifacts=[output_dir / "alive.txt", output_dir / "probe.jsonl"],
        )

    async def _run_wafw00f(self, hosts: list[dict]) -> dict[str, str]:
        """Run wafw00f against alive hosts for WAF detection."""
        import asyncio
        results: dict[str, str] = {}
        for host in hosts[:20]:  # Limit for performance
            url = host.get("final_url", host.get("url", ""))
            if not url:
                continue
            try:
                proc = await asyncio.create_subprocess_exec(
                    "wafw00f", url, "-o", "-",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                output = stdout.decode("utf-8", errors="replace")
                for line in output.splitlines():
                    if "is behind" in line:
                        waf_name = line.split("is behind")[-1].strip().rstrip(".")
                        results[host["hostname"]] = waf_name
                        if not host.get("waf"):
                            host["waf"] = waf_name
            except Exception:
                pass
        return results

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={"alive_hosts": list, "alive_urls": list, "alive_count": int},
            description="Alive hosts with status, titles, tech, WAF, CDN, favicon hash",
        )


def _detect_tech(headers: dict[str, str], body: str) -> list[str]:
    """Detect technologies from response headers and body."""
    detected: list[str] = []
    body_lower = body.lower()
    for tech_name, patterns in TECH_FINGERPRINTS.items():
        for location, pattern in patterns:
            if location.startswith("header:"):
                header_name = location.split(":", 1)[1]
                header_value = headers.get(header_name, "").lower()
                if pattern:
                    if pattern in header_value:
                        detected.append(tech_name)
                        break
                else:
                    if header_value:
                        detected.append(tech_name)
                        break
            elif location == "body":
                if pattern.lower() in body_lower:
                    detected.append(tech_name)
                    break
    return list(set(detected))


def _detect_waf(headers: dict[str, str]) -> str:
    """Detect WAF from response headers."""
    for waf_name, patterns in WAF_FINGERPRINTS.items():
        for location, pattern in patterns:
            header_name = location.split(":", 1)[1]
            header_value = headers.get(header_name, "").lower()
            if pattern:
                if pattern in header_value:
                    return waf_name
            else:
                if header_value:
                    return waf_name
    return ""


def _detect_cdn(headers: dict[str, str]) -> str:
    """Detect CDN from response headers."""
    cdn_hints = {
        "cf-ray": "Cloudflare",
        "x-amz-cf-id": "CloudFront",
        "x-cdn": "",
        "x-cache": "",
        "x-fastly-request-id": "Fastly",
    }
    for header, cdn_name in cdn_hints.items():
        if header in headers:
            if cdn_name:
                return cdn_name
            value = headers[header].strip()
            if value:
                parts = value.split()
                return parts[0] if parts else "Unknown CDN"
            return "Unknown CDN"
    return ""


async def _get_favicon_hash(client: httpx.AsyncClient, base_url: str) -> str:
    """Calculate MMH3 hash of favicon for Shodan pivoting."""
    import base64
    favicon_paths = ["/favicon.ico", "/assets/favicon.ico"]
    for path in favicon_paths:
        try:
            r = await client.get(f"{base_url.rstrip('/')}{path}")
            if r.status_code == 200 and len(r.content) > 0:
                # MMH3 hash via murmurhash or fallback to md5
                try:
                    import mmh3
                    b64_content = base64.encodebytes(r.content)
                    return str(mmh3.hash(b64_content))
                except ImportError:
                    # Fallback: use md5 hash (not Shodan-compatible but still useful)
                    return f"md5:{hashlib.md5(r.content).hexdigest()[:16]}"
        except Exception:
            pass
    return ""
