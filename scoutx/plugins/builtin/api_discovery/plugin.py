"""API Schema Discovery Plugin — find OpenAPI, Swagger, and GraphQL endpoints.

Probes alive hosts for common API documentation paths and extracts
endpoint schemas for deeper testing.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING, Any

import httpx

from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin
from scoutx.utils.io import write_json

if TYPE_CHECKING:
    from scoutx.core.engine import ScanContext

logger = logging.getLogger("scoutx.plugins.api_discovery")

# Common API documentation paths
API_PATHS = [
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/api-docs", "/api-docs.json", "/swagger-ui/",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/.well-known/openapi.json", "/.well-known/openapi.yaml",
    "/graphql", "/graphiql", "/playground", "/altair",
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/_api/", "/rest/", "/restapi/",
]

GRAPHQL_INTROSPECTION = '{"query":"{__schema{queryType{name}mutationType{name}types{name kind fields{name type{name}}}}}"}'


class Plugin(ScoutPlugin):
    """Discover API schemas and documentation endpoints."""

    meta = PluginMeta(
        name="api_discovery",
        description="API schema discovery — OpenAPI, Swagger, GraphQL introspection",
        version="0.1.0",
        author="ScoutX",
        tags=["api", "openapi", "swagger", "graphql", "discovery"],
    )
    depends_on: list[str] = ["probe"]
    concurrent_with: list[str] = ["cloud", "cors"]

    async def run(self, context: ScanContext) -> PluginResult:
        from scoutx.cli.ui import info, success

        output_dir = context.output_dir / "api_discovery"
        output_dir.mkdir(parents=True, exist_ok=True)

        probe_data = context.result_data("probe")
        hosts = probe_data.get("alive_hosts", [])
        if not hosts:
            return PluginResult.skipped("No alive hosts to check")

        # Get base URLs
        base_urls: list[str] = []
        for host in hosts:
            if isinstance(host, dict):
                url = host.get("url", "")
                if url:
                    base_urls.append(url.rstrip("/"))
            elif isinstance(host, str):
                base_urls.append(host.rstrip("/"))

        if not base_urls:
            return PluginResult.skipped("No URLs to probe")

        info(f"Probing {len(base_urls)} hosts for API schemas...")

        # Rate limit based on profile
        profile = context.profile
        concurrency = {"safe": 3, "balanced": 10, "aggressive": 25}.get(profile, 10)
        sem = asyncio.Semaphore(concurrency)

        discovered_apis: list[dict[str, Any]] = []
        graphql_endpoints: list[dict[str, Any]] = []

        async with httpx.AsyncClient(
            timeout=10, verify=False, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ScoutX/2.0)"},
        ) as client:
            tasks = []
            for base_url in base_urls[:50]:  # Cap at 50 hosts
                for path in API_PATHS:
                    tasks.append(self._check_path(client, sem, base_url, path))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, dict) and result.get("found"):
                    if result.get("type") == "graphql":
                        graphql_endpoints.append(result)
                    else:
                        discovered_apis.append(result)

            # Try GraphQL introspection on discovered GraphQL endpoints
            for gql in graphql_endpoints:
                schema = await self._introspect_graphql(client, sem, gql["url"])
                if schema:
                    gql["schema"] = schema

        output = {
            "api_schemas": discovered_apis,
            "graphql_endpoints": graphql_endpoints,
            "total_found": len(discovered_apis) + len(graphql_endpoints),
        }

        write_json(output_dir / "apis.json", output)

        total = output["total_found"]
        if total > 0:
            success(f"Found {total} API endpoints ({len(discovered_apis)} REST, {len(graphql_endpoints)} GraphQL)")
        else:
            info("No API documentation endpoints found")

        return PluginResult.completed(data=output, findings_count=total)

    async def _check_path(
        self, client: httpx.AsyncClient, sem: asyncio.Semaphore,
        base_url: str, path: str,
    ) -> dict[str, Any]:
        """Check a single URL path for API documentation."""
        url = f"{base_url}{path}"
        async with sem:
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    content_type = resp.headers.get("content-type", "")
                    body = resp.text[:5000]

                    # Check for OpenAPI/Swagger
                    if any(sig in body for sig in ['"openapi"', '"swagger"', '"paths"', '"info"']):
                        endpoints = self._extract_endpoints(body)
                        return {
                            "found": True, "type": "openapi", "url": url,
                            "content_type": content_type,
                            "endpoints_count": len(endpoints),
                            "endpoints": endpoints[:50],
                        }

                    # Check for GraphQL
                    if "graphql" in path.lower() or "graphiql" in body.lower():
                        return {"found": True, "type": "graphql", "url": url}

                    # Check for API listing
                    if '"api"' in body and ('"endpoints"' in body or '"routes"' in body):
                        return {
                            "found": True, "type": "api_listing", "url": url,
                            "content_type": content_type,
                        }

            except (httpx.HTTPError, Exception):
                pass

        return {"found": False}

    def _extract_endpoints(self, body: str) -> list[dict]:
        """Extract endpoint paths from OpenAPI/Swagger JSON."""
        try:
            spec = json.loads(body)
            paths = spec.get("paths", {})
            endpoints = []
            for path, methods in paths.items():
                if isinstance(methods, dict):
                    for method in methods:
                        if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
                            endpoints.append({"path": path, "method": method.upper()})
            return endpoints
        except (json.JSONDecodeError, AttributeError):
            return []

    async def _introspect_graphql(
        self, client: httpx.AsyncClient, sem: asyncio.Semaphore, url: str,
    ) -> dict | None:
        """Attempt GraphQL introspection query."""
        async with sem:
            try:
                resp = await client.post(
                    url,
                    content=GRAPHQL_INTROSPECTION,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    schema = data.get("data", {}).get("__schema", {})
                    if schema:
                        types = schema.get("types", [])
                        return {
                            "query_type": schema.get("queryType", {}).get("name"),
                            "mutation_type": schema.get("mutationType", {}).get("name"),
                            "types_count": len(types),
                            "types": [t.get("name") for t in types[:30] if not t.get("name", "").startswith("__")],
                        }
            except (httpx.HTTPError, json.JSONDecodeError, Exception):
                pass
        return None

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={"api_schemas": list, "graphql_endpoints": list, "total_found": int},
            description="Discovered API documentation and schema endpoints",
        )
