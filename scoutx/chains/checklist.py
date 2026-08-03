"""Vulnerability Checklist Mapper — maps recon findings against 138 security checks.

Based on the master-vuln-checklist-v2 methodology. Each check is scored
for applicability based on the target's tech stack, exposed services,
and discovered attack surface.
"""
from __future__ import annotations

import logging
from typing import Any

from scoutx.chains.models import ChecklistItem

logger = logging.getLogger("scoutx.chains.checklist")


# Phase definitions: (id_prefix, phase_name, category, check_name, severity, condition_fn_name)
CHECKLIST_DEFINITIONS: list[tuple[str, str, str, str, str, str]] = [
    # Phase 03: Authentication & Session
    ("AUTH-001", "Authentication", "Login", "Username Enumeration via Response", "high", "has_login"),
    ("AUTH-002", "Authentication", "Login", "Brute Force - No Rate Limiting", "high", "has_login"),
    ("AUTH-003", "Authentication", "Login", "Default Credentials on Admin Panel", "high", "has_admin"),
    ("AUTH-004", "Authentication", "Login", "Authentication Bypass via SQLi", "critical", "has_login"),
    ("AUTH-005", "Authentication", "Password Reset", "Password Reset Token Weak/Predictable", "high", "has_login"),
    ("AUTH-006", "Authentication", "Password Reset", "Password Reset Poisoning via Host Header", "high", "has_login"),
    ("AUTH-007", "Authentication", "MFA", "OTP Brute Force (No Lockout)", "high", "has_login"),
    ("AUTH-008", "Authentication", "MFA", "MFA Bypass via Response Manipulation", "critical", "has_login"),
    ("AUTH-009", "Authentication", "Session", "Session Token Weak Entropy", "high", "always"),
    ("AUTH-010", "Authentication", "Session", "Session Not Invalidated on Logout", "high", "always"),
    ("AUTH-011", "Authentication", "Session", "Cookie Missing HttpOnly Flag", "medium", "always"),
    ("AUTH-012", "Authentication", "Session", "Cookie Missing Secure Flag", "medium", "always"),
    ("AUTH-013", "Authentication", "Session", "Cookie Missing SameSite", "medium", "always"),
    # JWT
    ("JWT-001", "Authentication", "JWT", "JWT None Algorithm Attack", "critical", "has_jwt"),
    ("JWT-002", "Authentication", "JWT", "JWT Algorithm Confusion (RS256->HS256)", "critical", "has_jwt"),
    ("JWT-003", "Authentication", "JWT", "JWT Weak Secret Brute Force", "high", "has_jwt"),
    ("JWT-004", "Authentication", "JWT", "JWT Claim Manipulation (role/admin/sub)", "high", "has_jwt"),
    ("JWT-005", "Authentication", "JWT", "JWT kid Header Injection", "high", "has_jwt"),
    # OAuth
    ("OAUTH-001", "Authentication", "OAuth", "OAuth Open Redirect -> Code Steal", "critical", "has_oauth"),
    ("OAUTH-002", "Authentication", "OAuth", "OAuth State Parameter CSRF", "high", "has_oauth"),
    ("OAUTH-003", "Authentication", "OAuth", "OAuth Redirect URI Manipulation", "high", "has_oauth"),
    # Phase 04: Authorization
    ("AUTHZ-001", "Authorization", "IDOR", "IDOR via Numeric ID", "high", "has_api"),
    ("AUTHZ-002", "Authorization", "IDOR", "IDOR in POST/PUT/DELETE Body", "high", "has_api"),
    ("AUTHZ-003", "Authorization", "IDOR", "BOLA in GraphQL", "high", "has_graphql"),
    ("AUTHZ-004", "Authorization", "Privilege", "Vertical Privilege Escalation", "critical", "has_api"),
    ("AUTHZ-005", "Authorization", "Privilege", "Admin Panel Without Role Check", "critical", "has_admin"),
    ("AUTHZ-006", "Authorization", "Privilege", "Mass Assignment -> Role Escalation", "high", "has_api"),
    ("AUTHZ-007", "Authorization", "CSRF", "CSRF Token Missing", "high", "always"),
    ("AUTHZ-008", "Authorization", "CSRF", "CSRF via JSON Content-Type Switch", "high", "has_api"),
    # Phase 05: Injection
    ("INJ-001", "Injection", "SQLi", "SQL Injection - Error Based", "critical", "has_params"),
    ("INJ-002", "Injection", "SQLi", "SQL Injection - Blind Boolean", "critical", "has_params"),
    ("INJ-003", "Injection", "SQLi", "SQL Injection - Blind Time", "critical", "has_params"),
    ("INJ-004", "Injection", "SQLi", "SQLi in HTTP Headers", "critical", "always"),
    ("INJ-005", "Injection", "SQLi", "NoSQL Injection (MongoDB)", "critical", "has_mongodb"),
    ("INJ-006", "Injection", "Command", "OS Command Injection", "critical", "has_params"),
    ("INJ-007", "Injection", "SSTI", "SSTI - Jinja2 (Python)", "critical", "has_python"),
    ("INJ-008", "Injection", "SSTI", "SSTI - Twig (PHP)", "critical", "has_php"),
    ("INJ-009", "Injection", "SSTI", "SSTI - Freemarker/Velocity (Java)", "critical", "has_java"),
    ("INJ-010", "Injection", "Other", "LDAP Injection", "high", "has_ldap"),
    ("INJ-011", "Injection", "Other", "Host Header Injection", "high", "always"),
    ("INJ-012", "Injection", "Other", "HTTP Parameter Pollution", "medium", "has_params"),
    # Phase 06: XSS
    ("XSS-001", "XSS", "Types", "Reflected XSS", "high", "has_params"),
    ("XSS-002", "XSS", "Types", "Stored XSS", "high", "has_params"),
    ("XSS-003", "XSS", "Types", "DOM-Based XSS", "high", "has_js"),
    ("XSS-004", "XSS", "Types", "Blind XSS (Admin Panel)", "high", "has_params"),
    ("XSS-005", "XSS", "Bypass", "CSP Bypass via JSONP", "high", "has_csp"),
    ("XSS-006", "XSS", "Chain", "XSS + CSRF -> Admin ATO", "high", "has_params"),
    ("XSS-007", "XSS", "Chain", "XSS -> Cookie Steal -> Session Hijack", "high", "has_params"),
    # Phase 07: SSRF / XXE
    ("SSRF-001", "SSRF", "Basic", "Basic SSRF (Internal Port Scan)", "high", "has_url_params"),
    ("SSRF-002", "SSRF", "Cloud", "SSRF -> AWS IMDSv1 Metadata Steal", "critical", "has_cloud_aws"),
    ("SSRF-003", "SSRF", "Cloud", "SSRF -> GCP/Azure Metadata", "critical", "has_cloud"),
    ("SSRF-004", "SSRF", "Bypass", "SSRF via DNS Rebinding", "high", "has_url_params"),
    ("XXE-001", "XXE", "Basic", "XXE In-Band File Read", "high", "has_xml"),
    ("XXE-002", "XXE", "Upload", "XXE via File Upload (DOCX/SVG)", "high", "has_upload"),
    # Phase 08: File Upload
    ("FILE-001", "File Upload", "Upload", "Unrestricted File Upload (Webshell)", "critical", "has_upload"),
    ("FILE-002", "File Upload", "Upload", "Extension Bypass (file.php.jpg)", "high", "has_upload"),
    ("FILE-003", "File Upload", "Traversal", "Path Traversal (../../etc/passwd)", "high", "has_params"),
    ("FILE-004", "File Upload", "LFI", "Local File Inclusion", "critical", "has_params"),
    ("FILE-005", "File Upload", "LFI", "LFI -> Log Poisoning -> RCE", "critical", "has_params"),
    # Phase 09: Business Logic
    ("BIZ-001", "Business Logic", "Race", "Race Condition - Coupon Reuse", "high", "has_ecommerce"),
    ("BIZ-002", "Business Logic", "Price", "Price Manipulation via Parameter", "high", "has_ecommerce"),
    ("BIZ-003", "Business Logic", "Account", "ATO via Email Change Without Verification", "high", "has_login"),
    ("BIZ-004", "Business Logic", "Limit", "Rate Limiting Bypass", "medium", "always"),
    # Phase 10: API
    ("API-001", "API Security", "OWASP", "API1: BOLA", "high", "has_api"),
    ("API-002", "API Security", "OWASP", "API2: Broken Authentication", "high", "has_api"),
    ("API-003", "API Security", "GraphQL", "GraphQL Introspection Enabled", "high", "has_graphql"),
    ("API-004", "API Security", "GraphQL", "GraphQL Batching Attack", "high", "has_graphql"),
    ("API-005", "API Security", "Misc", "API Versioning Bypass (v1 vs v2)", "high", "has_api"),
    ("API-006", "API Security", "WebSocket", "WebSocket Auth Bypass", "high", "has_websocket"),
    # Phase 11: Crypto
    ("CRYPTO-001", "Cryptography", "TLS", "SSL/TLS Weak Config (TLS 1.0/1.1)", "high", "has_ssl_issues"),
    ("CRYPTO-002", "Cryptography", "Secrets", "API Key in Public Repository", "critical", "has_github"),
    ("CRYPTO-003", "Cryptography", "Secrets", "AWS Keys in Source Code", "critical", "has_aws_keys"),
    ("CRYPTO-004", "Cryptography", "Secrets", "PII Exposed in API Response", "high", "has_api"),
    # Phase 12: Deserialization
    ("DESER-001", "Deserialization", "RCE", "Java Deserialization RCE", "critical", "has_java"),
    ("DESER-002", "Deserialization", "RCE", "Python Pickle RCE", "critical", "has_python"),
    ("DESER-003", "Deserialization", "RCE", "PHP Object Deserialization RCE", "critical", "has_php"),
    ("DESER-004", "Deserialization", "RCE", ".NET ViewState Deserialization", "critical", "has_dotnet"),
    # Phase 13: Cache & Smuggling
    ("CACHE-001", "Cache", "Poisoning", "Web Cache Poisoning via Unkeyed Headers", "high", "has_cdn"),
    ("CACHE-002", "Cache", "Deception", "Web Cache Deception Attack", "high", "has_cdn"),
    ("SMUGGLE-001", "Smuggling", "HTTP", "HTTP Smuggling CL.TE", "critical", "always"),
    ("SMUGGLE-002", "Smuggling", "HTTP", "HTTP/2 Request Smuggling", "critical", "has_http2"),
    # Phase 15: Cloud
    ("CLOUD-001", "Cloud", "AWS", "S3 Bucket Public Read/Write", "critical", "has_cloud_aws"),
    ("CLOUD-002", "Cloud", "AWS", "IMDSv1 Credential Theft via SSRF", "critical", "has_cloud_aws"),
    ("CLOUD-003", "Cloud", "Container", "Kubernetes Dashboard Exposed", "critical", "has_k8s"),
    ("CLOUD-004", "Cloud", "Container", "Docker API Unauthenticated", "critical", "has_docker"),
    ("CLOUD-005", "Cloud", "CI/CD", "Jenkins/CI Pipeline Exposed", "critical", "has_jenkins"),
    ("CLOUD-006", "Cloud", "Services", "Elasticsearch Exposed", "critical", "has_elastic"),
    ("CLOUD-007", "Cloud", "Services", "MongoDB Exposed", "critical", "has_mongodb_port"),
    ("CLOUD-008", "Cloud", "Services", "Redis Exposed (RCE via cron)", "critical", "has_redis"),
]


class VulnChecklist:
    """Maps recon findings against the master vulnerability checklist."""

    def map_findings(self, scan_data: dict[str, Any]) -> list[ChecklistItem]:
        """Evaluate each checklist item against the scan data."""
        conditions = self._build_conditions(scan_data)
        items: list[ChecklistItem] = []

        for check_id, phase, category, check_name, severity, condition_key in CHECKLIST_DEFINITIONS:
            applicable = conditions.get(condition_key, False)
            reason = ""
            if applicable:
                reason = self._get_reason(condition_key, scan_data)

            items.append(ChecklistItem(
                id=f"VLN-{check_id}",
                phase=phase,
                category=category,
                check=check_name,
                severity=severity,
                applicable=applicable,
                reason=reason,
                verification_steps=self._get_verification_steps(check_id),
            ))

        return items

    def _build_conditions(self, scan_data: dict[str, Any]) -> dict[str, bool]:
        """Evaluate all conditions based on scan data."""
        intel = scan_data.get("intelligence", {})
        tech = intel.get("tech_intelligence", {})

        # Handle tech being either a dict or a list
        if isinstance(tech, list):
            # tech is a flat list of technology names
            detected_tech = [t.lower() for t in tech if isinstance(t, str)]
        elif isinstance(tech, dict):
            detected_tech = [t.lower() for t in tech.get("detected_technologies", []) if isinstance(t, str)]
        else:
            detected_tech = []
        tech_str = " ".join(detected_tech)

        endpoints = scan_data.get("endpoints", {}).get("endpoints", [])
        endpoint_strs = [e if isinstance(e, str) else e.get("url", "") for e in endpoints]
        endpoint_blob = " ".join(endpoint_strs).lower()

        ports_data = scan_data.get("ports", {})
        all_ports = self._extract_all_ports(ports_data)

        secrets_data = scan_data.get("secrets", {})
        secret_types = [f.get("type", "").lower() for f in secrets_data.get("findings", []) if isinstance(f, dict)]

        return {
            "always": True,
            "has_login": any(kw in endpoint_blob for kw in ("/login", "/signin", "/auth", "/session")),
            "has_admin": any(kw in endpoint_blob for kw in ("/admin", "/dashboard", "/manage", "/panel")),
            "has_api": any(kw in endpoint_blob for kw in ("/api/", "/v1/", "/v2/", "/rest/", "/graphql")),
            "has_graphql": "/graphql" in endpoint_blob,
            "has_params": len(endpoints) > 10,
            "has_url_params": any("=" in e for e in endpoint_strs),
            "has_upload": any(kw in endpoint_blob for kw in ("/upload", "/file", "/attach", "/import")),
            "has_ecommerce": any(kw in endpoint_blob for kw in ("/cart", "/checkout", "/payment", "/order", "/price")),
            "has_websocket": any(kw in endpoint_blob for kw in ("ws://", "wss://", "/socket", "/websocket")),
            "has_jwt": any("jwt" in s or "eyj" in s for s in secret_types) or "jwt" in tech_str,
            "has_oauth": any(kw in endpoint_blob for kw in ("/oauth", "/authorize", "/callback", "/sso")),
            "has_js": bool(scan_data.get("js", {})),
            "has_csp": True,  # Always worth checking
            "has_xml": any(kw in tech_str for kw in ("xml", "soap", "wsdl")),
            "has_python": any(kw in tech_str for kw in ("python", "django", "flask", "fastapi", "jinja")),
            "has_php": any(kw in tech_str for kw in ("php", "laravel", "symfony", "wordpress", "drupal")),
            "has_java": any(kw in tech_str for kw in ("java", "spring", "tomcat", "struts", "jboss")),
            "has_dotnet": any(kw in tech_str for kw in (".net", "asp.net", "iis", "blazor")),
            "has_cloud": any(kw in tech_str for kw in ("aws", "gcp", "azure", "cloud")),
            "has_cloud_aws": "aws" in tech_str or any("aws" in s for s in secret_types),
            "has_cdn": any(kw in tech_str for kw in ("cloudflare", "akamai", "fastly", "cdn")),
            "has_http2": True,  # Always worth checking
            "has_ssl_issues": bool(scan_data.get("ssl_analysis", {}).get("findings", [])),
            "has_github": any("github" in s for s in secret_types),
            "has_aws_keys": any("aws" in s for s in secret_types),
            "has_ldap": 389 in all_ports or "ldap" in tech_str,
            "has_k8s": any(p in all_ports for p in (6443, 8443, 10250)) or "kubernetes" in tech_str,
            "has_docker": 2375 in all_ports or "docker" in tech_str,
            "has_jenkins": 8080 in all_ports and "jenkins" in tech_str,
            "has_elastic": 9200 in all_ports,
            "has_mongodb": "mongodb" in tech_str or "nosql" in tech_str,
            "has_mongodb_port": 27017 in all_ports,
            "has_redis": 6379 in all_ports,
        }

    def _extract_all_ports(self, ports_data: dict[str, Any]) -> set[int]:
        """Extract all open port numbers from ports data."""
        all_ports: set[int] = set()
        hosts = ports_data.get("hosts", {})
        if isinstance(hosts, list):
            for entry in hosts:
                if isinstance(entry, dict):
                    for p in entry.get("ports", entry.get("open_ports", [])):
                        port_num = p if isinstance(p, int) else p.get("port", 0)
                        all_ports.add(port_num)
        elif isinstance(hosts, dict):
            for port_list in hosts.values():
                for p in (port_list if isinstance(port_list, list) else []):
                    port_num = p if isinstance(p, int) else p.get("port", 0)
                    all_ports.add(port_num)
        return all_ports

    def _get_reason(self, condition: str, scan_data: dict[str, Any]) -> str:
        """Human-readable reason why a check is applicable."""
        reasons = {
            "always": "Applies to all web targets",
            "has_login": "Login/authentication endpoints detected",
            "has_admin": "Admin panel endpoints discovered",
            "has_api": "API endpoints found",
            "has_graphql": "GraphQL endpoint detected",
            "has_params": "Multiple parameterized endpoints found",
            "has_url_params": "URL parameters present in discovered endpoints",
            "has_upload": "File upload functionality detected",
            "has_ecommerce": "E-commerce / payment endpoints found",
            "has_jwt": "JWT tokens detected in secrets or tech stack",
            "has_oauth": "OAuth/SSO endpoints discovered",
            "has_js": "JavaScript files analyzed",
            "has_python": "Python/Django/Flask detected in tech stack",
            "has_php": "PHP/WordPress/Laravel detected in tech stack",
            "has_java": "Java/Spring/Tomcat detected in tech stack",
            "has_dotnet": ".NET/ASP.NET detected in tech stack",
            "has_cloud_aws": "AWS infrastructure detected",
            "has_cloud": "Cloud infrastructure detected",
            "has_cdn": "CDN detected (Cloudflare/Akamai/Fastly)",
            "has_ssl_issues": "SSL/TLS issues found in analysis",
            "has_k8s": "Kubernetes ports/tech detected",
            "has_docker": "Docker API port detected",
            "has_elastic": "Elasticsearch port 9200 open",
            "has_mongodb_port": "MongoDB port 27017 open",
            "has_redis": "Redis port 6379 open",
        }
        return reasons.get(condition, f"Condition met: {condition}")

    def _get_verification_steps(self, check_id: str) -> list[str]:
        """Return brief verification steps for a check."""
        # Basic steps for common categories
        if check_id.startswith("AUTH"):
            return ["Test authentication endpoints manually", "Use Burp Suite intruder for brute force"]
        elif check_id.startswith("JWT"):
            return ["Decode token at jwt.io", "Test algorithm manipulation with jwt_tool"]
        elif check_id.startswith("INJ"):
            return ["Test parameters with SQLMap or manual payloads", "Check for error messages"]
        elif check_id.startswith("XSS"):
            return ["Inject XSS polyglot in all parameters", "Check DOM sources and sinks"]
        elif check_id.startswith("SSRF"):
            return ["Test URL parameters with Burp Collaborator", "Try internal IP ranges"]
        elif check_id.startswith("CLOUD"):
            return ["Verify with cloud-specific tools", "Check metadata endpoints"]
        return ["Manual verification required"]
