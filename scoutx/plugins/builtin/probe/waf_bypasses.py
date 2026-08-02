"""WAF Bypass Knowledge Base — fingerprints and documented bypass techniques.

Contains detection signatures and known bypass methods for common
Web Application Firewalls. Used by the probe plugin and attack chain
engine to provide actionable intelligence.
"""
from __future__ import annotations

from typing import Any

# WAF detection signatures and documented bypass techniques
# Sources: published research, vendor documentation, bug bounty writeups
WAF_BYPASSES: dict[str, dict[str, Any]] = {
    "cloudflare": {
        "detection": ["server: cloudflare", "cf-ray", "cf-cache-status", "__cfduid"],
        "techniques": [
            "Discover origin IP via historical DNS records (SecurityTrails, DNS history)",
            "Check MX records — mail servers often expose origin IP",
            "Search Shodan/Censys for SSL certificate hash to find origin",
            "Try direct IP access with original Host header",
            "Check for subdomain CNAMEs that bypass the proxy",
            "Use CloudFail or similar origin-finding tools",
        ],
        "header_tests": ["X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP", "True-Client-IP"],
        "notes": "Cloudflare can be bypassed if origin IP is discovered. Focus on DNS/cert recon.",
    },
    "aws_waf": {
        "detection": ["x-amzn-requestid", "x-amzn-trace-id", "awselb"],
        "techniques": [
            "Check for API Gateway endpoints that may not have WAF rules",
            "Test with different HTTP methods (PUT, PATCH) that may lack rules",
            "Try request smuggling via malformed Content-Length/Transfer-Encoding",
            "Use Unicode/encoding tricks for payload obfuscation",
            "Check for Lambda@Edge misconfigurations",
        ],
        "header_tests": ["X-Forwarded-For", "X-Amzn-Trace-Id"],
        "notes": "AWS WAF rules are customer-defined. Coverage varies greatly.",
    },
    "akamai": {
        "detection": [
            "server: akamaighost", "x-akamai-", "akamai-grn",
            "akamaighost", "akamai.net",
        ],
        "techniques": [
            "Find origin via DNS history or SSL certificate search",
            "Test edge cases in Akamai's rule engine with encoding variations",
            "Check for staging/dev environments without WAF",
            "Use path traversal encoding variants (..;/, %2e%2e/)",
        ],
        "header_tests": ["X-Forwarded-For", "True-Client-IP", "Akamai-Origin-Hop"],
        "notes": "Akamai is enterprise-grade. Focus on finding unprotected origins.",
    },
    "imperva": {
        "detection": [
            "x-cdn: imperva", "x-iinfo", "incap_ses_", "visid_incap_",
            "_incapsula_", "imperva",
        ],
        "techniques": [
            "Discover origin IP via historical DNS or email headers",
            "Check for secondary domains/subdomains without protection",
            "Test with double URL encoding",
            "Try HPP (HTTP Parameter Pollution) to split payloads",
            "Check Incapsula bypass via direct IP with Host header",
        ],
        "header_tests": ["X-Forwarded-For", "X-Real-IP", "Incap-Client-IP"],
        "notes": "Imperva/Incapsula. Origin discovery is the primary bypass vector.",
    },
    "modsecurity": {
        "detection": ["server: modsecurity", "mod_security", "NOYB"],
        "techniques": [
            "Identify CRS version and check for known rule bypasses",
            "Test with unusual encodings (double URL, Unicode, overlong UTF-8)",
            "Use comment injection in SQL (/*!50000 ...*/)",
            "Try case variations and concatenation tricks",
            "Check paranoia level — lower levels have more bypasses",
        ],
        "header_tests": [],
        "notes": "Open-source WAF. Bypass difficulty depends heavily on CRS version and paranoia level.",
    },
    "sucuri": {
        "detection": ["server: sucuri", "x-sucuri-id", "sucuri-", "cloudproxy"],
        "techniques": [
            "Find origin IP via DNS history",
            "Check for MX records pointing to origin",
            "Try direct IP access with original Host header",
            "Look for subdomains not proxied through Sucuri",
        ],
        "header_tests": ["X-Forwarded-For", "X-Real-IP"],
        "notes": "Cloud proxy WAF. Origin IP discovery is the main bypass path.",
    },
    "f5_bigip": {
        "detection": ["server: bigip", "x-wa-info", "bigipserver", "f5-"],
        "techniques": [
            "Check for ASM policy gaps in specific URL paths",
            "Test with chunked transfer encoding",
            "Try HTTP desync / request smuggling",
            "Check for iRules misconfigurations",
        ],
        "header_tests": ["X-Forwarded-For"],
        "notes": "Enterprise ADC with WAF module. Complex ruleset, focus on edge cases.",
    },
    "barracuda": {
        "detection": ["server: barracuda", "barra_counter_session", "barracuda-"],
        "techniques": [
            "Test with URL encoding variations",
            "Check for bypass via HTTP/2 or HTTP/1.0 downgrade",
            "Try multipart form data with unusual boundaries",
        ],
        "header_tests": ["X-Forwarded-For"],
        "notes": "Appliance-based WAF. Less common in cloud deployments.",
    },
    "fortinet": {
        "detection": ["server: fortiweb", "fortigate", "fortiwafd"],
        "techniques": [
            "Check for rule gaps in non-standard content types",
            "Test with alternative encodings",
            "Try request smuggling via malformed headers",
        ],
        "header_tests": ["X-Forwarded-For"],
        "notes": "Fortinet FortiWeb. Enterprise WAF with signature-based detection.",
    },
    "wordfence": {
        "detection": ["wordfence", "wfwaf-"],
        "techniques": [
            "WordPress-specific WAF — focus on non-WP attack vectors",
            "Check REST API endpoints that may not be covered",
            "Test with user-agent spoofing (Googlebot, etc.)",
        ],
        "header_tests": [],
        "notes": "WordPress-only WAF plugin. Only protects WP paths.",
    },
}


def get_bypass_suggestions(waf_name: str) -> dict[str, Any] | None:
    """Get bypass techniques for a detected WAF.

    Args:
        waf_name: WAF identifier (lowercase). Partial matching supported.

    Returns:
        Dict with techniques, header_tests, and notes. None if unknown WAF.
    """
    # Exact match first
    if waf_name.lower() in WAF_BYPASSES:
        return WAF_BYPASSES[waf_name.lower()]

    # Partial match
    for key, data in WAF_BYPASSES.items():
        if key in waf_name.lower() or waf_name.lower() in key:
            return data

    return None


def detect_waf_from_headers(headers: dict[str, str]) -> list[str]:
    """Detect WAF(s) from HTTP response headers.

    Returns list of detected WAF names.
    """
    detected = []
    header_str = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()

    for waf_name, config in WAF_BYPASSES.items():
        for sig in config["detection"]:
            if sig.lower() in header_str:
                if waf_name not in detected:
                    detected.append(waf_name)
                break

    return detected
