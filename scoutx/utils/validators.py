"""Input validation — domains, URLs, IPs, CIDR.

If it's touching the network, it goes through validation first. No exceptions.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse, urlunparse

# RFC-compliant-ish domain regex — good enough for recon
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_IP_V4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def validate_domain(domain: str) -> str:
    """Validate and normalise a domain name.

    Strips protocol, paths, ports, trailing dots. Raises ValueError if invalid.
    """
    value = domain.strip().lower()

    # Strip common prefixes
    for prefix in ("https://", "http://", "//"):
        if value.startswith(prefix):
            value = value[len(prefix):]

    # Strip path, port, query
    value = value.split("/")[0].split("?")[0].split("#")[0]
    if ":" in value:
        value = value.split(":")[0]

    # Strip trailing dot
    value = value.rstrip(".")

    # Strip wildcard prefix
    if value.startswith("*."):
        value = value[2:]

    if not value:
        raise ValueError("Empty domain")

    if not _DOMAIN_RE.match(value):
        raise ValueError(f"Invalid domain: {value}")

    return value


def validate_url(url: str) -> str:
    """Validate and return a normalised URL."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https", ""):
        raise ValueError(f"Unsupported scheme: {parsed.scheme}")
    if not parsed.hostname:
        raise ValueError(f"No hostname in URL: {url}")
    return url.strip()


def validate_ip(ip: str) -> str:
    """Validate an IPv4 or IPv6 address."""
    try:
        addr = ipaddress.ip_address(ip.strip())
        return str(addr)
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip}")


def validate_cidr(cidr: str) -> str:
    """Validate CIDR notation."""
    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
        return str(network)
    except ValueError:
        raise ValueError(f"Invalid CIDR: {cidr}")


def normalize_target(target: str) -> str:
    """Normalise any target input — domain, URL, or IP."""
    value = target.strip()

    # If it looks like a URL, extract the hostname
    if value.startswith(("http://", "https://", "//")):
        parsed = urlparse(value)
        value = parsed.hostname or value

    # Strip trailing dot, lowercase
    value = value.strip().lower().rstrip(".")

    # Strip port
    if ":" in value:
        value = value.split(":")[0]

    return value


def normalize_url(url: str) -> str:
    """Normalise a URL: lowercase hostname, remove default ports, strip trailing slash."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    scheme = parsed.scheme or "https"

    # Remove default ports
    port = parsed.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None

    netloc = hostname
    if port:
        netloc = f"{hostname}:{port}"

    path = parsed.path.rstrip("/") or "/"

    return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))


def is_ip(value: str) -> bool:
    """Check if value is an IP address."""
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_domain(value: str) -> bool:
    """Check if value is a valid domain."""
    return bool(_DOMAIN_RE.match(value.strip().lower().rstrip(".")))


def extract_hostname(url: str) -> str:
    """Extract hostname from a URL."""
    parsed = urlparse(url)
    return (parsed.hostname or "").lower()
