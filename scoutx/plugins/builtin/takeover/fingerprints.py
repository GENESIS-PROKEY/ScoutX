"""Takeover fingerprint database — CNAME patterns and error page signatures.

Each fingerprint describes a cloud service that can potentially be claimed
when a CNAME points to it but the underlying resource no longer exists.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TakeoverFingerprint:
    """A single takeover fingerprint."""

    service: str
    cname_patterns: tuple[str, ...]   # Substrings to match in CNAME targets
    body_patterns: tuple[str, ...]    # Substrings to match in HTTP response body
    vulnerable: bool = True           # False = dangling but not claimable
    severity: str = "high"            # critical / high / medium / info


# Master fingerprint database — 24 services
FINGERPRINTS: tuple[TakeoverFingerprint, ...] = (
    TakeoverFingerprint(
        service="AWS S3",
        cname_patterns=("s3.amazonaws.com", ".s3-website", "s3-ap-", "s3-us-", "s3-eu-"),
        body_patterns=("NoSuchBucket", "The specified bucket does not exist"),
        severity="critical",
    ),
    TakeoverFingerprint(
        service="AWS CloudFront",
        cname_patterns=("cloudfront.net",),
        body_patterns=("Bad request", "ERROR: The request could not be satisfied"),
        severity="high",
    ),
    TakeoverFingerprint(
        service="GitHub Pages",
        cname_patterns=("github.io",),
        body_patterns=("There isn't a GitHub Pages site here",),
        severity="critical",
    ),
    TakeoverFingerprint(
        service="Heroku",
        cname_patterns=("herokudns.com", "herokuapp.com", "herokussl.com"),
        body_patterns=("No such app", "no-such-app"),
        severity="critical",
    ),
    TakeoverFingerprint(
        service="Azure Web Apps",
        cname_patterns=("azurewebsites.net",),
        body_patterns=("404 Web Site not found",),
        severity="high",
    ),
    TakeoverFingerprint(
        service="Azure Traffic Manager",
        cname_patterns=("trafficmanager.net",),
        body_patterns=("404 Web Site not found",),
        severity="high",
    ),
    TakeoverFingerprint(
        service="Azure CloudApp",
        cname_patterns=("cloudapp.azure.com", "cloudapp.net"),
        body_patterns=("404 Web Site not found",),
        severity="high",
    ),
    TakeoverFingerprint(
        service="Shopify",
        cname_patterns=("myshopify.com",),
        body_patterns=("Sorry, this shop is currently unavailable",),
        severity="critical",
    ),
    TakeoverFingerprint(
        service="Fastly",
        cname_patterns=("fastly.net", "fastlylb.net"),
        body_patterns=("Fastly error: unknown domain",),
        severity="high",
    ),
    TakeoverFingerprint(
        service="Pantheon",
        cname_patterns=("pantheonsite.io",),
        body_patterns=("404 error unknown site", "The gods are wise"),
        severity="high",
    ),
    TakeoverFingerprint(
        service="Tumblr",
        cname_patterns=("domains.tumblr.com",),
        body_patterns=("There's nothing here", "Whatever you were looking for"),
        severity="high",
    ),
    TakeoverFingerprint(
        service="WordPress.com",
        cname_patterns=("wordpress.com",),
        body_patterns=("Do you want to register",),
        severity="medium",
    ),
    TakeoverFingerprint(
        service="Ghost",
        cname_patterns=("ghost.io",),
        body_patterns=("The thing you were looking for is no longer here",),
        severity="high",
    ),
    TakeoverFingerprint(
        service="Surge.sh",
        cname_patterns=("surge.sh",),
        body_patterns=("project not found",),
        severity="high",
    ),
    TakeoverFingerprint(
        service="Bitbucket",
        cname_patterns=("bitbucket.io",),
        body_patterns=("Repository not found",),
        severity="high",
    ),
    TakeoverFingerprint(
        service="Zendesk",
        cname_patterns=("zendesk.com",),
        body_patterns=("Help Center Closed",),
        severity="medium",
    ),
    TakeoverFingerprint(
        service="Readme.io",
        cname_patterns=("readme.io",),
        body_patterns=("Project doesnt exist",),
        severity="high",
    ),
    TakeoverFingerprint(
        service="HubSpot",
        cname_patterns=("hs-sites.com", "hubspot.net"),
        body_patterns=("Domain not found",),
        severity="high",
    ),
    TakeoverFingerprint(
        service="Cargo Collective",
        cname_patterns=("cargocollective.com",),
        body_patterns=("If you're moving",),
        severity="medium",
    ),
    TakeoverFingerprint(
        service="Statuspage",
        cname_patterns=("statuspage.io",),
        body_patterns=("Status page pushed a DNS", "You are being redirected"),
        severity="medium",
    ),
    TakeoverFingerprint(
        service="Intercom",
        cname_patterns=("custom.intercom.help",),
        body_patterns=("Uh oh",),
        severity="medium",
    ),
    TakeoverFingerprint(
        service="Unbounce",
        cname_patterns=("unbouncepages.com",),
        body_patterns=("The requested URL was not found",),
        severity="high",
    ),
    TakeoverFingerprint(
        service="Fly.io",
        cname_patterns=("fly.dev", "fly.io"),
        body_patterns=("404 Not Found",),
        severity="medium",
    ),
    TakeoverFingerprint(
        service="Netlify",
        cname_patterns=("netlify.app", "netlify.com"),
        body_patterns=("Not Found - Request ID",),
        severity="high",
    ),
    TakeoverFingerprint(
        service="Vercel",
        cname_patterns=("vercel.app", "vercel.com", "now.sh"),
        body_patterns=(),
        vulnerable=False,
        severity="info",
    ),
    TakeoverFingerprint(
        service="Render",
        cname_patterns=("onrender.com",),
        body_patterns=(),
        vulnerable=False,
        severity="info",
    ),
)


def match_cname(cname: str) -> list[TakeoverFingerprint]:
    """Find all fingerprints matching a CNAME target."""
    cname_lower = cname.lower()
    return [fp for fp in FINGERPRINTS if any(p in cname_lower for p in fp.cname_patterns)]


def match_body(body: str) -> list[TakeoverFingerprint]:
    """Find all fingerprints matching an HTTP response body."""
    return [
        fp for fp in FINGERPRINTS
        if fp.body_patterns and any(p.lower() in body.lower() for p in fp.body_patterns)
    ]
