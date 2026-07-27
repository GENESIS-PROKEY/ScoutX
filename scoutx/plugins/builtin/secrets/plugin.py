"""Secret Detection Plugin — 35+ regex patterns plus GitHub org hunting, entropy,
S3 bucket verification, and JWT payload decoding.

Scans downloaded JS files, HTML sources, and response bodies for
API keys, tokens, passwords, private keys, and other secrets.
Each finding gets a confidence score and severity rating.

Enhanced per Phase 10 of the Elite Methodology.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import math
import re
import shutil
from collections import Counter
from pathlib import Path
from typing import Any, TYPE_CHECKING

from scoutx.plugins.base import PluginMeta, PluginResult, ResultSchema, ScoutPlugin
from scoutx.utils.io import write_json, write_jsonl
from scoutx.utils.crypto import redact

if TYPE_CHECKING:
    from scoutx.core.engine import ScanContext

logger = logging.getLogger("scoutx.plugins.secrets")


# ── Secret patterns ────────────────────────────────────────────────────
# Each tuple: (name, pattern, severity, confidence, description)
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str, str, str]] = [
    # AWS
    ("AWS Access Key", re.compile(r"(?:AKIA|A3T[A-Z0-9])[A-Z0-9]{12,}"), "critical", "high", "AWS IAM access key"),
    ("AWS Secret Key", re.compile(r"""(?:aws_secret_access_key|aws_secret)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?""", re.IGNORECASE), "critical", "high", "AWS secret access key"),
    # Google
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), "high", "high", "Google Cloud API key"),
    ("Google OAuth", re.compile(r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com"), "high", "high", "Google OAuth client ID"),
    ("Firebase Key", re.compile(r"""["']AIza[0-9A-Za-z_-]{35}["']"""), "high", "high", "Firebase API key"),
    # GitHub
    ("GitHub Token", re.compile(r"gh[pous]_[A-Za-z0-9_]{36,}"), "critical", "high", "GitHub personal/OAuth token"),
    ("GitHub Classic Token", re.compile(r"github_pat_[A-Za-z0-9_]{22,}"), "critical", "high", "GitHub fine-grained token"),
    # Stripe
    ("Stripe Secret Key", re.compile(r"sk_live_[A-Za-z0-9]{20,}"), "critical", "high", "Stripe live secret key"),
    ("Stripe Publishable", re.compile(r"pk_live_[A-Za-z0-9]{20,}"), "medium", "high", "Stripe live publishable key"),
    # Slack
    ("Slack Token", re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}"), "critical", "high", "Slack API token"),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}"), "high", "high", "Slack incoming webhook URL"),
    # Twilio
    ("Twilio API Key", re.compile(r"SK[a-f0-9]{32}"), "high", "medium", "Twilio API key"),
    ("Twilio Account SID", re.compile(r"AC[a-f0-9]{32}"), "medium", "medium", "Twilio account SID"),
    # SendGrid
    ("SendGrid Key", re.compile(r"SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,}"), "critical", "high", "SendGrid API key"),
    # Mailgun
    ("Mailgun Key", re.compile(r"key-[A-Za-z0-9]{32}"), "high", "medium", "Mailgun API key"),
    # JWT
    ("JWT Token", re.compile(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"), "high", "high", "JSON Web Token"),
    # Private Keys
    ("RSA Private Key", re.compile(r"-----BEGIN RSA PRIVATE KEY-----"), "critical", "high", "RSA private key header"),
    ("SSH Private Key", re.compile(r"-----BEGIN (?:OPENSSH|EC|DSA) PRIVATE KEY-----"), "critical", "high", "SSH private key header"),
    ("PGP Private Key", re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"), "critical", "high", "PGP private key block"),
    # Database URLs
    ("Database URL", re.compile(r"""(?:postgres|mysql|mongodb|redis)://[^\s"'<>]{10,}""", re.IGNORECASE), "critical", "high", "Database connection string"),
    # Generic API patterns
    ("Bearer Token", re.compile(r"""(?:bearer|authorization)\s*[:=]\s*["']?([A-Za-z0-9_\-.]{20,})["']?""", re.IGNORECASE), "high", "medium", "Bearer/Authorization token"),
    ("API Key Generic", re.compile(r"""(?:api_?key|apikey|api_?secret)\s*[=:]\s*["']?([A-Za-z0-9_\-]{16,})["']?""", re.IGNORECASE), "high", "medium", "Generic API key assignment"),
    ("Secret Generic", re.compile(r"""(?:secret|password|passwd|pwd)\s*[=:]\s*["']([^"'\s]{6,})["']""", re.IGNORECASE), "high", "medium", "Generic secret/password assignment"),
    # Heroku
    ("Heroku API Key", re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "medium", "low", "Possible Heroku API key (UUID format)"),
    # Shopify
    ("Shopify Token", re.compile(r"shpat_[a-fA-F0-9]{32}"), "high", "high", "Shopify private app token"),
    ("Shopify Secret", re.compile(r"shpss_[a-fA-F0-9]{32}"), "high", "high", "Shopify shared secret"),
    # Square
    ("Square Access Token", re.compile(r"sq0atp-[A-Za-z0-9_-]{22,}"), "critical", "high", "Square access token"),
    ("Square OAuth Secret", re.compile(r"sq0csp-[A-Za-z0-9_-]{43,}"), "critical", "high", "Square OAuth secret"),
    # PayPal
    ("PayPal Braintree", re.compile(r"access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}"), "critical", "high", "PayPal Braintree access token"),
    # Discord
    ("Discord Token", re.compile(r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}"), "critical", "high", "Discord bot token"),
    ("Discord Webhook", re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"), "high", "high", "Discord webhook URL"),
    # NPM
    ("NPM Token", re.compile(r"npm_[A-Za-z0-9]{36}"), "critical", "high", "NPM access token"),
    # Cloudinary
    ("Cloudinary URL", re.compile(r"cloudinary://[0-9]+:[A-Za-z0-9_-]+@[a-z0-9]+"), "high", "high", "Cloudinary URL with credentials"),
    # Internal IPs (info only)
    ("Internal IP", re.compile(r"""["']((?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3})["']"""), "low", "low", "Internal/private IP address"),
    # Hardcoded emails with password context
    ("Email in Code", re.compile(r"""["'][a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}["']"""), "low", "low", "Hardcoded email address"),
]


class Plugin(ScoutPlugin):
    """Secret detection in JavaScript and downloaded assets."""

    meta = PluginMeta(
        name="secrets",
        description="Detect exposed secrets, API keys, credentials + GitHub org hunting, entropy, S3, JWT",
        version="0.2.0",
        author="ScoutX",
        tags=["analysis", "secrets", "credentials", "security", "github", "s3", "jwt"],
    )
    depends_on: list[str] = ["js"]
    concurrent_with: list[str] = ["endpoints"]

    async def run(self, context: ScanContext) -> PluginResult:
        from scoutx.cli.ui import info, success, warn
        from scoutx.core.events import Event, EventType

        js_data = context.result_data("js")
        downloaded_files = js_data.get("downloaded_files", [])
        if not downloaded_files:
            return PluginResult.skipped("No JS files to scan for secrets")

        output_dir = context.output_dir / "secrets"
        output_dir.mkdir(parents=True, exist_ok=True)

        info(f"Scanning {len(downloaded_files)} JS files with {len(SECRET_PATTERNS)} patterns...")

        all_findings: list[dict[str, Any]] = []
        findings_by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for js_file in downloaded_files:
            file_path = Path(js_file.get("file", ""))
            js_url = js_file.get("url", "")

            if not file_path.exists():
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            # Skip minified junk that's too short or too long per line
            if len(content) < 50:
                continue

            for pattern_name, pattern, severity, confidence, description in SECRET_PATTERNS:
                for match in pattern.finditer(content):
                    matched_text = match.group(0)
                    # Get some context around the match
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context_text = content[start:end].replace("\n", " ").strip()

                    # Skip obvious false positives
                    if _is_false_positive(pattern_name, matched_text, context_text):
                        continue

                    finding = {
                        "pattern": pattern_name,
                        "severity": severity,
                        "confidence": confidence,
                        "description": description,
                        "match": redact(matched_text, show_chars=6),
                        "match_raw": matched_text[:100],
                        "context": context_text[:200],
                        "source_url": js_url,
                        "source_file": str(file_path.name),
                        "line_number": content[:match.start()].count("\n") + 1,
                    }
                    all_findings.append(finding)
                    findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1

        # Deduplicate by match content
        seen: set[str] = set()
        deduped: list[dict[str, Any]] = []
        for finding in all_findings:
            key = f"{finding['pattern']}:{finding['match_raw']}"
            if key not in seen:
                seen.add(key)
                deduped.append(finding)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        deduped.sort(key=lambda f: severity_order.get(f["severity"], 5))

        # --- Phase 10 Enhancements ---

        # JWT payload decoding
        jwt_findings = self._decode_jwt_payloads(deduped)
        if jwt_findings:
            deduped.extend(jwt_findings)
            info(f"Decoded {len(jwt_findings)} JWT payloads")

        # Entropy-based detection
        entropy_findings = self._entropy_scan(downloaded_files)
        if entropy_findings:
            deduped.extend(entropy_findings)
            info(f"Entropy scan found {len(entropy_findings)} high-entropy strings")

        # S3 bucket verification
        s3_findings = await self._verify_s3_buckets(deduped)

        # GitHub org secret hunting (if gh CLI available)
        if shutil.which("gh"):
            info("Running GitHub org secret hunt...")
            gh_findings = await self._github_org_hunt(context.target)
            if gh_findings:
                deduped.extend(gh_findings)
                info(f"GitHub hunt found {len(gh_findings)} exposed items")

        # Recalculate totals after enhancements
        total = len(deduped)
        critical = sum(1 for f in deduped if f["severity"] == "critical")
        high = sum(1 for f in deduped if f["severity"] == "high")

        # Write outputs
        write_jsonl(output_dir / "secrets.jsonl", deduped)
        write_json(output_dir / "secrets.json", {
            "target": context.target,
            "total": total,
            "by_severity": findings_by_severity,
            "patterns_used": len(SECRET_PATTERNS),
            "files_scanned": len(downloaded_files),
            "findings": deduped,
        })

        # Emit events for critical/high findings
        for finding in deduped:
            if finding["severity"] in ("critical", "high"):
                await context.events.emit(Event(
                    type=EventType.SECRET_DETECTED,
                    data=finding,
                    scan_id=context.scan_id,
                    source="secrets",
                ))

        # Store in DB
        try:
            if context.db:
                for finding in deduped:
                    if finding["severity"] in ("critical", "high", "medium"):
                        await context.db.add_finding(
                            context.scan_id,
                            plugin_name="secrets",
                            finding_type="secret",
                            severity=finding["severity"],
                            confidence=finding["confidence"],
                            title=f"{finding['pattern']}: {finding['match']}",
                            description=finding["description"],
                            target_url=finding.get("source_url", ""),
                            evidence=finding.get("context", ""),
                            raw_data=finding,
                        )
        except Exception as exc:
            logger.warning("Failed to store secret findings: %s", exc)

        success(f"Secret scan complete: {total} findings across {len(downloaded_files)} files")

        return PluginResult.completed(
            data={"findings": deduped, "by_severity": findings_by_severity},
            findings_count=total,
            artifacts=[output_dir / "secrets.jsonl"],
        )

    # --- Phase 10 Enhancement Methods ---

    def _decode_jwt_payloads(self, findings: list[dict]) -> list[dict]:
        """Decode JWT tokens and extract payload info."""
        jwt_decoded: list[dict] = []
        for f in findings:
            if f.get("pattern") != "JWT Token":
                continue
            raw = f.get("match_raw", "")
            parts = raw.split(".")
            if len(parts) < 2:
                continue
            try:
                payload_b64 = parts[1] + "==" * (4 - len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                jwt_decoded.append({
                    "pattern": "JWT Decoded Payload",
                    "severity": "high",
                    "confidence": "high",
                    "description": "Decoded JWT payload with potentially sensitive claims",
                    "match": json.dumps(payload)[:100],
                    "match_raw": json.dumps(payload)[:200],
                    "context": f"Claims: {', '.join(payload.keys())}",
                    "source_url": f.get("source_url", ""),
                    "source_file": f.get("source_file", ""),
                    "jwt_claims": payload,
                })
            except Exception:
                pass
        return jwt_decoded

    def _entropy_scan(self, downloaded_files: list[dict]) -> list[dict]:
        """Find high-entropy strings that might be secrets."""
        findings: list[dict] = []
        # Matches quoted strings 20-80 chars with mixed case/digits
        entropy_re = re.compile(r'["\']([A-Za-z0-9+/=_-]{20,80})["\']')

        for js_file in downloaded_files[:30]:  # Limit for performance
            file_path = Path(js_file.get("file", ""))
            if not file_path.exists():
                continue
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            for match in entropy_re.finditer(content):
                val = match.group(1)
                ent = self._shannon_entropy(val)
                if ent > 4.5 and len(val) >= 20:
                    # Check it's not just a hash or minified var
                    if not val.startswith("data:") and "." not in val[:10]:
                        findings.append({
                            "pattern": "High Entropy String",
                            "severity": "medium",
                            "confidence": "medium",
                            "description": f"Shannon entropy {ent:.2f} (threshold 4.5)",
                            "match": redact(val, show_chars=8),
                            "match_raw": val[:60],
                            "context": content[max(0, match.start()-30):match.end()+30][:150],
                            "source_url": js_file.get("url", ""),
                            "source_file": str(file_path.name),
                        })
                        if len(findings) > 50:  # Cap entropy findings
                            return findings
        return findings

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )

    async def _verify_s3_buckets(self, findings: list[dict]) -> list[dict]:
        """Verify discovered S3 bucket references."""
        s3_verified: list[dict] = []
        s3_re = re.compile(r'([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3[.-]')

        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            for f in findings:
                raw = f.get("match_raw", "")
                for bucket_match in s3_re.finditer(raw):
                    bucket = bucket_match.group(1)
                    try:
                        r = await client.get(f"https://{bucket}.s3.amazonaws.com/")
                        if r.status_code != 403:
                            f["s3_verified"] = True
                            f["s3_status"] = r.status_code
                            if r.status_code == 200:
                                f["severity"] = "critical"
                                f["description"] += " [S3 BUCKET PUBLIC]"
                            s3_verified.append(f)
                    except Exception:
                        pass
        return s3_verified

    async def _github_org_hunt(self, domain: str) -> list[dict]:
        """Hunt for secrets in GitHub repos related to the target domain."""
        findings: list[dict] = []
        org_name = domain.split(".")[0]
        try:
            proc = await asyncio.create_subprocess_exec(
                "gh", "search", "code", f"{domain} password OR secret OR api_key",
                "--limit", "20", "--json", "path,repository,textMatches",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            results = json.loads(stdout.decode("utf-8", errors="replace"))
            for result in results:
                findings.append({
                    "pattern": "GitHub Code Search",
                    "severity": "high",
                    "confidence": "medium",
                    "description": f"Secret-like content found in GitHub repo",
                    "match": result.get("path", ""),
                    "match_raw": result.get("path", ""),
                    "context": f"Repo: {result.get('repository', {}).get('nameWithOwner', '')}",
                    "source_url": f"https://github.com/{result.get('repository', {}).get('nameWithOwner', '')}",
                    "source_file": result.get("path", ""),
                })
        except Exception as exc:
            logger.debug("GitHub hunt failed: %s", exc)
        return findings

    def schema(self) -> ResultSchema:
        return ResultSchema(
            fields={"findings": list, "by_severity": dict},
            description="Detected secrets with severity, confidence, evidence, JWT decoding, entropy",
        )


def _is_false_positive(pattern_name: str, match: str, context: str) -> bool:
    """Heuristic false positive suppression."""
    lower_ctx = context.lower()

    # Skip test/example/placeholder values
    fp_indicators = [
        "example", "test", "placeholder", "your_", "xxx", "000",
        "insert_", "replace_", "todo", "fixme", "dummy", "fake",
        "sample", "template", "demo", "mock",
    ]
    for indicator in fp_indicators:
        if indicator in match.lower() or indicator in lower_ctx:
            return True

    # UUID pattern — too many false positives unless in auth context
    if pattern_name == "Heroku API Key":
        auth_words = ["key", "token", "secret", "api", "auth", "credential"]
        if not any(w in lower_ctx for w in auth_words):
            return True

    # Email — skip if it's clearly documentation
    if pattern_name == "Email in Code":
        if "example.com" in match or "@test" in match:
            return True

    # Internal IP — skip common documentation IPs
    if pattern_name == "Internal IP":
        if "192.168.1.1" in match or "10.0.0.1" in match or "172.16.0.1" in match:
            return True

    return False
