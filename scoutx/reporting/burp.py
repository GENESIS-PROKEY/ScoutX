"""Burp Suite XML export format."""
from __future__ import annotations

import asyncio
import html
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("scoutx.reporting.burp")


class BurpReporter:
    """Generate a Burp Suite compatible XML report."""

    async def generate(self, scan_data: dict[str, Any], output_dir: Path) -> Path:
        """Render and write the Burp XML report."""
        export_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        
        xml_parts = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<issues burpVersion="2024.0" exportTime="{html.escape(export_time)}">'
        ]
        
        serial = 1
        
        # 1. Secrets -> Information disclosure (5244416)
        secrets = scan_data.get("secrets", [])
        for secret in secrets:
            severity = str(secret.get("severity", "High")).capitalize()
            # Burp severities: High, Medium, Low, Information
            if severity.lower() == "info":
                severity = "Information"
                
            match = html.escape(str(secret.get("match", "")))
            pattern = html.escape(str(secret.get("pattern", "")))
            source = html.escape(str(secret.get("source_file", "")))
            
            xml_parts.append("  <issue>")
            xml_parts.append(f"    <serialNumber>{serial}</serialNumber>")
            xml_parts.append(f"    <type>5244416</type>")
            xml_parts.append(f"    <name>Information disclosure: {pattern}</name>")
            xml_parts.append(f"    <host>https://{html.escape(str(scan_data.get('target', '')))}</host>")
            xml_parts.append(f"    <path>{source}</path>")
            xml_parts.append(f"    <location>{source}</location>")
            xml_parts.append(f"    <severity>{severity}</severity>")
            xml_parts.append(f"    <confidence>Firm</confidence>")
            xml_parts.append(f"    <issueBackground>An exposed secret or API key was found.</issueBackground>")
            xml_parts.append(f"    <remediationBackground>Remove the secret and revoke the compromised credentials.</remediationBackground>")
            xml_parts.append(f"    <issueDetail>Secret match: {match}</issueDetail>")
            xml_parts.append("  </issue>")
            serial += 1

        # 2. SSL issues -> SSL certificate (16842752)
        ssl_issues = scan_data.get("ssl_issues", [])
        for ssl in ssl_issues:
            severity = str(ssl.get("severity", "Low")).capitalize()
            if severity.lower() == "info":
                severity = "Information"
                
            issue_title = html.escape(str(ssl.get("issue", "SSL Issue")))
            hostname = html.escape(str(ssl.get("hostname", "")))
            details = html.escape(str(ssl.get("details", "")))
            
            xml_parts.append("  <issue>")
            xml_parts.append(f"    <serialNumber>{serial}</serialNumber>")
            xml_parts.append(f"    <type>16842752</type>")
            xml_parts.append(f"    <name>SSL certificate: {issue_title}</name>")
            xml_parts.append(f"    <host>https://{hostname}</host>")
            xml_parts.append(f"    <path>/</path>")
            xml_parts.append(f"    <location>/</location>")
            xml_parts.append(f"    <severity>{severity}</severity>")
            xml_parts.append(f"    <confidence>Certain</confidence>")
            xml_parts.append(f"    <issueBackground>A potential SSL/TLS configuration issue was found.</issueBackground>")
            xml_parts.append(f"    <remediationBackground>Ensure the server is configured with strong ciphers and valid certificates.</remediationBackground>")
            xml_parts.append(f"    <issueDetail>{details}</issueDetail>")
            xml_parts.append("  </issue>")
            serial += 1

        # 3. Open ports -> Open port
        open_ports = scan_data.get("open_ports", [])
        for port in open_ports:
            p_num = port.get("port", 0)
            service = html.escape(str(port.get("service", "")))
            host = html.escape(str(port.get("host", "")))
            
            xml_parts.append("  <issue>")
            xml_parts.append(f"    <serialNumber>{serial}</serialNumber>")
            xml_parts.append(f"    <type>0</type>")
            xml_parts.append(f"    <name>Open port {p_num} ({service})</name>")
            xml_parts.append(f"    <host>{host}</host>")
            xml_parts.append(f"    <path>/</path>")
            xml_parts.append(f"    <location>/</location>")
            xml_parts.append(f"    <severity>Information</severity>")
            xml_parts.append(f"    <confidence>Certain</confidence>")
            xml_parts.append(f"    <issueBackground>An open network port was detected.</issueBackground>")
            xml_parts.append(f"    <remediationBackground>Ensure this port is intended to be exposed.</remediationBackground>")
            xml_parts.append(f"    <issueDetail>Port {p_num} is open.</issueDetail>")
            xml_parts.append("  </issue>")
            serial += 1

        # 4. Endpoints / CORS could be mapped if they exist in some structured way.
        # Assuming we might find CORS in endpoints categories or attack chains.
        attack_chains = scan_data.get("attack_chains", [])
        for chain in attack_chains:
            severity = str(chain.get("severity", "Medium")).capitalize()
            if severity.lower() == "info":
                severity = "Information"
                
            cat = chain.get("category", "").lower()
            if "cors" in cat:
                type_id = "1049088"
                name_prefix = "Cross-origin resource sharing"
            else:
                type_id = "0"
                name_prefix = "Vulnerability"
                
            title = html.escape(str(chain.get("title", f"{name_prefix} finding")))
            desc = html.escape(str(chain.get("description", "")))
            
            xml_parts.append("  <issue>")
            xml_parts.append(f"    <serialNumber>{serial}</serialNumber>")
            xml_parts.append(f"    <type>{type_id}</type>")
            xml_parts.append(f"    <name>{title}</name>")
            xml_parts.append(f"    <host>https://{html.escape(str(scan_data.get('target', '')))}</host>")
            xml_parts.append(f"    <path>/</path>")
            xml_parts.append(f"    <location>/</location>")
            xml_parts.append(f"    <severity>{severity}</severity>")
            xml_parts.append(f"    <confidence>Tentative</confidence>")
            xml_parts.append(f"    <issueBackground>{desc}</issueBackground>")
            xml_parts.append(f"    <remediationBackground>Investigate and resolve the reported issue.</remediationBackground>")
            xml_parts.append(f"    <issueDetail>{desc}</issueDetail>")
            xml_parts.append("  </issue>")
            serial += 1
            
        xml_parts.append("</issues>")
        
        xml_content = "\n".join(xml_parts)
        
        output_dir.mkdir(parents=True, exist_ok=True)
        out_path = output_dir / "burp_export.xml"
        out_path.write_text(xml_content, encoding="utf-8")
        
        logger.info("Burp XML report written to %s", out_path)
        return out_path
