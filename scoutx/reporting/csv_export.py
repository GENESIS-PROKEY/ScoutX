"""CSV export — flat data for spreadsheet analysis.

Exports findings, hosts, ports, and secrets as separate CSV files.
Perfect for importing into Google Sheets, Excel, or pandas.
"""
from __future__ import annotations

import csv
import logging
from pathlib import Path

from scoutx.reporting.aggregator import ScanSummary

logger = logging.getLogger("scoutx.reporting.csv")


class CsvReporter:
    """Export scan data as CSV files."""

    def __init__(self, summary: ScanSummary) -> None:
        self._s = summary

    def generate(self, output_dir: Path) -> list[Path]:
        """Write multiple CSV files and return their paths."""
        output_dir.mkdir(parents=True, exist_ok=True)
        generated: list[Path] = []

        # Subdomains
        if self._s.subdomains:
            path = output_dir / "subdomains.csv"
            self._write_csv(path, ["hostname"], [[sub] for sub in self._s.subdomains])
            generated.append(path)

        # Alive hosts
        if self._s.alive_hosts:
            path = output_dir / "alive_hosts.csv"
            headers = ["hostname", "status_code", "title", "server", "technologies", "waf", "cdn", "final_url"]
            rows = []
            for h in self._s.alive_hosts:
                rows.append([
                    h.get("hostname", ""),
                    h.get("status_code", ""),
                    h.get("title", ""),
                    h.get("server", ""),
                    "|".join(h.get("technologies", [])),
                    h.get("waf", ""),
                    h.get("cdn", ""),
                    h.get("final_url", ""),
                ])
            self._write_csv(path, headers, rows)
            generated.append(path)

        # Open ports
        if self._s.open_ports:
            path = output_dir / "open_ports.csv"
            headers = ["host", "port", "service", "hostnames"]
            rows = []
            for p in self._s.open_ports:
                rows.append([
                    p.get("host", ""),
                    p.get("port", ""),
                    p.get("service", ""),
                    "|".join(p.get("hostnames", [])),
                ])
            self._write_csv(path, headers, rows)
            generated.append(path)

        # Secrets
        if self._s.secrets:
            path = output_dir / "secrets.csv"
            headers = ["severity", "confidence", "pattern", "match", "source_url", "source_file", "line_number", "description"]
            rows = []
            for s in self._s.secrets:
                rows.append([
                    s.get("severity", ""),
                    s.get("confidence", ""),
                    s.get("pattern", ""),
                    s.get("match", ""),
                    s.get("source_url", ""),
                    s.get("source_file", ""),
                    s.get("line_number", ""),
                    s.get("description", ""),
                ])
            self._write_csv(path, headers, rows)
            generated.append(path)

        # SSL Issues
        if self._s.ssl_issues:
            path = output_dir / "ssl_issues.csv"
            headers = ["hostname", "issue", "severity", "details"]
            rows = [[i.get("hostname", ""), i.get("issue", ""), i.get("severity", ""), i.get("details", "")] for i in self._s.ssl_issues]
            self._write_csv(path, headers, rows)
            generated.append(path)

        # Endpoints
        if self._s.endpoints:
            path = output_dir / "endpoints.csv"
            headers = ["path", "categories", "interesting", "source_count"]
            rows = []
            for e in self._s.endpoints:
                rows.append([
                    e.get("path", ""),
                    "|".join(e.get("categories", [])),
                    e.get("interesting", False),
                    len(e.get("sources", [])),
                ])
            self._write_csv(path, headers, rows)
            generated.append(path)

        # Parameters
        if self._s.parameters:
            path = output_dir / "parameters.csv"
            headers = ["name", "frequency", "interesting", "examples"]
            rows = []
            for p in self._s.parameters:
                rows.append([
                    p.get("name", ""),
                    p.get("frequency", ""),
                    p.get("interesting", False),
                    "|".join(p.get("examples", [])[:5]),
                ])
            self._write_csv(path, headers, rows)
            generated.append(path)

        logger.info("CSV export: %d files written to %s", len(generated), output_dir)
        return generated

    @staticmethod
    def _write_csv(path: Path, headers: list[str], rows: list[list]) -> None:
        """Write a CSV file with headers and rows."""
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
