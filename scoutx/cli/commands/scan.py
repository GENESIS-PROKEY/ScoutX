"""Scan commands — the bread and butter of ScoutX."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer

from scoutx.cli.ui import console, error, info, print_module_header, success, warn


def register(app: typer.Typer) -> None:
    """Register scan commands on the given Typer app."""

    @app.command()
    def full(
        domain: str = typer.Argument(..., help="Target domain, e.g. example.com"),
        output: Path = typer.Option(Path("results"), "-o", "--output", help="Output directory"),
        profile: str = typer.Option("balanced", "--profile", help="Safety profile: safe, balanced, aggressive, passive, quick"),
        proxy: Optional[str] = typer.Option(None, "--proxy", help="HTTP/SOCKS5 proxy"),
        user_agent: Optional[str] = typer.Option(None, "--user-agent", help="Custom User-Agent"),
        random_user_agent: bool = typer.Option(False, "--random-ua", help="Rotate User-Agent per request"),
        resume_mode: bool = typer.Option(False, "--resume", help="Resume from last checkpoint"),
        report_flag: bool = typer.Option(True, "--report/--no-report", help="Generate report after scan"),
        scope_file: Optional[Path] = typer.Option(None, "--scope", help="Scope definition file"),
        config_path: Optional[Path] = typer.Option(None, "--config", "-c", help="Config file path"),
        quick: bool = typer.Option(False, "--quick", help="Quick scan: subdomains + probe + ports only (~60s)"),
        passive: bool = typer.Option(False, "--passive", help="Passive mode: OSINT only, zero active requests"),
        no_tui: bool = typer.Option(False, "--no-tui", help="Disable live terminal UI"),
        report_format: str = typer.Option("html,md", "--format", "-f", help="Report formats: html, md, csv, sarif, obsidian, burp"),
    ) -> None:
        """Run the full async recon pipeline.

        Pipeline phases run concurrently where possible:
        subdomains → [probe | ports | ssl] → [js | params | takeover] →
        [endpoints | secrets | screenshots] → [intelligence | nuclei] → report
        """
        try:
            from scoutx.core.config import ScoutXConfig
            from scoutx.core.engine import ScanEngine
            from scoutx.core.events import EventBus
            from scoutx.core.scope import Scope
            from scoutx.database.repository import Repository
            from scoutx.plugins.manager import PluginManager
            from scoutx.utils.validators import validate_domain

            target = validate_domain(domain)
            info(f"Target acquired: {target}")
            info(f"Safety profile: {profile}")

            # Override profile for quick/passive shortcuts
            if quick:
                profile = "quick"
            elif passive:
                profile = "passive"

            config = ScoutXConfig(config_path=config_path, overrides={
                "scan_profile": profile,
                **({"stealth.proxy": proxy} if proxy else {}),
                **({"stealth.random_user_agent": random_user_agent} if random_user_agent else {}),
            })

            scope = Scope.from_file(scope_file) if scope_file else Scope.from_target(target)
            event_bus = EventBus()
            plugin_manager = PluginManager(config)
            plugin_manager.discover_builtin()

            db = Repository(config.database_path)

            engine = ScanEngine(
                config=config,
                scope=scope,
                plugin_manager=plugin_manager,
                db=db,
                event_bus=event_bus,
            )

            result = asyncio.run(engine.run(
                target=target,
                profile=profile,
                resume=resume_mode,
                output_dir=output,
            ))

            if result.status == "completed":
                success(f"Scan completed in {result.duration_seconds:.1f}s")
            elif result.status == "partial":
                warn(f"Scan completed with warnings in {result.duration_seconds:.1f}s")
            else:
                error(f"Scan failed after {result.duration_seconds:.1f}s")

            # Auto-generate reports if scan produced results
            if report_flag and result.status in ("completed", "partial"):
                try:
                    from scoutx.reporting.aggregator import ScanAggregator
                    from scoutx.reporting.html import HtmlReporter
                    from scoutx.reporting.markdown import MarkdownReporter

                    info("Generating reports...")
                    scan_dir = output / target
                    aggregator = ScanAggregator(scan_dir, target)
                    summary = aggregator.aggregate()

                    report_dir = scan_dir / "reports"
                    report_dir.mkdir(parents=True, exist_ok=True)

                    HtmlReporter(summary).generate(report_dir / "report.html")
                    MarkdownReporter(summary).generate(report_dir / "report.md")

                    # Obsidian export if requested
                    formats = [f.strip().lower() for f in report_format.split(",")]
                    if "obsidian" in formats:
                        try:
                            from scoutx.reporting.obsidian import ObsidianReporter
                            ObsidianReporter(summary.to_dict() if hasattr(summary, 'to_dict') else {}).generate_sync(report_dir / "obsidian")
                            success("Obsidian vault exported")
                        except Exception as obs_exc:
                            warn(f"Obsidian export failed: {obs_exc}")

                    if "burp" in formats:
                        try:
                            import asyncio
                            from scoutx.reporting.burp import BurpReporter
                            burp_reporter = BurpReporter()
                            asyncio.run(burp_reporter.generate(summary.to_dict() if hasattr(summary, 'to_dict') else {}, report_dir))
                            success("Burp XML exported")
                        except Exception as burp_exc:
                            warn(f"Burp export failed: {burp_exc}")

                    success(f"Reports generated in {report_dir}")
                except Exception as report_exc:
                    warn(f"Report generation failed: {report_exc}")

        except ValueError as exc:
            error(f"Invalid target: {exc}")
            raise typer.Exit(code=1) from exc
        except KeyboardInterrupt:
            warn("Scan interrupted by user")
            raise typer.Exit(code=130)
        except Exception as exc:
            error(f"Scan error: {exc}")
            raise typer.Exit(code=1) from exc

    @app.command("scan")
    def scan(
        domain: str = typer.Argument(..., help="Target domain, e.g. example.com"),
        output: Path = typer.Option(Path("results"), "-o", "--output"),
        profile: str = typer.Option("balanced", "--profile"),
        proxy: Optional[str] = typer.Option(None, "--proxy"),
        user_agent: Optional[str] = typer.Option(None, "--user-agent"),
        random_user_agent: bool = typer.Option(False, "--random-ua"),
        resume_mode: bool = typer.Option(False, "--resume"),
        report_flag: bool = typer.Option(True, "--report/--no-report"),
        scope_file: Optional[Path] = typer.Option(None, "--scope"),
        config_path: Optional[Path] = typer.Option(None, "--config", "-c"),
        quick: bool = typer.Option(False, "--quick"),
        passive: bool = typer.Option(False, "--passive"),
        no_tui: bool = typer.Option(False, "--no-tui"),
        report_format: str = typer.Option("html,md", "--format", "-f"),
    ) -> None:
        """Start a full recon workflow (alias for full)."""
        info("`scan` is an alias for `full` — running the standard workflow.")
        full(
            domain=domain,
            output=output,
            profile=profile,
            proxy=proxy,
            user_agent=user_agent,
            random_user_agent=random_user_agent,
            resume_mode=resume_mode,
            report_flag=report_flag,
            scope_file=scope_file,
            config_path=config_path,
            quick=quick,
            passive=passive,
            no_tui=no_tui,
            report_format=report_format,
        )

    @app.command()
    def resume(
        domain: str = typer.Argument(..., help="Target domain to resume"),
        output: Path = typer.Option(Path("results"), "-o", "--output"),
        config_path: Optional[Path] = typer.Option(None, "--config", "-c"),
    ) -> None:
        """Resume an interrupted scan from last checkpoint."""
        full(
            domain=domain,
            output=output,
            profile="balanced",
            proxy=None,
            user_agent=None,
            random_user_agent=False,
            resume_mode=True,
            report_flag=True,
            scope_file=None,
            config_path=config_path,
            quick=False,
            passive=False,
            no_tui=False,
            report_format="html,md",
        )

    @app.command()
    def report(
        domain: str = typer.Argument(..., help="Target domain"),
        output: Path = typer.Option(Path("results"), "-o", "--output"),
        fmt: str = typer.Option("html,md", "--format", "-f", help="Report formats: html, md, csv, sarif, obsidian, pdf, burp"),
    ) -> None:
        """Generate reports from existing scan data."""
        from scoutx.reporting.aggregator import ScanAggregator
        from scoutx.utils.validators import validate_domain

        try:
            target = validate_domain(domain)
            print_module_header("Report Generation", target)

            scan_dir = output / target
            if not scan_dir.exists():
                error(f"No scan data found at {scan_dir}")
                raise typer.Exit(code=1)

            # Aggregate scan data
            info("Aggregating scan results...")
            aggregator = ScanAggregator(scan_dir, target)
            summary = aggregator.aggregate()

            formats = [f.strip().lower() for f in fmt.split(",")]
            report_dir = scan_dir / "reports"
            report_dir.mkdir(parents=True, exist_ok=True)
            generated: list[str] = []

            if "html" in formats:
                from scoutx.reporting.html import HtmlReporter
                path = HtmlReporter(summary).generate(report_dir / "report.html")
                generated.append(f"HTML: {path}")
                success(f"HTML report: {path}")

            if "md" in formats or "markdown" in formats:
                from scoutx.reporting.markdown import MarkdownReporter
                path = MarkdownReporter(summary).generate(report_dir / "report.md")
                generated.append(f"Markdown: {path}")
                success(f"Markdown report: {path}")

            if "csv" in formats:
                from scoutx.reporting.csv_export import CsvReporter
                paths = CsvReporter(summary).generate(report_dir / "csv")
                for p in paths:
                    generated.append(f"CSV: {p}")
                success(f"CSV export: {len(paths)} files")

            if "sarif" in formats:
                from scoutx.reporting.sarif import SarifReporter
                path = SarifReporter(summary).generate(report_dir / "report.sarif.json")
                generated.append(f"SARIF: {path}")
                success(f"SARIF report: {path}")

            if "obsidian" in formats:
                try:
                    from scoutx.reporting.obsidian import ObsidianReporter
                    ObsidianReporter(summary.to_dict() if hasattr(summary, 'to_dict') else {}).generate_sync(report_dir / "obsidian")
                    generated.append("Obsidian: vault")
                    success("Obsidian vault exported")
                except Exception as obs_exc:
                    warn(f"Obsidian export failed: {obs_exc}")

            if "pdf" in formats:
                try:
                    import asyncio

                    from scoutx.reporting.pdf import PdfReporter
                    pdf_reporter = PdfReporter()
                    pdf_path = asyncio.run(pdf_reporter.generate(summary.to_dict() if hasattr(summary, 'to_dict') else {}, report_dir))
                    if pdf_path:
                        generated.append(f"PDF: {pdf_path}")
                        success(f"PDF report: {pdf_path}")
                    else:
                        warn("PDF export skipped (install weasyprint or playwright)")
                except Exception as pdf_exc:
                    warn(f"PDF export failed: {pdf_exc}")

            if "burp" in formats:
                try:
                    import asyncio
                    from scoutx.reporting.burp import BurpReporter
                    burp_reporter = BurpReporter()
                    path = asyncio.run(burp_reporter.generate(summary.to_dict() if hasattr(summary, 'to_dict') else {}, report_dir))
                    generated.append(f"Burp: {path}")
                    success(f"Burp report: {path}")
                except Exception as burp_exc:
                    warn(f"Burp export failed: {burp_exc}")

            info(f"Generated {len(generated)} report(s) in {report_dir}")

        except ValueError as exc:
            error(f"Invalid target: {exc}")
            raise typer.Exit(code=1) from exc
        except Exception as exc:
            error(f"Report generation failed: {exc}")
            raise typer.Exit(code=1) from exc

    @app.command()
    def diff(
        target: str = typer.Argument(..., help="Target domain to diff scans for"),
        output: Path = typer.Option(Path("results"), "-o", "--output"),
        scan_a: str = typer.Option("previous", "--from", "-a", help="Older scan ID or 'previous'"),
        scan_b: str = typer.Option("latest", "--to", "-b", help="Newer scan ID or 'latest'"),
        json_output: bool = typer.Option(False, "--json", help="Output diff as JSON"),
        timeline: bool = typer.Option(False, "--timeline", help="Generate visual timeline of changes"),
    ) -> None:
        """Compare two scans and show what changed."""
        from scoutx.reporting.diff import ScanDiffer, format_diff_text
        from scoutx.utils.io import write_json

        print_module_header("Scan Diff", target)

        scan_dir = output / target
        if not scan_dir.exists():
            error(f"No scan data found for {target} at {scan_dir}")
            raise typer.Exit(code=1)

        # For now we use the single scan dir as both A and B
        # (future: support multiple timestamped scan dirs)
        # The diff engine compares whatever is in the two directories
        scan_a_path = scan_dir
        scan_b_path = scan_dir

        # If user passed actual paths, use those
        if Path(scan_a).exists():
            scan_a_path = Path(scan_a)
        if Path(scan_b).exists():
            scan_b_path = Path(scan_b)

        if scan_a_path == scan_b_path:
            info("Same scan directory — showing self-diff (0 changes expected)")

        try:
            differ = ScanDiffer(scan_a_path, scan_b_path)
            result = differ.diff()

            if json_output:
                diff_file = scan_dir / "reports" / "diff.json"
                diff_file.parent.mkdir(parents=True, exist_ok=True)
                write_json(diff_file, result.to_dict())
                success(f"Diff JSON written to {diff_file}")
            else:
                text = format_diff_text(result)
                console.print(text)

            info(f"Total changes: {result.total_changes} ({result.change_velocity} velocity)")
            if result.has_critical_changes:
                warn("Critical changes detected! Review new secrets and open ports.")

            # Generate timeline if requested
            if timeline:
                try:
                    from scoutx.reporting.timeline import TimelineGenerator
                    tl_gen = TimelineGenerator(result.to_dict(), result.to_dict())
                    tl_md = tl_gen.generate_markdown()
                    tl_file = scan_dir / "reports" / "timeline.md"
                    tl_file.parent.mkdir(parents=True, exist_ok=True)
                    tl_file.write_text(tl_md, encoding="utf-8")
                    success(f"Timeline written to {tl_file}")
                except Exception as tl_exc:
                    warn(f"Timeline generation failed: {tl_exc}")

        except Exception as exc:
            error(f"Diff failed: {exc}")
            raise typer.Exit(code=1) from exc

