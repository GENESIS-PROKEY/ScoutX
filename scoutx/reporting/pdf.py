"""PDF report generator — converts HTML report to PDF.

Tries WeasyPrint first (best quality), falls back to Playwright's
print-to-PDF, and degrades gracefully if neither is available.
"""
from __future__ import annotations

import logging
from pathlib import Path

from scoutx.reporting.aggregator import ScanSummary

logger = logging.getLogger("scoutx.reporting.pdf")


class PdfReporter:
    """Generate a PDF report from scan data.

    Strategy:
        1. Generate HTML report first (we already have that engine)
        2. Convert HTML -> PDF via WeasyPrint or Playwright
        3. If neither is available, skip with a warning
    """

    def __init__(self, summary: ScanSummary) -> None:
        self._summary = summary

    async def generate(self, output_path: Path) -> Path | None:
        """Render and write the PDF report.

        Returns the output path on success, None if PDF generation
        is unavailable.
        """
        # Step 1: Generate the HTML report to a temp location
        from scoutx.reporting.html import HtmlReporter

        html_path = output_path.parent / "report_temp.html"
        reporter = HtmlReporter(self._summary)
        reporter.generate(html_path)

        # Step 2: Try conversion backends
        pdf_path = output_path

        # Backend 1: WeasyPrint (best quality, pure Python)
        result = self._try_weasyprint(html_path, pdf_path)
        if result:
            self._cleanup_temp(html_path)
            return result

        # Backend 2: Playwright (headless Chrome print-to-PDF)
        result = await self._try_playwright(html_path, pdf_path)
        if result:
            self._cleanup_temp(html_path)
            return result

        # Neither backend available
        logger.warning(
            "PDF generation unavailable. Install either:\n"
            "  pip install weasyprint   (recommended)\n"
            "  pip install playwright && playwright install chromium"
        )
        self._cleanup_temp(html_path)
        return None

    def _try_weasyprint(self, html_path: Path, pdf_path: Path) -> Path | None:
        """Attempt PDF generation via WeasyPrint."""
        try:
            import weasyprint  # type: ignore[import-untyped]

            pdf_path.parent.mkdir(parents=True, exist_ok=True)
            doc = weasyprint.HTML(filename=str(html_path))
            doc.write_pdf(str(pdf_path))
            logger.info("PDF report written via WeasyPrint to %s", pdf_path)
            return pdf_path
        except ImportError:
            logger.debug("WeasyPrint not installed, trying next backend")
            return None
        except Exception as exc:
            logger.warning("WeasyPrint failed: %s", exc)
            return None

    async def _try_playwright(self, html_path: Path, pdf_path: Path) -> Path | None:
        """Attempt PDF generation via Playwright's print-to-PDF."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.debug("Playwright not installed, no PDF backends available")
            return None

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                page = await browser.new_page()

                # Load the HTML file
                file_url = html_path.resolve().as_uri()
                await page.goto(file_url, wait_until="networkidle")

                # Print to PDF
                pdf_path.parent.mkdir(parents=True, exist_ok=True)
                await page.pdf(
                    path=str(pdf_path),
                    format="A4",
                    print_background=True,
                    margin={
                        "top": "1cm",
                        "bottom": "1cm",
                        "left": "1cm",
                        "right": "1cm",
                    },
                )

                await browser.close()
                logger.info("PDF report written via Playwright to %s", pdf_path)
                return pdf_path

        except Exception as exc:
            logger.warning("Playwright PDF generation failed: %s", exc)
            return None

    def _cleanup_temp(self, html_path: Path) -> None:
        """Remove temporary HTML file."""
        try:
            if html_path.exists() and html_path.name == "report_temp.html":
                html_path.unlink()
        except Exception:
            pass
