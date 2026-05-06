"""
ReportService — generates human-readable and machine-readable reports.

Supported formats:
  - console  (coloured terminal summary)
  - json     (full structured output)
  - txt      (plain text for archiving)
  - html     (interactive HTML report)
  - sarif    (SARIF format for GitHub Security tab)
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from html import escape

from app.core.logging import logger
from app.core.settings import settings
from app.models.scan import CheckStatus, ScanResult, Severity


# Severity → terminal colour codes
SEVERITY_COLOUR = {
    Severity.CRITICAL: "\033[91m",   # bright red
    Severity.HIGH:     "\033[31m",   # red
    Severity.MEDIUM:   "\033[33m",   # yellow
    Severity.LOW:      "\033[34m",   # blue
    Severity.INFO:     "\033[37m",   # grey
}
RESET = "\033[0m"
BOLD  = "\033[1m"


class ReportService:
    """Generates reports from ScanResult objects."""

    # ── Console ───────────────────────────────────────────────────────────

    def print_console(self, result: ScanResult) -> None:
        """Print a coloured summary to stdout."""
        bar = "=" * 65
        print(f"\n{BOLD}{bar}{RESET}")
        print(f"{BOLD}  Laravel Security Scanner - Scan Report{RESET}")
        print(bar)
        print(f"  Target     : {result.target.url}")
        print(f"  Scanned at : {result.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"  Duration   : {self._duration(result):.2f}s")
        print(f"  Risk Score : {BOLD}{result.risk_score} / 10{RESET}")
        print(bar)

        if result.error:
            print(f"\n  [!]  Scan error: {result.error}\n")
            return

        for finding in result.findings:
            colour = SEVERITY_COLOUR.get(finding.severity, "")
            status_icon = "[OK]" if finding.status == CheckStatus.SAFE else (
                "[!!]" if finding.severity in (Severity.CRITICAL, Severity.HIGH) else
                "[!]" if finding.severity == Severity.MEDIUM else
                "[~]" if finding.severity == Severity.LOW else "[i]"
            )

            print(f"\n{colour}{BOLD}[{finding.severity.value}] {finding.title}{RESET} {status_icon}")
            print(f"  Status: {finding.status.value}")
            print(f"  {finding.description}")

            if finding.evidence and finding.status != CheckStatus.SAFE:
                print(f"\n  Evidence:")
                for line in finding.evidence.splitlines():
                    # Remove or replace problematic Unicode characters
                    clean_line = line.encode('ascii', 'replace').decode('ascii')
                    print(f"    {clean_line}")

            if finding.remediation and finding.status != CheckStatus.SAFE:
                print(f"\n  Remediation:")
                for line in finding.remediation.splitlines():
                    # Remove or replace problematic Unicode characters
                    clean_line = line.encode('ascii', 'replace').decode('ascii')
                    print(f"    {clean_line}")

        print(f"\n{bar}")
        print(
            f"  Summary: "
            f"{BOLD}{len(result.vulnerable_findings)}{RESET} vulnerable | "
            f"CRITICAL: {SEVERITY_COLOUR[Severity.CRITICAL]}{result.critical_count}{RESET} | "
            f"HIGH: {SEVERITY_COLOUR[Severity.HIGH]}{result.high_count}{RESET}"
        )
        print(f"{bar}\n")

    # ── JSON ──────────────────────────────────────────────────────────────

    def save_json(self, result: ScanResult, output_dir: Path | None = None) -> Path:
        """Serialise result to a JSON file. Returns the output path."""
        out_dir = output_dir or settings.REPORT_OUTPUT_DIR
        out_dir.mkdir(parents=True, exist_ok=True)

        filename = f"scan_{self._slug(result.target.url)}_{self._ts()}.json"
        path = out_dir / filename

        payload = result.model_dump(mode="json")
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

        logger.info(f"JSON report saved: {path}")
        return path

    # ── Plain text ────────────────────────────────────────────────────────

    def save_txt(self, result: ScanResult, output_dir: Path | None = None) -> Path:
        """Save a plain-text report. Returns the output path."""
        out_dir = output_dir or settings.REPORT_OUTPUT_DIR
        out_dir.mkdir(parents=True, exist_ok=True)

        filename = f"scan_{self._slug(result.target.url)}_{self._ts()}.txt"
        path = out_dir / filename

        lines: list[str] = [
            "Laravel Security Scanner — Scan Report",
            "=" * 65,
            f"Target     : {result.target.url}",
            f"Scanned at : {result.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Risk Score : {result.risk_score} / 10",
            "=" * 65,
        ]

        for finding in result.findings:
            lines += [
                "",
                f"[{finding.severity.value}] {finding.title}",
                f"Status: {finding.status.value}",
                finding.description,
            ]
            if finding.evidence:
                lines += ["Evidence:", finding.evidence]
            if finding.remediation:
                lines += ["Remediation:", finding.remediation]

        path.write_text("\n".join(lines), encoding="utf-8")
        logger.info(f"TXT report saved: {path}")
        return path

    # ── HTML ─────────────────────────────────────────────────────────────

    def save_html(self, result: ScanResult, output_dir: Path | None = None) -> Path:
        """Save an HTML report. Returns the output path."""
        out_dir = output_dir or settings.REPORT_OUTPUT_DIR
        out_dir.mkdir(parents=True, exist_ok=True)

        filename = f"scan_{self._slug(result.target.url)}_{self._ts()}.html"
        path = out_dir / filename

        # Severity color mapping
        severity_colors = {
            Severity.CRITICAL: "#ff0000",
            Severity.HIGH: "#ff4444",
            Severity.MEDIUM: "#ffaa00",
            Severity.LOW: "#4444ff",
            Severity.INFO: "#888888",
        }

        # Build findings HTML
        findings_html = ""
        for finding in result.findings:
            color = severity_colors.get(finding.severity, "#000000")
            status_text = finding.status.value
            status_class = "safe" if finding.status == CheckStatus.SAFE else "vulnerable"
            
            findings_html += f"""
            <div class="finding {status_class}">
                <h3 style="color: {color};">
                    [{finding.severity.value}] {escape(finding.title)}
                    <span class="status">{status_text}</span>
                </h3>
                <p>{escape(finding.description)}</p>
            """
            
            if finding.evidence and finding.status != CheckStatus.SAFE:
                findings_html += f"""
                <div class="evidence">
                    <h4>Evidence:</h4>
                    <pre>{escape(finding.evidence)}</pre>
                </div>
                """
            
            if finding.remediation and finding.status != CheckStatus.SAFE:
                findings_html += f"""
                <div class="remediation">
                    <h4>Remediation:</h4>
                    <pre>{escape(finding.remediation)}</pre>
                </div>
                """
            
            findings_html += "</div>\n"

        # Build complete HTML
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Laravel Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; }}
        h3 {{ margin-bottom: 5px; }}
        .finding {{ margin: 20px 0; padding: 15px; border-left: 4px solid #ccc; background: #fafafa; }}
        .finding.vulnerable {{ border-left-color: #ff4444; }}
        .finding.safe {{ border-left-color: #44ff44; }}
        .status {{ font-size: 0.8em; padding: 2px 8px; border-radius: 3px; background: #eee; }}
        .evidence, .remediation {{ margin: 10px 0; padding: 10px; background: #f0f0f0; border-radius: 3px; }}
        h4 {{ margin: 5px 0; color: #666; }}
        pre {{ white-space: pre-wrap; word-wrap: break-word; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .summary-box {{ flex: 1; padding: 15px; background: #f0f0f0; border-radius: 5px; text-align: center; }}
        .summary-box h2 {{ margin: 0; font-size: 2em; }}
        .risk-score {{ font-size: 3em; color: {'#ff4444' if result.risk_score > 7 else '#ffaa00' if result.risk_score > 4 else '#44aa44'}; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Laravel Security Scanner - Scan Report</h1>
        <div class="summary">
            <div class="summary-box">
                <h2>{len(result.vulnerable_findings)}</h2>
                <p>Vulnerabilities</p>
            </div>
            <div class="summary-box">
                <h2 class="risk-score">{result.risk_score}</h2>
                <p>Risk Score (0-10)</p>
            </div>
            <div class="summary-box">
                <h2>{result.critical_count}</h2>
                <p>Critical</p>
            </div>
            <div class="summary-box">
                <h2>{result.high_count}</h2>
                <p>High</p>
            </div>
        </div>
        
        <p><strong>Target:</strong> {escape(result.target.url)}</p>
        <p><strong>Scanned at:</strong> {result.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        <p><strong>Duration:</strong> {self._duration(result):.2f}s</p>
        
        <h2>Findings</h2>
        {findings_html}
    </div>
</body>
</html>
"""

        path.write_text(html_content, encoding="utf-8")
        logger.info(f"HTML report saved: {path}")
        return path

    # ── SARIF ─────────────────────────────────────────────────────

    def save_sarif(self, result: ScanResult, output_dir: Path | None = None) -> Path:
        """Save a SARIF report for GitHub Security tab integration. Returns the output path."""
        out_dir = output_dir or settings.REPORT_OUTPUT_DIR
        out_dir.mkdir(parents=True, exist_ok=True)

        filename = f"scan_{self._slug(result.target.url)}_{self._ts()}.sarif.json"
        path = out_dir / filename

        # Map severity to SARIF level
        def _severity_to_level(sev: Severity) -> str:
            if sev in (Severity.CRITICAL, Severity.HIGH):
                return "error"
            elif sev == Severity.MEDIUM:
                return "warning"
            else:
                return "note"

        # Build SARIF results
        sarif_results = []
        for finding in result.findings:
            # Only include vulnerable findings
            if finding.status != CheckStatus.VULNERABLE:
                continue

            # Create a result entry
            sarif_result = {
                "ruleId": finding.check_id,
                "level": _severity_to_level(finding.severity),
                "message": {
                    "text": finding.description or finding.title
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": result.target.url
                            }
                        }
                    }
                ],
                "properties": {
                    "severity": finding.severity.value,
                    "status": finding.status.value,
                }
            }

            # Add remediation if available
            if finding.remediation:
                sarif_result["fixes"] = [
                    {
                        "description": {
                            "text": finding.remediation
                        }
                    }
                ]

            # Add evidence if available
            if finding.evidence:
                sarif_result["properties"]["evidence"] = finding.evidence

            sarif_results.append(sarif_result)

        # Build complete SARIF structure
        sarif_content = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": settings.APP_NAME,
                            "version": settings.APP_VERSION,
                            "properties": {
                                "risk_score": result.risk_score,
                                "critical_count": result.critical_count,
                                "high_count": result.high_count,
                            }
                        }
                    },
                    "results": sarif_results
                }
            ]
        }

        path.write_text(json.dumps(sarif_content, indent=2), encoding="utf-8")
        logger.info(f"SARIF report saved: {path}")
        return path

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _ts() -> str:
        return datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    @staticmethod
    def _slug(url: str) -> str:
        import re
        return re.sub(r"[^\w]", "_", url)[:40].strip("_")

    @staticmethod
    def _duration(result: ScanResult) -> float:
        if result.finished_at:
            return (result.finished_at - result.started_at).total_seconds()
        return 0.0
