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
from app.models.score import RiskLevel


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

    # ── Helper Methods ───────────────────────────────────────────────────────────

    def _print_security_score(self, result: ScanResult) -> None:
        """Print security score with grade."""
        from app.models.score import Grade, RiskLevel
        from app.services.score_calculator import calculate_security_score

        score = calculate_security_score(result)

        # Color for score
        if score.grade == Grade.APLUS:
            color = "\033[92m"  # green
        elif score.grade in (Grade.A, Grade.BPLUS, Grade.B):
            color = "\033[93m"  # yellow
        elif score.grade == Grade.C:
            color = "\033[33m"  # orange/yellow
        else:
            color = "\033[91m"  # red

        print(f"  Security Score : {BOLD}{score.overall_score}/100{RESET} {color}[{score.grade.value}]{RESET}")
        print(f"  Risk Level      : {score.risk_level.value.upper()}")

        # Category breakdown
        print()
        categories = self._get_category_display_lines(score)
        for line in categories:
            print(f"  {line}")

    def _get_category_display_lines(self, score_obj) -> list[str]:
        """Get category score display lines."""
        from app.models.score import Category, Grade

        lines = []
        grade_colors = {
            Grade.APLUS: "\033[92m",  # green
            Grade.A: "\033[92m",
            Grade.BPLUS: "\033[93m",  # yellow
            Grade.B: "\033[93m",
            Grade.C: "\033[33m",  # orange
            Grade.D: "\033[91m",  # red
            Grade.F: "\033[91m",
        }

        for cat_score in score_obj.categories:
            if cat_score.findings_count == 0:
                continue

            cat_name = cat_score.category.value.upper()
            bar = self._make_bar(cat_score.score)
            color = grade_colors.get(cat_score.grade, "")

            lines.append(
                f"{cat_name:10} {bar} {cat_score.score}/100 {color}[{cat_score.letter_grade}]{RESET}"
            )

        return lines

    def _make_bar(self, score: int, width: int = 12) -> str:
        """Make a progress bar string."""
        filled = "█" * int(score / 100 * width)
        empty = "░" * (width - len(filled))
        return f"{filled}{empty}"

    # ── Console ───────────────────────────────────────────────────────────

    def print_console(self, result: ScanResult) -> None:
        """Print a coloured summary to stdout."""
        bar = "=" * 65
        print(f"\n{BOLD}{bar}{RESET}")
        print(f"{BOLD}  Laravel Security Scanner - Scan Report{RESET}")
        print(bar)
        print(f"  Target      : {result.target.url}")
        print(f"  Scanned at  : {result.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"  Duration    : {self._duration(result):.2f}s")

        # Security Score
        self._print_security_score(result)

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

        # Add security score to payload
        from app.services.score_calculator import calculate_security_score

        payload = result.model_dump(mode="json")
        payload["security_score"] = calculate_security_score(result).to_dict()

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
        """Save an HTML report using the modern template. Returns the output path."""
        from app.services.score_calculator import calculate_security_score
        from app.models.score import CategoryScore, RiskLevel

        out_dir = output_dir or settings.REPORT_OUTPUT_DIR
        out_dir.mkdir(parents=True, exist_ok=True)

        filename = f"scan_{self._slug(result.target.url)}_{self._ts()}.html"
        path = out_dir / filename

        score = calculate_security_score(result)
        template_path = Path(__file__).parent.parent / "templates" / "report_template.html"
        template = template_path.read_text(encoding="utf-8")

        severity_counts = {
            "critical": sum(1 for f in result.findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in result.findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in result.findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in result.findings if f.severity == Severity.LOW),
            "info": sum(1 for f in result.findings if f.severity == Severity.INFO),
        }

        score_color = self._get_score_color(score.overall_score)
        grade_lower = score.grade.value.lower().replace("+", "plus")
        score_offset = 534 - int(534 * score.overall_score / 100)

        def get_cat_color(cat_score: int) -> str:
            if cat_score >= 90:
                return "#16a34a"
            if cat_score >= 70:
                return "#3b82f6"
            if cat_score >= 50:
                return "#ca8a04"
            return "#dc2626"

        category_cards = ""
        cat_scores_dict = {cat.category: cat for cat in score.categories}
        for cat in ["config", "auth", "headers", "secrets", "database", "input"]:
            cat_enum = getattr(__import__("app.models.score", fromlist=["Category"]).Category, cat.upper())
            cat_score = cat_scores_dict.get(cat_enum)
            if cat_score and cat_score.findings_count > 0:
                card = f"""
                <div class="category-card">
                    <div class="category-header">
                        <span class="category-name">{cat}</span>
                        <span class="category-score" style="color: {get_cat_color(cat_score.score)}">{cat_score.score}</span>
                    </div>
                    <div class="category-progress">
                        <div class="category-progress-bar" style="width: {cat_score.score}%; background: {get_cat_color(cat_score.score)}"></div>
                    </div>
                    <div class="category-meta">{cat_score.findings_count} findings | {cat_score.grade.value}</div>
                </div>
                """
                category_cards += card

        findings_cards = ""
        for finding in result.findings:
            if finding.status.value == "safe":
                continue
            severity_class = finding.severity.value.lower()
            evidence_html = ""
            if finding.evidence:
                evidence_html = f"""
                <div class="finding-detail">
                    <div class="finding-detail-label">Evidence</div>
                    <div class="finding-detail-value">{escape(finding.evidence[:500])}</div>
                </div>
                """
            remediation_html = ""
            if finding.remediation:
                remediation_html = f"""
                <div class="finding-detail">
                    <div class="finding-detail-label">Remediation</div>
                    <div class="finding-detail-value">{escape(finding.remediation[:500])}</div>
                </div>
                """
            findings_cards += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="severity-badge severity-{severity_class}">{finding.severity.value}</span>
                    <span class="finding-title">{escape(finding.title)}</span>
                    <span class="finding-toggle">▼</span>
                </div>
                <div class="finding-body">
                    <div class="finding-detail">
                        <div class="finding-detail-label">Status</div>
                        <div class="finding-detail-value">{finding.status.value}</div>
                    </div>
                    <div class="finding-detail">
                        <div class="finding-detail-label">Description</div>
                        <div class="finding-detail-value">{escape(finding.description[:300])}</div>
                    </div>
                    {evidence_html}
                    {remediation_html}
                </div>
            </div>
            """

        category_scores = {cat.category.value: cat.score for cat in score.categories}
        recommendations = self._generate_recommendations(result, score, severity_counts)

        risk_summary = self._get_risk_summary(score.risk_level)
        primary_concerns = self._get_primary_concerns(result, severity_counts)

        severity_bg = "var(--critical-bg)" if score.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL) else (
            "var(--high-bg)" if score.risk_level == RiskLevel.MEDIUM_HIGH else "var(--safe-bg)"
        )
        severity_icon = "🚨" if score.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL) else (
            "⚠️" if score.risk_level == RiskLevel.MEDIUM_HIGH else "✅"
        )

        replacements = {
            "{target_url}": escape(result.target.url),
            "{score}": str(score.overall_score),
            "{score_color}": score_color,
            "{score_offset}": str(score_offset),
            "{grade}": score.grade.value,
            "{grade_lower}": grade_lower,
            "{scan_date}": result.started_at.strftime("%Y-%m-%d %H:%M:%S"),
            "{duration}": f"{self._duration(result):.2f}",
            "{checks_run}": str(len(result.findings)),
            "{total_findings}": str(len(result.vulnerable_findings)),
            "{critical_count}": str(severity_counts["critical"]),
            "{high_count}": str(severity_counts["high"]),
            "{medium_count}": str(severity_counts["medium"]),
            "{low_count}": str(severity_counts["low"]),
            "{info_count}": str(severity_counts["info"]),
            "{category_cards}": category_cards,
            "{severity_bg}": severity_bg,
            "{severity_icon}": severity_icon,
            "{risk_level}": score.risk_level.value.upper().replace("_", " "),
            "{risk_summary}": risk_summary,
            "{primary_concerns}": primary_concerns,
            "{recommendations}": recommendations,
            "{findings_count}": str(len(result.vulnerable_findings)),
            "{findings_cards}": findings_cards,
            "{generation_date}": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "{config_score}": str(category_scores.get("config", 100)),
            "{auth_score}": str(category_scores.get("auth", 100)),
            "{headers_score}": str(category_scores.get("headers", 100)),
            "{secrets_score}": str(category_scores.get("secrets", 100)),
            "{database_score}": str(category_scores.get("database", 100)),
            "{input_score}": str(category_scores.get("input", 100)),
        }

        html_content = template
        for placeholder, value in replacements.items():
            html_content = html_content.replace(placeholder, value)

        html_content = html_content.replace("{{", "{").replace("}}", "}")

        path.write_text(html_content, encoding="utf-8")
        logger.info(f"HTML report saved: {path}")
        return path

    def _get_score_color(self, score: int) -> str:
        """Get color for score."""
        if score >= 90:
            return "#16a34a"
        if score >= 70:
            return "#3b82f6"
        if score >= 50:
            return "#ca8a04"
        return "#dc2626"

    def _get_risk_summary(self, risk_level: RiskLevel) -> str:
        """Get risk summary text."""
        summaries = {
            RiskLevel.VERY_LOW: "No significant vulnerabilities detected. The application appears secure.",
            RiskLevel.LOW: "Minor issues found. Low risk of exploitation.",
            RiskLevel.MEDIUM_LOW: "Some security improvements recommended.",
            RiskLevel.MEDIUM: "Moderate vulnerabilities found. Consider addressing soon.",
            RiskLevel.MEDIUM_HIGH: "Significant vulnerabilities detected. Priority remediation recommended.",
            RiskLevel.HIGH: "Critical security issues detected. Immediate action required.",
            RiskLevel.CRITICAL: "Critical vulnerabilities detected. Emergency response needed.",
        }
        return summaries.get(risk_level, "Unable to assess risk level.")

    def _get_primary_concerns(self, result: ScanResult, severity_counts: dict) -> str:
        """Get primary concerns text."""
        if severity_counts["critical"] > 0:
            return f"{severity_counts['critical']} critical issue(s) require immediate attention."
        if severity_counts["high"] > 0:
            return f"{severity_counts['high']} high-severity issue(s) should be prioritized."
        if severity_counts["medium"] > 0:
            return f"{severity_counts['medium']} medium-severity issue(s) should be addressed."
        if severity_counts["low"] > 0:
            return f"{severity_counts['low']} low-severity issue(s) noted for future improvement."
        return "No vulnerabilities detected."

    def _generate_recommendations(self, result: ScanResult, score, severity_counts: dict) -> str:
        """Generate recommendations HTML."""
        recommendations = []

        if severity_counts["critical"] > 0:
            recommendations.append("""
            <div class="rec-item">
                <div class="rec-number">1</div>
                <div class="rec-content">
                    <h4>Address Critical Issues Immediately</h4>
                    <p>Critical vulnerabilities detected. Prioritize remediation to prevent exploitation.</p>
                </div>
            </div>
            """)

        if severity_counts["high"] > 0:
            recommendations.append("""
            <div class="rec-item">
                <div class="rec-number">2</div>
                <div class="rec-content">
                    <h4>Review High-Severity Findings</h4>
                    <p>Review and remediate high-severity security issues in the detailed findings section.</p>
                </div>
            </div>
            """)

        if score.overall_score < 80:
            recommendations.append("""
            <div class="rec-item">
                <div class="rec-number">3</div>
                <div class="rec-content">
                    <h4>Implement Security Headers</h4>
                    <p>Add missing security headers (CSP, HSTS, X-Frame-Options) to protect against common attacks.</p>
                </div>
            </div>
            """)

        if score.overall_score < 70:
            recommendations.append("""
            <div class="rec-item">
                <div class="rec-number">4</div>
                <div class="rec-content">
                    <h4>Enable Debug = false in Production</h4>
                    <p>Ensure APP_DEBUG is set to false in production environments to prevent information disclosure.</p>
                </div>
            </div>
            """)

        if not recommendations:
            recommendations.append("""
            <div class="rec-item">
                <div class="rec-number">1</div>
                <div class="rec-content">
                    <h4>Maintain Security Posture</h4>
                    <p>Continue following security best practices and run regular scans.</p>
                </div>
            </div>
            """)

        return "\n".join(recommendations)

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
