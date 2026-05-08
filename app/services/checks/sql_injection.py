"""
Check: SQL Injection (Hybrid Static + Dynamic).

Combines static code analysis with dynamic probing for accurate
vulnerability detection with reduced false positives.

Severity: CRITICAL — SQL injection can lead to data breach, data manipulation, or RCE.
"""
from __future__ import annotations

import re

import httpx

from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck
from app.services.source_fetcher import SourceFetcher
from app.services.static_analyzer import (
    RiskLevel,
    StaticCodeAnalyzer,
    StaticFinding,
    VulnerabilityType,
)


SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR '1'='1'/*",
    "admin' --",
    "1' ORDER BY 1--",
    "1' UNION SELECT NULL--",
]

SQL_ERROR_PATTERNS = [
    r"SQL syntax|mysql_fetch|MySQLSyntaxError",
    r"ORA-\d{5}|oracle.*error",
    r"Microsoft SQL Native Error",
    r"SQLite3::|sqlite3.*error",
    r"PostgreSQL.*ERROR",
    r"Syntax error or access violation",
    r"You have an error in your SQL",
    r"mysqli?_\w+",
    r"pg_\w+|pg_execute",
]

CONFIDENT_THRESHOLD = 0.6


class SQLInjectionCheck(BaseCheck):
    CHECK_ID = "SQL_INJECTION"
    TITLE = "SQL Injection Vulnerability (Hybrid)"

    async def run(self, target: ScanTarget) -> Finding:
        static_findings = await self._analyze_source(target)
        dynamic_findings = await self._probe_sqli(target)

        combined = self._combine_results(static_findings, dynamic_findings)

        if combined["confidence"] >= CONFIDENT_THRESHOLD:
            return self._create_finding(combined, static_findings, dynamic_findings)

        if dynamic_findings["vulnerable"]:
            return self._create_finding(dynamic_findings, static_findings, dynamic_findings)

        if static_findings["findings"]:
            medium_conf = self._calculate_static_confidence(static_findings["findings"])
            if medium_conf >= 0.5:
                return self._create_finding(
                    {"confidence": medium_conf, **static_findings},
                    static_findings,
                    dynamic_findings,
                )

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=Severity.MEDIUM,
            status=CheckStatus.SAFE,
            description="No SQL injection vulnerabilities detected (hybrid analysis).",
        )

    async def _analyze_source(self, target: ScanTarget) -> dict:
        """Static code analysis."""
        try:
            fetcher = SourceFetcher(self._client)
            source_files = await fetcher.fetch_all(target.url)

            if not source_files:
                logger.debug(f"[{self.CHECK_ID}] No source files fetched")
                return {"findings": [], "has_source": False}

            analyzer = StaticAnalyzer()
            all_findings = analyzer.analyze(source_files)

            sql_findings = analyzer.filter_by_type(
                all_findings, VulnerabilityType.SQL_INJECTION
            )
            high_risk = analyzer.get_high_risk_only(sql_findings)

            logger.debug(
                f"[{self.CHECK_ID}] Static: {len(high_risk)} high-risk SQL findings"
            )

            return {"findings": sql_findings, "high_risk": high_risk, "has_source": True}

        except Exception as e:
            logger.warning(f"[{self.CHECK_ID}] Static analysis failed: {e}")
            return {"findings": [], "has_source": False}

    async def _probe_sqli(self, target: ScanTarget) -> dict:
        """Dynamic SQL injection probing."""
        vulnerabilities = []
        evidence_details = []

        paths_to_test = ["", "/search", "/query", "/user", "/id", "/product"]

        for path in paths_to_test:
            url = self._build_url(target.url, path)

            for payload in SQL_PAYLOADS[:4]:
                try:
                    test_url = f"{url}?id={payload}"
                    response = await self._client.get(
                        test_url,
                        headers=target.headers,
                        follow_redirects=True,
                    )

                    if self._is_sqli_response(
                        response.text, response.status_code, payload
                    ):
                        vulnerabilities.append(f"{path}?id={payload[:20]}")
                        evidence_details.append(
                            f"URL: {test_url[:80]} | Status: {response.status_code}"
                        )
                        break

                except (httpx.TimeoutException, httpx.RequestError):
                    continue

        is_vulnerable = len(vulnerabilities) > 0
        confidence = 0.8 if is_vulnerable else 0.0

        return {
            "vulnerable": is_vulnerable,
            "vulnerabilities": vulnerabilities,
            "evidence": evidence_details,
            "confidence": confidence,
        }

    def _is_sqli_response(
        self, response_text: str, status_code: int, payload: str
    ) -> bool:
        """Check if response indicates SQL injection vulnerability."""
        text_lower = response_text.lower()

        has_error = any(
            re.search(pattern, text_lower, re.IGNORECASE)
            for pattern in SQL_ERROR_PATTERNS
        )

        if has_error:
            return True

        is_500 = status_code >= 500
        has_sql_signs = any(
            keyword in text_lower
            for keyword in ["sql", "syntax", "mysql", "postgresql", "database"]
        )

        return is_500 and has_sql_signs

    def _combine_results(
        self, static: dict, dynamic: dict
    ) -> dict:
        """Combine static and dynamic findings."""
        if not static.get("has_source"):
            return dynamic

        if static.get("findings") and dynamic.get("vulnerable"):
            combined_confidence = min(
                static.get("confidence", 0.5) + dynamic.get("confidence", 0.5) + 0.1,
                1.0,
            )

            return {
                "confidence": combined_confidence,
                "vulnerable": True,
                "source": "both",
                "static_findings": static.get("findings", []),
                "dynamic_vulns": dynamic.get("vulnerabilities", []),
            }

        if static.get("findings") and not dynamic.get("vulnerable"):
            static_conf = self._calculate_static_confidence(
                static.get("findings", [])
            )

            return {
                "confidence": static_conf,
                "vulnerable": static_conf >= 0.7,
                "source": "static",
                "static_findings": static.get("findings", []),
            }

        return dynamic

    def _calculate_static_confidence(
        self, findings: list[StaticFinding]
    ) -> float:
        """Calculate confidence from static findings."""
        if not findings:
            return 0.0

        max_confidence = max(f.confidence for f in findings)
        high_risk_count = sum(
            1 for f in findings if f.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        )

        if high_risk_count > 0:
            return min(max_confidence + 0.1, 1.0)

        return max_confidence * 0.7

    def _create_finding(
        self, combined: dict, static: dict, dynamic: dict
    ) -> Finding:
        """Create Finding object from results."""
        evidence_parts = []

        if static.get("findings"):
            for f in static.get("findings", [])[:3]:
                evidence_parts.append(
                    f"STATIC: {f.file_path}:{f.line_number} - {f.reason}"
                )

        if dynamic.get("vulnerabilities"):
            for v in dynamic.get("vulnerabilities", [])[:3]:
                evidence_parts.append(f"DYNAMIC: {v}")

        confidence = combined.get("confidence", 0.5)

        if confidence >= 0.8:
            severity = Severity.CRITICAL
        elif confidence >= 0.6:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=severity,
            status=CheckStatus.VULNERABLE,
            description=(
                f"SQL injection vulnerability detected (confidence: {confidence:.0%}). "
                f"Static analysis: {len(static.get('findings', []))} findings. "
                f"Dynamic probing: {len(dynamic.get('vulnerabilities', []))} tests failed."
            ),
            evidence="\n".join(evidence_parts[:8]),
            remediation=(
                "1. Use parameterized queries or prepared statements.\n"
                "2. Use Laravel's Eloquent ORM or Query Builder with bindings.\n"
                "3. Validate and sanitize all user input.\n"
                "4. Implement least-privilege database users.\n"
                "5. Use WAF as additional Layer."
            ),
            cvss_score=9.5 if confidence >= 0.8 else (7.5 if confidence >= 0.6 else 5.0),
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            ],
        )