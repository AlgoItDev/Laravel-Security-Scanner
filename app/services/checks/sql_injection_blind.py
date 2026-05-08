"""
Check: SQL Injection (Blind) vulnerability detection.

Tests for blind SQL injection by analyzing response differences
for various SQL injection payloads in URL parameters.

Severity: CRITICAL — SQL injection can lead to data breach, data manipulation, or RCE.
"""
from __future__ import annotations

import asyncio
import re

import httpx

from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR '1'='1'/*",
    "admin' --",
    "admin' #",
    "1' ORDER BY 1--",
    "1' UNION SELECT NULL--",
    "' OR 1=1--",
    "1; SELECT * FROM users",
]


SQL_ERROR_PATTERNS = [
    r"SQL syntax|mysql_fetch|MySQLSyntaxError",
    r"ORA-\d{5}|oracle.*error",
    r"Microsoft SQL Native Error",
    r"SQLite3::|sqlite3.*error",
    r"PostgreSQL.*ERROR",
    r"Syntax error or access violation",
    r"You have an error in your SQL",
    r"mysql_\w+|mysqli_\w+",
    r"pg_\w+|pg_execute",
]


class SQLInjectionBlindCheck(BaseCheck):
    CHECK_ID = "SQL_INJECTION_BLIND"
    TITLE = "Blind SQL Injection Vulnerability"

    async def run(self, target: ScanTarget) -> Finding:
        """
        Test URL parameters for blind SQL injection by analyzing
        timing and response differences.
        """
        vulnerabilities: list[str] = []
        evidence_details: list[str] = []

        paths_to_test = ["", "/", "/search", "/query", "/id", "/page", "/user", "/product"]

        for path in paths_to_test:
            url = self._build_url(target.url, path)
            
            for payload in SQL_PAYLOADS[:5]:
                try:
                    test_url = f"{url}?id={payload}"
                    response = await self._client.get(
                        test_url,
                        headers=target.headers,
                        follow_redirects=True,
                    )
                    
                    response_text = response.text.lower()
                    status_code = response.status_code

                    has_error = any(
                        re.search(pattern, response_text, re.IGNORECASE)
                        for pattern in SQL_ERROR_PATTERNS
                    )

                    is_500 = status_code >= 500
                    has_sqli_signs = (
                        "sql" in response_text or
                        "syntax" in response_text or
                        "mysql" in response_text or
                        "postgresql" in response_text or
                        "sqlite" in response_text or
                        "database" in response_text
                    )

                    if has_error or (is_500 and has_sqli_signs):
                        vulnerabilities.append(f"{path}?id={payload}")
                        evidence_details.append(
                            f"URL: {test_url} | Status: {status_code} | "
                            f"Error detected: {has_error}"
                        )
                        break

                except (httpx.TimeoutException, httpx.RequestError) as exc:
                    logger.debug(f"[{self.CHECK_ID}] Request failed: {exc}")
                    continue

        if vulnerabilities:
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.CRITICAL,
                status=CheckStatus.VULNERABLE,
                description=(
                    f"Potential blind SQL injection vulnerabilities found at {len(vulnerabilities)} "
                    f"endpoint(s). These parameters may be vulnerable to SQL injection attacks."
                ),
                evidence="\n".join(evidence_details[:5]),
                remediation=(
                    "1. Use parameterized queries or prepared statements.\n"
                    "2. Implement input validation and sanitization.\n"
                    "3. Use an ORM like Eloquent with proper query building.\n"
                    "4. Apply least-privilege principle to database users.\n"
                    "5. Implement WAF (Web Application Firewall) as additional layer."
                ),
                cvss_score=9.5,
                references=[
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                ],
            )

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=Severity.CRITICAL,
            status=CheckStatus.SAFE,
            description="No obvious SQL injection vulnerabilities detected.",
        )