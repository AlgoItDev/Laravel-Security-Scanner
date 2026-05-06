"""
Check: .env file publicly accessible.

Attempts to fetch /.env and common variants.
Severity: CRITICAL — exposed .env leaks DB creds, APP_KEY, mail secrets, etc.
"""
from __future__ import annotations

import httpx
from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


ENV_PATHS = [".env", ".env.backup", ".env.example", ".env.production", ".env.local"]

# Tokens that suggest a real Laravel .env (not a 404 page)
ENV_SIGNATURES = [
    "APP_KEY=",
    "APP_ENV=",
    "DB_PASSWORD=",
    "DB_HOST=",
    "MAIL_PASSWORD=",
    "APP_DEBUG=",
]


class EnvExposedCheck(BaseCheck):
    CHECK_ID = "ENV_EXPOSED"
    TITLE = ".env File Publicly Accessible"

    async def run(self, target: ScanTarget) -> Finding:
        """
        Probe known .env paths. If any returns 200 with Laravel env signatures,
        classify as CRITICAL VULNERABLE.
        """
        exposed_paths: list[str] = []
        evidence_snippets: list[str] = []

        for path in ENV_PATHS:
            url = self._build_url(target.url, path)
            try:
                resp = await self._client.get(
                    url,
                    headers=target.headers,
                    follow_redirects=False,
                )
                logger.debug(f"[{self.CHECK_ID}] {url} → HTTP {resp.status_code}")

                if resp.status_code == 200:
                    body = resp.text
                    if any(sig in body for sig in ENV_SIGNATURES):
                        exposed_paths.append(path)
                        # Redact sensitive values for evidence
                        snippet = self._redact(body[:400])
                        evidence_snippets.append(f"[{path}] {snippet}")

            except httpx.TimeoutException:
                logger.warning(f"[{self.CHECK_ID}] Timeout for {url}")
            except httpx.RequestError as exc:
                logger.warning(f"[{self.CHECK_ID}] Request error for {url}: {exc}")

        if exposed_paths:
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.CRITICAL,
                status=CheckStatus.VULNERABLE,
                description=(
                    f"The following .env files are publicly accessible: "
                    f"{', '.join(exposed_paths)}. "
                    "These files contain sensitive credentials and configuration secrets."
                ),
                evidence="\n---\n".join(evidence_snippets),
                remediation=(
                    "1. Immediately rotate all credentials in the exposed .env files.\n"
                    "2. Configure your web server to deny access to dot-files.\n"
                    "   Nginx: add `location ~ /\\.env { deny all; }` to your server block.\n"
                    "   Apache: add `<FilesMatch \"^\\.env\"> Deny from all </FilesMatch>`.\n"
                    "3. Ensure .env is listed in .gitignore."
                ),
                cvss_score=9.8,
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/",
                    "https://laravel.com/docs/deployment#server-configuration",
                ],
            )

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=Severity.CRITICAL,
            status=CheckStatus.SAFE,
            description=".env files are not publicly accessible.",
        )

    @staticmethod
    def _redact(text: str) -> str:
        """Redact values from KEY=VALUE pairs to avoid leaking secrets in reports."""
        import re
        return re.sub(r"(=)([^\n]{1,})", r"\1[REDACTED]", text)
