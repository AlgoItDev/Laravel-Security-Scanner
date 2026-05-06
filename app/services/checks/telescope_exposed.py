"""
Check: Laravel Telescope exposure.

Laravel Telescope is a debugging assistant that should not be accessible in production.
If exposed, it can leak sensitive information including requests, exceptions, logs, etc.
Severity: HIGH
"""
from __future__ import annotations

import httpx
from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


class TelescopeExposedCheck(BaseCheck):
    CHECK_ID = "TELESCOPE_EXPOSED"
    TITLE = "Laravel Telescope Exposed"

    # Common Telescope endpoints
    TELESCOPE_PATHS = [
        "/telescope",
        "/telescope/requests",
        "/telescope/exceptions",
        "/telescope/logs",
        "/_debugbar/telescope",  # Alternative path
    ]

    async def run(self, target: ScanTarget) -> Finding:
        """
        Check if Laravel Telescope is accessible.
        """
        exposed_paths = []

        for path in self.TELESCOPE_PATHS:
            url = self._build_url(target.url, path)
            try:
                resp = await self._client.get(
                    url,
                    headers=target.headers,
                    follow_redirects=True,
                )
                logger.debug(f"[{self.CHECK_ID}] {url} → HTTP {resp.status_code}")

                if resp.status_code == 200:
                    # Check if response looks like Telescope
                    body = resp.text.lower()
                    telescope_indicators = [
                        "telescope",
                        "laravel telescope",
                        "request-path",
                        "request-method",
                        "response-status",
                    ]
                    # Count how many indicators are present
                    matches = sum(1 for indicator in telescope_indicators if indicator in body)
                    if matches >= 2:  # At least 2 indicators to reduce false positives
                        exposed_paths.append(path)

            except httpx.TimeoutException:
                logger.warning(f"[{self.CHECK_ID}] Timeout for {url}")
            except httpx.RequestError as exc:
                logger.warning(f"[{self.CHECK_ID}] Request error for {url}: {exc}")

        if exposed_paths:
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.HIGH,
                status=CheckStatus.VULNERABLE,
                description=(
                    f"Laravel Telescope is accessible at: {', '.join(exposed_paths)}. "
                    "Telescope should not be accessible in production environments."
                ),
                evidence=f"Exposed paths: {', '.join(exposed_paths)}",
                remediation=(
                    "1. Remove Telescope package from production: "
                    "`composer remove laravel/telescope --dev`\n"
                    "2. Or ensure Telescope is only enabled in non-production environments:\n"
                    "   In `app/Providers/TelescopeServiceProvider.php`, wrap in environment check:\n"
                    "   `if ($this->app->environment('local')) { $this->register(); }`\n"
                    "3. Configure web server to deny access to /telescope path.\n"
                    "4. Use `Telescope::night()` or `Telescope::ignoreMigrations()` as needed."
                ),
                cvss_score=7.5,
                references=[
                    "https://laravel.com/docs/telescope",
                    "https://github.com/laravel/telescope",
                ],
            )

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=Severity.HIGH,
            status=CheckStatus.SAFE,
            description="Laravel Telescope is not accessible.",
        )
