"""
Check: Laravel Horizon exposure.

Laravel Horizon is a queue dashboard that should not be accessible in production.
If exposed, it can reveal queue jobs, metrics, and other sensitive information.
Severity: MEDIUM
"""
from __future__ import annotations

import httpx
from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


class HorizonExposedCheck(BaseCheck):
    CHECK_ID = "HORIZON_EXPOSED"
    TITLE = "Laravel Horizon Exposed"

    # Common Horizon endpoints
    HORIZON_PATHS = [
        "/horizon",
        "/horizon/dashboard",
        "/horizon/api/metrics",
        "/horizon/api/jobs",
    ]

    async def run(self, target: ScanTarget) -> Finding:
        """
        Check if Laravel Horizon is accessible.
        """
        exposed_paths = []

        for path in self.HORIZON_PATHS:
            url = self._build_url(target.url, path)
            try:
                resp = await self._client.get(
                    url,
                    headers=target.headers,
                    follow_redirects=True,
                )
                logger.debug(f"[{self.CHECK_ID}] {url} → HTTP {resp.status_code}")

                if resp.status_code == 200:
                    # Check if response looks like Horizon
                    body = resp.text.lower()
                    horizon_indicators = [
                        "horizon",
                        "laravel horizon",
                        "queue",
                        "metrics",
                        "jobs",
                        "failed-jobs",
                    ]
                    # Count indicators
                    matches = sum(1 for indicator in horizon_indicators if indicator in body)
                    if matches >= 2:  # At least 2 indicators
                        exposed_paths.append(path)

            except httpx.TimeoutException:
                logger.warning(f"[{self.CHECK_ID}] Timeout for {url}")
            except httpx.RequestError as exc:
                logger.warning(f"[{self.CHECK_ID}] Request error for {url}: {exc}")

        if exposed_paths:
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.MEDIUM,
                status=CheckStatus.VULNERABLE,
                description=(
                    f"Laravel Horizon appears to be accessible at: {', '.join(exposed_paths)}. "
                    "Horizon should not be accessible in production environments."
                ),
                evidence=f"Exposed paths: {', '.join(exposed_paths)}",
                remediation=(
                    "1. Remove Horizon package from production: "
                    "`composer remove laravel/horizon`\n"
                    "2. Or ensure Horizon is only enabled in non-production environments:\n"
                    "   In `app/Providers/HorizonServiceProvider.php`, wrap in environment check:\n"
                    "   `if ($this->app->environment('local', 'staging')) { $this->register(); }`\n"
                    "3. Configure web server to deny access to /horizon path.\n"
                    "4. Use Horizon's built-in authentication: "
                    "`Horizon::auth(function ($request) { return $request->user() && $request->user()->isAdmin(); });`"
                ),
                cvss_score=5.3,
                references=[
                    "https://laravel.com/docs/horizon",
                    "https://github.com/laravel/horizon",
                ],
            )

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=Severity.MEDIUM,
            status=CheckStatus.SAFE,
            description="Laravel Horizon does not appear to be exposed.",
        )
