"""
Check: Laravel Nova exposure.

Laravel Nova is an administration panel that should not be accessible in production.
If exposed, it can reveal administrative interfaces and potentially sensitive data.
Severity: HIGH
"""
from __future__ import annotations

import httpx
from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


class NovaExposedCheck(BaseCheck):
    CHECK_ID = "NOVA_EXPOSED"
    TITLE = "Laravel Nova Exposed"

    # Common Nova endpoints
    NOVA_PATHS = [
        "/nova",
        "/nova/dashboard",
        "/nova-api/",
    ]
    
    # Indicators in HTML that suggest Nova is present
    NOVA_INDICATORS = [
        "nova",
        "laravel nova",
        "nova-script",
        "nova-style",
    ]

    async def run(self, target: ScanTarget) -> Finding:
        """
        Check if Laravel Nova is accessible.
        """
        exposed_paths = []
        evidence_details = []

        # Check Nova endpoints
        for path in self.NOVA_PATHS:
            url = self._build_url(target.url, path)
            try:
                resp = await self._client.get(
                    url,
                    headers=target.headers,
                    follow_redirects=True,
                )
                logger.debug(f"[{self.CHECK_ID}] {url} → HTTP {resp.status_code}")

                if resp.status_code == 200:
                    body = resp.text.lower()
                    # Check for Nova indicators in response
                    matches = sum(1 for indicator in self.NOVA_INDICATORS if indicator in body)
                    if matches >= 2:  # At least 2 indicators
                        exposed_paths.append(path)
                        evidence_details.append(f"Endpoint {path} returned 200 with Nova indicators")

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
                    f"Laravel Nova appears to be accessible at: {', '.join(exposed_paths)}. "
                    "Nova should not be accessible in production environments."
                ),
                evidence="\n".join(evidence_details) if evidence_details else "Nova detected",
                remediation=(
                    "1. Remove Nova package from production: "
                    "`composer remove laravel/nova`\n"
                    "2. Or ensure Nova is only enabled in non-production environments:\n"
                    "   Check `app/Providers/NovaServiceProvider.php` and ensure it's wrapped in environment check\n"
                    "3. Configure web server to deny access to /nova path.\n"
                    "4. Use Nova's built-in authentication: "
                    "`Nova::auth(function ($request) { return $request->user()->isAdmin(); });`"
                ),
                cvss_score=7.5,
                references=[
                    "https://nova.laravel.com/docs",
                    "https://github.com/laravel/nova",
                ],
            )

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=Severity.HIGH,
            status=CheckStatus.SAFE,
            description="Laravel Nova does not appear to be exposed.",
        )
