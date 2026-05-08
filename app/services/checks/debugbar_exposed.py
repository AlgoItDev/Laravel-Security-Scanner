"""
Check: Laravel Debugbar exposure.

Laravel Debugbar is a debugging toolbar that should not be enabled in production.
If exposed, it can leak sensitive information including queries, exceptions, etc.
Severity: MEDIUM (can be HIGH if sensitive data is exposed)
"""
from __future__ import annotations

import httpx
from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


class DebugbarExposedCheck(BaseCheck):
    CHECK_ID = "DEBUGBAR_EXPOSED"
    TITLE = "Laravel Debugbar Exposed"

    # Common Debugbar endpoints and indicators
    DEBUGBAR_PATHS = [
        "/_debugbar",
        "/_debugbar/clockwork",
        "/debugbar",
    ]
    
    # Indicators in HTML that suggest Debugbar is present
    DEBUGBAR_INDICATORS = [
        "debugbar",
        "phpdebugbar",
        "DebugBar",
        "X-Debugbar-",
    ]

    async def run(self, target: ScanTarget) -> Finding:
        """
        Check if Laravel Debugbar is accessible or present in responses.
        """
        exposed_paths = []
        evidence_details = []

        # Check Debugbar endpoints
        for path in self.DEBUGBAR_PATHS:
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
                    # Check for Debugbar indicators in response
                    if any(indicator.lower() in body for indicator in self.DEBUGBAR_INDICATORS):
                        exposed_paths.append(path)
                        evidence_details.append(f"Endpoint {path} returned 200 with Debugbar indicators")

            except httpx.TimeoutException:
                logger.warning(f"[{self.CHECK_ID}] Timeout for {url}")
            except httpx.RequestError as exc:
                logger.warning(f"[{self.CHECK_ID}] Request error for {url}: {exc}")

        # Also check main page for Debugbar scripts/styles
        try:
            resp = await self._client.get(
                target.url,
                headers=target.headers,
                follow_redirects=True,
            )
            
            # Check headers for Debugbar headers
            for header in resp.headers:
                if "debugbar" in header.lower():
                    evidence_details.append(f"Debugbar header present: {header}")
                    exposed_paths.append("(response headers)")
                    break
            
            # Check HTML for Debugbar assets
            body = resp.text
            if "debugbar" in body.lower() or "phpdebugbar" in body.lower():
                if not exposed_paths:  # Avoid duplicate
                    exposed_paths.append("(embedded in page)")
                    evidence_details.append("Debugbar scripts/styles detected in page HTML")
                    
        except (httpx.TimeoutException, httpx.RequestError):
            pass  # Already handled in endpoint checks

        if exposed_paths:
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.MEDIUM,
                status=CheckStatus.VULNERABLE,
                description=(
                    f"Laravel Debugbar appears to be enabled/exposed. "
                    f"Exposed via: {', '.join(set(exposed_paths))}. "
                    "Debugbar should not be enabled in production environments."
                ),
                evidence="\n".join(evidence_details) if evidence_details else "Debugbar detected",
                remediation=(
                    r"⚠️ MEDIUM: Debugbar enabled! Query log, memory usage herkes görür!" + "\n\n"
                    r"🛡️ Seçenek 1: ENV ile Kapat:" + "\n"
                    "   # .env:\n"
                    "   DEBUGBAR_ENABLED=false\n\n"
                    r"🛡️ Seçenek 2: Service Provider:" + "\n"
                    "   # app/Providers/AppServiceProvider.php:\n"
                    r"   public function register() {" + "\n"
                    r"       if ($this->app->environment('local')) {" + "\n"
                    r"           $this->app->register(\Debugbar::class);" + "\n"
                    "       }\n"
                    "   }\n\n"
                    "🛡️ Seçenek 3: config/debugbar.php:\n"
                    "   'enabled' => env('DEBUGBAR_ENABLED', false),\n\n"
                    "🛡️ Seçenek 4: Kaldır:\n"
                    "   composer remove barryvdh/laravel-debugbar --dev\n\n"
                    "🔗 Ref: https://github.com/barryvdh/laravel-debugbar"
                ),
                cvss_score=5.3,
                references=[
                    "https://github.com/barryvdh/laravel-debugbar",
                    "https://laravel.com/docs/configuration#environment-configuration",
                ],
            )

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=Severity.MEDIUM,
            status=CheckStatus.SAFE,
            description="Laravel Debugbar does not appear to be exposed.",
        )
