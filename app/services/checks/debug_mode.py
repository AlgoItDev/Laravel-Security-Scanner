"""
Check: Laravel debug mode enabled in production.

When APP_DEBUG=true is active, detailed exception pages (stack traces,
env vars, source code) are shown to anonymous users.
Severity: HIGH
"""
from __future__ import annotations

import httpx
from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


# Strings found exclusively on Laravel's Ignition / Whoops debug pages
DEBUG_SIGNATURES = [
    "Ignition",                        # Laravel Ignition error page
    "whoops</title>",                  # Whoops! error handler
    "APP_DEBUG",                       # env var leaking in page
    "Illuminate\\",                    # Laravel namespace in stack trace
    "vendor/laravel/framework",        # vendor path exposed
    "Stack trace:",                    # PHP stack trace header
    "symfony/debug",                   # Symfony debug component
    "ErrorException",                  # uncaught exception class
]

# Probe paths that are likely to trigger an exception/404 with debug info
PROBE_PATHS = [
    "_debug_probe_404_nonexistent_path_xyz",
    "index.php?trigger_debug=1",
]


class DebugModeCheck(BaseCheck):
    CHECK_ID = "DEBUG_MODE"
    TITLE = "Laravel Debug Mode Enabled"

    async def run(self, target: ScanTarget) -> Finding:
        """
        Trigger a 404/500 and inspect the response for debug page signatures.
        Also checks the X-Debug-Token and X-DebugBar-* response headers.
        """
        triggered_paths: list[str] = []
        evidence_parts: list[str] = []

        for path in PROBE_PATHS:
            url = self._build_url(target.url, path)
            try:
                resp = await self._client.get(
                    url,
                    headers=target.headers,
                    follow_redirects=True,
                )
                logger.debug(f"[{self.CHECK_ID}] {url} → HTTP {resp.status_code}")

                body = resp.text.lower()
                matched = [sig for sig in DEBUG_SIGNATURES if sig.lower() in body]

                # Header-based evidence
                header_hits = [
                    h for h in resp.headers
                    if "debug" in h.lower() or "debugbar" in h.lower()
                ]

                if matched or header_hits:
                    triggered_paths.append(path)
                    evidence_parts.append(
                        f"Path: {path} | HTTP {resp.status_code}\n"
                        f"  Body signatures: {matched}\n"
                        f"  Debug headers  : {header_hits}"
                    )

            except httpx.TimeoutException:
                logger.warning(f"[{self.CHECK_ID}] Timeout for {url}")
            except httpx.RequestError as exc:
                logger.warning(f"[{self.CHECK_ID}] Request error: {exc}")

        if triggered_paths:
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.HIGH,
                status=CheckStatus.VULNERABLE,
                description=(
                    "Laravel debug mode appears to be active. Error pages expose "
                    "stack traces, environment variables, and application source paths "
                    "to anonymous users."
                ),
                evidence="\n".join(evidence_parts),
                remediation=(
                    "🔴 CRITICAL: APP_DEBUG=true stack trace'ları saldırgana gösterir\n\n"
                    "📁 1. Düzeltme (.env):\n"
                    "   APP_DEBUG=false\n"
                    "   APP_ENV=production\n\n"
                    "⚡ 2. Cache temizle:\n"
                    "   php artisan config:clear\n"
                    "   # veya: php artisan config:cache (production'da)\n\n"
                    "🧪 3. Test:\n"
                    "   # Stack trace YOK, safe error sayfası OLMALI\n"
                    "   curl -I https://site.test/not-found\n\n"
                    "📚 4. İleri Adımlar:\n"
                    "   - Custom error handler: app/Exceptions/Handler.php\n"
                    "   - views/errors/ dizini oluştur\n"
                    "   - Log viewer: Laravel Forge / Envoyer kullan\n\n"
                    "🔗 Ref: https://laravel.com/docs/configuration#debug-mode"
                ),
                cvss_score=7.5,
                references=[
                    "https://laravel.com/docs/configuration#debug-mode",
                    "https://owasp.org/www-community/Improper_Error_Handling",
                ],
            )

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=Severity.HIGH,
            status=CheckStatus.SAFE,
            description="No debug mode indicators found.",
        )
