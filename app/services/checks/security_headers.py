"""
Check: Missing or insecure HTTP security headers.

Covers: HSTS, X-Frame-Options, X-Content-Type-Options,
CSP, Referrer-Policy, Permissions-Policy.
Severity: MEDIUM / LOW depending on missing header.
"""
from __future__ import annotations

from dataclasses import dataclass

import httpx
from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


@dataclass(frozen=True)
class HeaderRule:
    name: str
    severity: Severity
    description: str
    remediation: str
    # Optional: check that value contains this substring (case-insensitive)
    required_value_fragment: str | None = None


HEADER_RULES: list[HeaderRule] = [
    HeaderRule(
        name="Strict-Transport-Security",
        severity=Severity.HIGH,
        description="HSTS header missing — site is vulnerable to protocol downgrade attacks.",
        remediation=(
            "🛡️ HSTS (HTTP Strict Transport Security):\n"
            "   # app/Http/Middleware/TrustProxies.php:\n"
            "   'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains'\n\n"
            "   # Nginx:\n"
            "   add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\";\n\n"
            "   # .htaccess:\n"
            "   Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\""
        ),
    ),
    HeaderRule(
        name="X-Frame-Options",
        severity=Severity.MEDIUM,
        description="Missing X-Frame-Options — site may be clickjackable.",
        remediation=(
            "🛡️ X-Frame-Options (Clickjacking koruması):\n"
            "   # Nginx:\n"
            "   add_header X-Frame-Options \"SAMEORIGIN\";\n\n"
            "   # Laravel (Bootstrap/app.php):\n"
            "   'X-Frame-Options' => 'SAMEORIGIN',\n\n"
            "   # Veya CSP frame-ancestors kullan:\n"
            "   'Content-Security-Policy' => \"frame-ancestors 'self'\""
        ),
    ),
    HeaderRule(
        name="X-Content-Type-Options",
        severity=Severity.MEDIUM,
        description="Missing X-Content-Type-Options — MIME-sniffing attacks possible.",
        remediation=(
            "🛡️ X-Content-Type-Options:\n"
            "   # Nginx:\n"
            "   add_header X-Content-Type-Options \"nosniff\";\n\n"
            "   # Laravel:\n"
            "   'X-Content-Type-Options' => 'nosniff'"
        ),
    ),
    HeaderRule(
        name="Content-Security-Policy",
        severity=Severity.MEDIUM,
        description="No Content-Security-Policy — XSS and data injection risks elevated.",
        remediation=(
            "🛡️ Content-Security-Policy (CSP) - En güçlü koruma:\n"
            "   # Başlangıç (relaxed):\n"
            "   'Content-Security-Policy' => \"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'\"\n\n"
            "   # İleri (strict):\n"
            "   'Content-Security-Policy' => \"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'\"\n\n"
            "   # Laravel MIX (vite.config.js):\n"
            "   // CSP plugin ile Vite\n\n"
            "🔗 Ref: https://content-security-policy.com/"
        ),
    ),
    HeaderRule(
        name="Referrer-Policy",
        severity=Severity.LOW,
        description="Missing Referrer-Policy — referrer leakage possible.",
        remediation=(
            "🛡️ Referrer-Policy:\n"
            "   # Laravel:\n"
            "   'Referrer-Policy' => 'strict-origin-when-cross-origin'\n\n"
            "   # Nginx:\n"
            "   add_header Referrer-Policy \"strict-origin-when-cross-origin\";"
        ),
    ),
    HeaderRule(
        name="Permissions-Policy",
        severity=Severity.LOW,
        description="Missing Permissions-Policy — browser feature access not restricted.",
        remediation=(
            "🛡️ Permissions-Policy (Browser features kısıtlama):\n"
            "   # Laravel:\n"
            "   'Permissions-Policy' => 'camera=(), microphone=(), geolocation=()'\n\n"
            "   # Nginx:\n"
            "   add_header Permissions-Policy \"camera=(), microphone=(), geolocation=();\""
        ),
    ),
    HeaderRule(
        name="X-Powered-By",
        severity=Severity.LOW,
        description=(
            "X-Powered-By header exposes technology stack (e.g. PHP version). "
            "Aids fingerprinting."
        ),
        remediation=(
            "🛡️ X-Powered-By Kaldır:\n"
            "   # php.ini:\n"
            "   expose_php = Off\n\n"
            "   # Nginx:\n"
            "   more_clear_headers 'X-Powered-By';\n\n"
            "   # Apache:\n"
            "   Header unset X-Powered-By"
        ),
    ),
]


class SecurityHeadersCheck(BaseCheck):
    CHECK_ID = "SECURITY_HEADERS"
    TITLE = "HTTP Security Headers"

    async def run(self, target: ScanTarget) -> Finding:
        """Fetch the root URL and evaluate security headers."""
        try:
            resp = await self._client.get(
                target.url,
                headers=target.headers,
                follow_redirects=True,
            )
        except httpx.TimeoutException:
            logger.warning(f"[{self.CHECK_ID}] Timeout fetching {target.url}")
            return self._skipped("Request timed out.")
        except httpx.RequestError as exc:
            logger.warning(f"[{self.CHECK_ID}] Request error: {exc}")
            return self._skipped(str(exc))

        response_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        issues: list[str] = []

        for rule in HEADER_RULES:
            header_lower = rule.name.lower()
            present = header_lower in response_headers_lower

            # X-Powered-By is BAD if PRESENT
            if rule.name == "X-Powered-By":
                if present:
                    val = response_headers_lower[header_lower]
                    issues.append(
                        f"• [{rule.severity.value}] {rule.name} is set to '{val}'. "
                        f"{rule.description} -> {rule.remediation}"
                    )
                continue

            # All others are BAD if ABSENT
            if not present:
                issues.append(
                    f"• [{rule.severity.value}] {rule.name} is missing. "
                    f"{rule.description} -> {rule.remediation}"
                )

        logger.debug(f"[{self.CHECK_ID}] {len(issues)} header issues found.")

        if issues:
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.MEDIUM,
                status=CheckStatus.VULNERABLE,
                description=f"{len(issues)} security header issue(s) detected.",
                evidence="\n".join(issues),
                remediation=(
                    "Review and add missing headers in your web server config or "
                    "Laravel middleware (e.g. `app/Http/Middleware/SecurityHeaders.php`)."
                ),
                references=[
                    "https://securityheaders.com/",
                    "https://owasp.org/www-project-secure-headers/",
                ],
            )

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=Severity.MEDIUM,
            status=CheckStatus.SAFE,
            description="All expected security headers are present.",
        )

    def _skipped(self, reason: str) -> Finding:
        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=Severity.MEDIUM,
            status=CheckStatus.SKIPPED,
            description=f"Check skipped: {reason}",
        )
