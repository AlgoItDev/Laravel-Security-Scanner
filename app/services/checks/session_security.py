"""
Check: Session security configuration.

Laravel session security checks:
- Secure cookie flag
- HttpOnly flag
- SameSite attribute
- Session cookie name (should not be default)
Severity: MEDIUM to HIGH
"""
from __future__ import annotations

import httpx
from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


class SessionSecurityCheck(BaseCheck):
    CHECK_ID = "SESSION_SECURITY"
    TITLE = "Session Security Configuration"

    async def run(self, target: ScanTarget) -> Finding:
        issues = []
        evidence_details = []

        try:
            resp = await self._client.get(
                target.url,
                headers=target.headers,
                follow_redirects=True,
            )

            session_cookie_name = None
            for name in resp.cookies.keys():
                if name in ['laravel_session', 'session', 'PHPSESSID']:
                    session_cookie_name = name
                    break

            set_cookie_header = resp.headers.get('Set-Cookie', '')

            if session_cookie_name and set_cookie_header:
                if 'secure' not in set_cookie_header.lower():
                    issues.append("Session cookie missing Secure flag")
                    evidence_details.append("Set-Cookie header missing 'secure' flag")
                if 'httponly' not in set_cookie_header.lower():
                    issues.append("Session cookie missing HttpOnly flag")
                    evidence_details.append("Set-Cookie header missing 'httponly' flag")
                if 'samesite' not in set_cookie_header.lower():
                    issues.append("Session cookie missing SameSite attribute")
                    evidence_details.append("Set-Cookie header missing 'samesite' attribute")
            elif set_cookie_header and ('laravel_session' in set_cookie_header or 'session' in set_cookie_header):
                if 'secure' not in set_cookie_header.lower():
                    issues.append("Session cookie missing Secure flag")
                    evidence_details.append("Set-Cookie header missing 'secure' flag")
                if 'httponly' not in set_cookie_header.lower():
                    issues.append("Session cookie missing HttpOnly flag")
                    evidence_details.append("Set-Cookie header missing 'httponly' flag")
                if 'samesite' not in set_cookie_header.lower():
                    issues.append("Session cookie missing SameSite attribute")
                    evidence_details.append("Set-Cookie header missing 'samesite' attribute")
            else:
                return Finding(
                    check_id=self.CHECK_ID,
                    title=self.TITLE,
                    severity=Severity.MEDIUM,
                    status=CheckStatus.SAFE,
                    description="No session cookie detected - might be using token-based authentication.",
                )

            if len(issues) >= 3:
                severity = Severity.HIGH
                status = CheckStatus.VULNERABLE
            elif len(issues) > 0:
                severity = Severity.MEDIUM
                status = CheckStatus.VULNERABLE
            else:
                return Finding(
                    check_id=self.CHECK_ID,
                    title=self.TITLE,
                    severity=Severity.MEDIUM,
                    status=CheckStatus.SAFE,
                    description="Session security appears properly configured.",
                )

            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=severity,
                status=status,
                description=f"Session security issues found: {'; '.join(issues)}",
                evidence="\n".join(evidence_details) if evidence_details else "Session cookie issues detected",
                remediation=(
                    "⚠️ HIGH: Session cookie güvenlik eksik! Hijacking riski!\n\n"
                    "🛡️ 1. config/session.php ayarları:\n"
                    "   'driver' => env('SESSION_DRIVER', 'redis'),\n"
                    "   'secure' => env('SESSION_SECURE_COOKIE', true),  # HTTPS!\n"
                    "   'httponly' => true,  # JS erişimi yok\n"
                    "   'samesite' => 'lax',  # CSRF koruma\n\n"
                    "🛡️ 2. Cookie name değiştir:\n"
                    "   'cookie' => env('SESSION_COOKIE', 'app_session'),\n\n"
                    "🛡️ 3. Redis (önerilen):\n"
                    "   # .env:\n"
                    "   SESSION_DRIVER=redis\n"
                    "   REDIS_HOST=127.0.0.1\n\n"
                    "🛡️ 4. Lifetime kısıtla:\n"
                    "   'lifetime' => env('SESSION_LIFETIME', 120),\n"
                    "   'expire_on_close' => true,\n\n"
                    "🔗 Ref: https://laravel.com/docs/session"
                ),
                cvss_score=6.5 if severity == Severity.HIGH else 4.0,
                references=[
                    "https://laravel.com/docs/session",
                    "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control",
                ],
            )

        except httpx.TimeoutException:
            logger.warning(f"[{self.CHECK_ID}] Timeout for {target.url}")
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.MEDIUM,
                status=CheckStatus.UNKNOWN,
                description="Could not check session security due to timeout.",
            )
        except httpx.RequestError as exc:
            logger.warning(f"[{self.CHECK_ID}] Request error: {exc}")
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.MEDIUM,
                status=CheckStatus.UNKNOWN,
                description=f"Could not check session security: {exc}",
            )