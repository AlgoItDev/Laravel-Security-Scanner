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
        """
        Check session cookie security settings.
        """
        issues = []
        evidence_details = []
        
        try:
            resp = await self._client.get(
                target.url,
                headers=target.headers,
                follow_redirects=True,
            )
            
            # Get session cookie
            session_cookie = None
            for cookie in resp.cookies:
                # Laravel default session cookie names
                if cookie.name in ['laravel_session', 'session', 'PHPSESSID']:
                    session_cookie = cookie
                    break
            
            if not session_cookie and 'Set-Cookie' in resp.headers:
                # Try to find from header
                set_cookie = resp.headers['Set-Cookie']
                if 'laravel_session' in set_cookie or 'session' in set_cookie:
                    # Parse cookie attributes from header
                    if 'secure' not in set_cookie.lower():
                        issues.append("Session cookie missing Secure flag")
                        evidence_details.append("Set-Cookie header missing 'secure' flag")
                    if 'httponly' not in set_cookie.lower():
                        issues.append("Session cookie missing HttpOnly flag")
                        evidence_details.append("Set-Cookie header missing 'httponly' flag")
                    if 'samesite' not in set_cookie.lower():
                        issues.append("Session cookie missing SameSite attribute")
                        evidence_details.append("Set-Cookie header missing 'samesite' attribute")
            elif session_cookie:
                # Check cookie attributes (httpx cookie object)
                if not session_cookie.secure:
                    issues.append("Session cookie missing Secure flag")
                    evidence_details.append(f"Cookie '{session_cookie.name}' has Secure=False")
                
                # httpx cookies don't expose HttpOnly/SameSite directly
                # Check via Set-Cookie header
                if 'Set-Cookie' in resp.headers:
                    set_cookie = resp.headers['Set-Cookie']
                    if 'httponly' not in set_cookie.lower():
                        issues.append("Session cookie missing HttpOnly flag")
                        evidence_details.append("HttpOnly flag not set")
                    if 'samesite' not in set_cookie.lower():
                        issues.append("Session cookie missing SameSite attribute")
                        evidence_details.append("SameSite attribute not set")
            else:
                # No session cookie found - might be using token-based auth
                # Check if session driver is file-based (insecure)
                return Finding(
                    check_id=self.CHECK_ID,
                    title=self.TITLE,
                    severity=Severity.MEDIUM,
                    status=CheckStatus.SAFE,
                    description="No session cookie detected - might be using token-based authentication.",
                )
            
            # Determine severity
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
                    "1. Enable Secure flag in session config:\n"
                    "   In `config/session.php`: 'secure' => env('SESSION_SECURE_COOKIE', true),\n"
                    "2. Enable HttpOnly flag:\n"
                    "   'httponly' => true,\n"
                    "3. Set SameSite attribute:\n"
                    "   'samesite' => 'lax', // or 'strict'\n"
                    "4. Consider changing session cookie name:\n"
                    "   'cookie' => 'myapp_session', // not default name\n"
                    "5. Use secure session driver for production:\n"
                    "   'driver' => 'redis' or 'memcached', // not 'file'"
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
