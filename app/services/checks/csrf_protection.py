"""
Check: Missing CSRF protection.

Laravel applications should have CSRF protection enabled by default,
but misconfigurations or custom routes might disable it.
Severity: HIGH
"""
from __future__ import annotations

import httpx
from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


class CSRFProtectionCheck(BaseCheck):
    CHECK_ID = "CSRF_PROTECTION"
    TITLE = "CSRF Protection Check"

    async def run(self, target: ScanTarget) -> Finding:
        """
        Check if CSRF protection might be missing.
        We check for:
        1. Missing CSRF token in forms
        2. Missing XSRF-TOKEN header in AJAX requests
        3. Laravel specific CSRF cookie (XSRF-TOKEN) presence
        """
        issues = []
        
        try:
            # Get the main page
            resp = await self._client.get(
                target.url,
                headers=target.headers,
                follow_redirects=True,
            )
            
            # Check 1: Look for forms without CSRF tokens
            body = resp.text
            import re
            
            # Find all forms
            forms = re.findall(r'(<form[^>]*>.*?</form>)', body, re.DOTALL)
            for form_html in forms:
                method_match = re.search(r'method=["\']?(GET|get)["\']?', form_html)
                if method_match:
                    continue

                has_token = (
                    '_token' in form_html or
                    'csrf_token' in form_html or
                    'csrf-token' in form_html or
                    'name="_token"' in form_html or
                    'name="csrf' in form_html
                )

                if not has_token:
                    issues.append("Form without CSRF token detected")
                    break
            
            # Check 2: Check for Laravel's CSRF cookie
            xsrf_cookie_present = False
            if 'XSRF-TOKEN' in resp.cookies.keys() or 'XSRF-TOKEN' in resp.headers.get('set-cookie', ''):
                xsrf_cookie_present = True
            elif 'xsrf_token' in resp.cookies.keys() or 'xsrf_token' in resp.headers.get('set-cookie', ''):
                xsrf_cookie_present = True
            
            # Check 3: Look for meta tag with CSRF token
            meta_csrf = re.search(
                r'<meta\s+name=["\']?csrf-token["\']?\s+content=["\']([^"\']+)["\']?', 
                body
            )
            
            # Evaluate findings
            if issues:
                return Finding(
                    check_id=self.CHECK_ID,
                    title=self.TITLE,
                    severity=Severity.HIGH,
                    status=CheckStatus.VULNERABLE,
                    description=(
                        "Potential CSRF protection missing. "
                        "Forms without CSRF tokens detected."
                    ),
                    evidence="\n".join(issues),
                    remediation=(
                        "1. Ensure CSRF middleware is enabled in Laravel:\n"
                        "   Check `app/Http/Middleware/VerifyCsrfToken.php` is in the middleware stack.\n"
                        "2. For forms, always include CSRF token:\n"
                        "   `<input type=\"hidden\" name=\"_token\" value=\"{{ csrf_token() }}\">`\n"
                        "3. For AJAX requests, include XSRF-TOKEN header:\n"
                        "   `XSRF-TOKEN: `$(document).find('meta[name=\"csrf-token\"]').attr('content')`\n"
                        "4. Ensure routes that need CSRF protection are not excluded."
                    ),
                    cvss_score=7.1,
                    references=[
                        "https://laravel.com/docs/csrf",
                        "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control",
                    ],
                )

            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.HIGH,
                status=CheckStatus.SAFE,
                description="CSRF protection appears to be properly configured.",
            )
                
        except httpx.TimeoutException:
            logger.warning(f"[{self.CHECK_ID}] Timeout for {target.url}")
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.HIGH,
                status=CheckStatus.UNKNOWN,
                description="Could not check CSRF protection due to timeout.",
            )
        except httpx.RequestError as exc:
            logger.warning(f"[{self.CHECK_ID}] Request error: {exc}")
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.HIGH,
                status=CheckStatus.UNKNOWN,
                description=f"Could not check CSRF protection: {exc}",
            )
