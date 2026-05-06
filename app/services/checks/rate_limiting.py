"""
Check: Missing rate limiting.

Checks if the target has rate limiting controls.
Repeated requests should be blocked/throttled.
Severity: MEDIUM
"""
from __future__ import annotations

import time

import httpx
from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


class RateLimitingCheck(BaseCheck):
    CHECK_ID = "RATE_LIMITING"
    TITLE = "Rate Limiting Missing"

    async def run(self, target: ScanTarget) -> Finding:
        """
        Check if rate limiting is in place by sending multiple requests.
        """
        try:
            # First, get a baseline response
            resp1 = await self._client.get(
                target.url,
                headers=target.headers,
                follow_redirects=False,
            )
            
            # Now send several requests quickly
            statuses = [resp1.status_code]
            for _ in range(5):  # Send 5 quick requests
                try:
                    resp = await self._client.get(
                        target.url,
                        headers=target.headers,
                        follow_redirects=False,
                    )
                    statuses.append(resp.status_code)
                    # If we get rate limited (429), that's good
                    if resp.status_code == 429:
                        return Finding(
                            check_id=self.CHECK_ID,
                            title=self.TITLE,
                            severity=Severity.MEDIUM,
                            status=CheckStatus.SAFE,
                            description="Rate limiting appears to be in place (429 Too Many Requests detected).",
                        )
                    time.sleep(0.1)  # Small delay between requests
                except Exception:
                    continue
            
            # Check if all responses are 200 (no rate limiting)
            if all(s == 200 for s in statuses):
                return Finding(
                    check_id=self.CHECK_ID,
                    title=self.TITLE,
                    severity=Severity.MEDIUM,
                    status=CheckStatus.VULNERABLE,
                    description="No rate limiting detected. Multiple rapid requests all returned 200.",
                    evidence=f"Sent 6 rapid requests, all returned 200.",
                    remediation=(
                        "1. Implement rate limiting in Laravel:\n"
                        "   Use Laravel's built-in rate limiting:\n"
                        "   In `app/Providers/RouteServiceProvider.php`:\n"
                        "   `Route::middleware('throttle:60,1')->group(function () {\n"
                        "       // your routes\n"
                        "   });`\n"
                        "2. Or use web server rate limiting:\n"
                        "   Nginx: `limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;`\n"
                        "   Apache: `mod_reqtimeout` or `mod_ratelimit`"
                    ),
                    cvss_score=5.3,
                    references=[
                        "https://laravel.com/docs/rate-limiting",
                        "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
                    ],
                )
            else:
                # Some variation in responses - might have some protection
                return Finding(
                    check_id=self.CHECK_ID,
                    title=self.TITLE,
                    severity=Severity.MEDIUM,
                    status=CheckStatus.SAFE,
                    description="Rate limiting might be in place (varying response codes detected).",
                )
                
        except httpx.TimeoutException:
            logger.warning(f"[{self.CHECK_ID}] Timeout for {target.url}")
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.MEDIUM,
                status=CheckStatus.UNKNOWN,
                description="Could not check rate limiting due to timeout.",
            )
        except httpx.RequestError as exc:
            logger.warning(f"[{self.CHECK_ID}] Request error: {exc}")
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.MEDIUM,
                status=CheckStatus.UNKNOWN,
                description=f"Could not check rate limiting: {exc}",
            )
