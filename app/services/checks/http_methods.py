"""
Check: Dangerous HTTP methods enabled.

Checks if dangerous HTTP methods (PUT, DELETE, TRACE, PATCH)
are accessible, which could indicate misconfigured server.
OPTIONS is allowed (used for CORS preflight).
Severity: MEDIUM
"""
from __future__ import annotations

import httpx
from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


class HTTPMethodsCheck(BaseCheck):
    CHECK_ID = "HTTP_METHODS"
    TITLE = "Dangerous HTTP Methods Enabled"

    DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "PATCH"]

    async def run(self, target: ScanTarget) -> Finding:
        exposed_methods = []
        evidence_details = []

        for method in self.DANGEROUS_METHODS:
            url = target.url
            try:
                resp = await self._client.request(method, url, headers=target.headers)
                logger.debug(f"[{self.CHECK_ID}] {method} {url} -> HTTP {resp.status_code}")

                if resp.status_code not in [405, 501, 403, 404]:
                    if resp.status_code == 200:
                        exposed_methods.append(method)
                        evidence_details.append(f"{method} method returned 200")
                    elif resp.status_code == 204:
                        exposed_methods.append(method)
                        evidence_details.append(f"{method} method returned 204 (No Content)")

            except httpx.TimeoutException:
                logger.warning(f"[{self.CHECK_ID}] Timeout for {method} {url}")
            except httpx.RequestError as exc:
                logger.warning(f"[{self.CHECK_ID}] Request error for {method} {url}: {exc}")

        if exposed_methods:
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.MEDIUM,
                status=CheckStatus.VULNERABLE,
                description=(
                    f"Potentially dangerous HTTP methods appear accessible: "
                    f"{', '.join(exposed_methods)}. "
                    "These methods might allow unauthorized modifications."
                ),
                evidence="\n".join(evidence_details),
                remediation=(
                    "1. Restrict HTTP methods at web server level:\n"
                    "   Nginx: `limit_except GET POST { deny all; }`\n"
                    "   Apache: `<LimitExcept GET POST> Deny from all </LimitExcept>`\n"
                    "2. Ensure Laravel routes only accept intended methods:\n"
                    "   In `routes/web.php`: `Route::post(...)` instead of `Route::any(...)`\n"
                    "3. Disable TRACE method (information disclosure risk)."
                ),
                cvss_score=5.8,
                references=[
                    "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control",
                    "https://laravel.com/docs/routing#available-router-methods",
                ],
            )

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=Severity.MEDIUM,
            status=CheckStatus.SAFE,
            description="No dangerous HTTP methods appear to be accessible.",
        )