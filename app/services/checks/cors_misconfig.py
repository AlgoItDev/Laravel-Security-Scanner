"""
Check: CORS (Cross-Origin Resource Sharing) Misconfiguration.

Analyzes CORS headers to detect dangerous configurations such as
allowing arbitrary origins, missing credentials protection, etc.

Severity: MEDIUM — CORS misconfigurations can lead to data theft via cross-origin attacks.
"""
from __future__ import annotations

import httpx

from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


class CORSMisconfigCheck(BaseCheck):
    CHECK_ID = "CORS_MISCONFIG"
    TITLE = "CORS Misconfiguration"

    async def run(self, target: ScanTarget) -> Finding:
        """
        Analyze CORS headers for security issues:
        - Access-Control-Allow-Origin: *
        - Access-Control-Allow-Credentials: true with *
        - Missing Access-Control-Allow-Methods restrictions
        """
        issues: list[str] = []
        evidence_details: list[str] = []

        endpoints_to_check = ["", "/api", "/api/user", "/auth"]

        for endpoint in endpoints_to_check:
            url = self._build_url(target.url, endpoint)
            
            test_origin = "https://evil.example.com"
            headers = {**target.headers, "Origin": test_origin}

            try:
                response = await self._client.get(
                    url,
                    headers=headers,
                    follow_redirects=True,
                )

                cors_origin = response.headers.get("Access-Control-Allow-Origin", "")
                cors_creds = response.headers.get("Access-Control-Allow-Credentials", "")
                cors_methods = response.headers.get("Access-Control-Allow-Methods", "")
                cors_headers = response.headers.get("Access-Control-Allow-Headers", "")

                if cors_origin == "*":
                    issues.append("Access-Control-Allow-Origin set to * (wildcard)")
                    evidence_details.append(
                        f"Endpoint: {endpoint} | Origin: * | "
                        f"Credentials: {cors_creds or 'not set'}"
                    )

                if cors_origin == "*" and cors_creds.lower() == "true":
                    issues.append("Wildcard origin with credentials (critical misconfiguration)")
                    evidence_details.append(
                        f"Endpoint: {endpoint} | CRITICAL: * with credentials=true"
                    )

                if cors_origin == test_origin:
                    issues.append("Origin is dynamically echoed back (potential issue)")
                    evidence_details.append(
                        f"Endpoint: {endpoint} | Origin: {test_origin} echoed"
                    )

                if not cors_methods and not cors_headers:
                    issues.append("CORS headers present but incomplete restrictions")
                    evidence_details.append(
                        f"Endpoint: {endpoint} | Allowed-Methods: {cors_methods or 'not set'}"
                    )

            except (httpx.TimeoutException, httpx.RequestError) as exc:
                logger.debug(f"[{self.CHECK_ID}] Request failed: {exc}")
                continue

        if issues:
            unique_issues = list(set(issues))
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.MEDIUM,
                status=CheckStatus.VULNERABLE,
                description=(
                    f"CORS misconfiguration(s) detected: {', '.join(unique_issues)}. "
                    "These configurations can allow unauthorized cross-origin access to sensitive data."
                ),
                evidence="\n".join(evidence_details),
                remediation=(
                    "⚠️ MEDIUM: CORS misconfiguration! Cross-origin attack riski!\n\n"
                    "🛡️ 1. Wildcard YASAK (*):\n"
                    "   # ❌ Yanlış:\n"
                    "   'allowed_origins' => ['*'],  # credentials ile!\n\n"
                    "   # ✅ Doğru:\n"
                    "   'allowed_origins' => ['https://app.example.com'],\n\n"
                    "🛡️ 2. Credential ile:\n"
                    "   # credentials varsa * çalışmaz, spesifik domain şart\n"
                    "   'supports_credentials' => true ise:\n"
                    "       'allowed_origins' => ['https://example.com'],\n\n"
                    "🛡️ 3. Methods kısıtla:\n"
                    "   'allowed_methods' => ['GET', 'POST'],\n\n"
                    "🛡️ 4. Laravel config:\n"
                    "   # config/cors.php:\n"
                    "   'paths' => ['api/*'],\n"
                    "   'allowed_methods' => ['GET', 'POST'],\n\n"
                    "🛡️ 5. SameSite Cookie:\n"
                    "   'samesite' => 'Strict',  # CSRF ek koruma\n\n"
                    "🔗 Ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
                ),
                cvss_score=5.5,
                references=[
                    "https://owasp.org/www-community/attacks/Cross-Site_Request_Forgery",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                ],
            )

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=Severity.MEDIUM,
            status=CheckStatus.SAFE,
            description="CORS configuration appears secure.",
        )