"""
Check: JWT (JSON Web Token) security analysis.

Analyzes JWT tokens found in requests/responses for security issues
such as weak algorithms, missing expiration, or None algorithm usage.

Severity: HIGH — JWT vulnerabilities can lead to authentication bypass and unauthorized access.
"""
from __future__ import annotations

import base64
import json
import re
from typing import Any

import httpx

from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


JWT_PATTERNS = [
    r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
]

WEAK_ALGORITHMS = ["HS256", "HS384", "HS512"]
SECURE_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]


class JWTAnalysisCheck(BaseCheck):
    CHECK_ID = "JWT_ANALYSIS"
    TITLE = "JWT Token Security Analysis"

    async def run(self, target: ScanTarget) -> Finding:
        """
        Analyze JWT tokens for security issues including:
        - Weak algorithm usage (HS256)
        - None algorithm vulnerability
        - Missing expiration claim
        - Missing issuer/audience
        """
        issues: list[str] = []
        evidence_details: list[str] = []

        endpoints_to_check = [
            "",
            "/api",
            "/api/auth",
            "/api/login",
            "/api/user",
            "/auth",
            "/user",
        ]

        for endpoint in endpoints_to_check:
            url = self._build_url(target.url, endpoint)
            try:
                response = await self._client.get(
                    url,
                    headers=target.headers,
                    follow_redirects=True,
                )
                
                auth_header = response.headers.get("Authorization", "")
                response_text = response.text

                if auth_header.startswith("Bearer "):
                    token = auth_header[7:]
                    analysis = self._analyze_jwt(token)
                    if analysis:
                        issues.extend(analysis["issues"])
                        evidence_details.append(
                            f"Endpoint: {endpoint} | Token found in Authorization header | "
                            f"Algorithm: {analysis.get('algorithm', 'Unknown')}"
                        )

                for pattern in JWT_PATTERNS:
                    tokens = re.findall(pattern, response_text)
                    for token in tokens:
                        analysis = self._analyze_jwt(token)
                        if analysis and analysis["issues"]:
                            issues.extend(analysis["issues"])
                            evidence_details.append(
                                f"Endpoint: {endpoint} | Token found in response body | "
                                f"Algorithm: {analysis.get('algorithm', 'Unknown')}"
                            )

            except (httpx.TimeoutException, httpx.RequestError) as exc:
                logger.debug(f"[{self.CHECK_ID}] Request failed: {exc}")
                continue

        if issues:
            unique_issues = list(set(issues))
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.HIGH,
                status=CheckStatus.VULNERABLE,
                description=(
                    f"Found {len(unique_issues)} JWT security issue(s): "
                    f"{', '.join(unique_issues[:3])}. "
                    "These vulnerabilities can lead to authentication bypass."
                ),
                evidence="\n".join(evidence_details[:5]),
                remediation=(
                    "⚠️ HIGH: JWT güvenlik açıkları! Authentication bypass!\n\n"
                    "🛡️ 1. Algoritma (EN ÖNEMLİ):\n"
                    "   # ❌ KULLANMA:\n"
                    "   'HS256'  # Symmetric - secret sızdırılabilir\n\n"
                    "   # ✅ KULLAN:\n"
                    "   'RS256'  # Asymmetric - private key gizli\n"
                    "   'ES256'  # ECDSA - daha kısa\n\n"
                    "🛡️ 2. Expiration (exp):\n"
                    "   # Her token'a exp ekle:\n"
                    "   jwt.sign({ user_id }, secret, { expiresIn: '1h' });\n\n"
                    "🛡️ 3. Issuer/Audience doğrula:\n"
                    "   # payload:\n"
                    "   { iss: 'https://api.example.com', aud: 'myapp' }\n\n"
                    "🛡️ 4. Blacklist ( logout):\n"
                    "   # Redis'e token ID'si kaydet\n"
                    "   Redis::sadd('blacklist', tokenId);\n\n"
                    "🛡️ 5. Key storage:\n"
                    "   # .env (ASLA git'e commitlenmesin!)\n"
                    "   JWT_PRIVATE_KEY=./keys/private.pem\n\n"
                    "🔗 Ref: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"
                ),
                cvss_score=7.0,
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/",
                    "https://jwt.io/introduction/",
                    "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                ],
            )

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=Severity.HIGH,
            status=CheckStatus.SAFE,
            description="No JWT tokens found or JWT tokens appear secure.",
        )

    def _analyze_jwt(self, token: str) -> dict[str, Any] | None:
        """Decode and analyze a JWT token for security issues."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            header_raw = parts[0]
            payload_raw = parts[1]

            header = json.loads(base64.urlsafe_b64decode(header_raw + "=="))
            payload = json.loads(base64.urlsafe_b64decode(payload_raw + "=="))

            algorithm = header.get("alg", "")
            issues: list[str] = []

            if algorithm in ["HS256", "HS384", "HS512"]:
                issues.append(f"Weak symmetric algorithm: {algorithm}")

            if algorithm == "none":
                issues.append("None algorithm vulnerability (critical)")

            if "exp" not in payload:
                issues.append("Missing token expiration (exp) claim")

            if "iat" not in payload:
                issues.append("Missing issued-at (iat) claim")

            if "iss" not in payload:
                issues.append("Missing issuer (iss) claim")

            return {
                "algorithm": algorithm,
                "issues": issues,
                "payload": payload,
                "header": header,
            }

        except Exception as exc:
            logger.debug(f"[{self.CHECK_ID}] JWT decode failed: {exc}")
            return None