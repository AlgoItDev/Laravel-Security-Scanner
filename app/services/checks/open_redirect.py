"""
Check: Open Redirect vulnerability detection.

Tests URL parameters that might redirect users for open redirect vulnerabilities.
Uses controlled payloads and verifies if external redirects are allowed.

Severity: MEDIUM — Open redirects can be used for phishing and malware distribution.
"""
from __future__ import annotations

from urllib.parse import urlencode

import httpx

from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


REDIRECT_PAYLOADS = [
    "https://evil.example.com",
    "https://google.com",
    "//google.com",
    "///google.com",
    "https://google.com%23@example.com",
    "https://google.com%40@example.com",
    "javascript:alert(1)",
    r"\/\/google.com",
]


REDIRECT_PARAM_NAMES = [
    "redirect", "url", "next", "dest", "callback", "return", "redirect_to",
    "continue", "out", "view", "to", "src", "route", "redirect_uri",
    "return_url", "returnTo", "redirect_url", "redir", "next", "data",
    "reference", "sp", "q", "query", "url", "encode", "校验", "u", "pu",
]


class OpenRedirectCheck(BaseCheck):
    CHECK_ID = "OPEN_REDIRECT"
    TITLE = "Open Redirect Vulnerability"

    async def run(self, target: ScanTarget) -> Finding:
        """
        Test URL parameters for open redirect vulnerabilities
        by injecting payloads and analyzing redirect behavior.
        """
        vulnerabilities: list[str] = []
        evidence_details: list[str] = []

        for param in REDIRECT_PARAM_NAMES[:8]:
            for payload in REDIRECT_PAYLOADS[:4]:
                try:
                    test_url = f"{target.url}/?{param}={payload}"
                    response = await self._client.get(
                        test_url,
                        headers=target.headers,
                        follow_redirects=False,
                    )

                    location = response.headers.get("Location", "")
                    response_url = str(response.url)

                    if self._is_external_redirect(location, payload):
                        vulnerabilities.append(f"{param}={payload}")
                        evidence_details.append(
                            f"Parameter: {param} | Payload: {payload} | "
                            f"Location header: {location[:100]}"
                        )
                        break

                    if "evil" in location.lower() or "google.com" in location:
                        vulnerabilities.append(f"{param}={payload}")
                        evidence_details.append(
                            f"Parameter: {param} | External redirect detected | "
                            f"Location: {location[:100]}"
                        )
                        break

                    if response_url and response_url != test_url:
                        for vuln_payload in ["//", "///", "http://", "https://"]:
                            if response_url.startswith(vuln_payload) and "google" in response_url:
                                vulnerabilities.append(f"{param}={payload}")
                                evidence_details.append(
                                    f"Parameter: {param} | Redirect to: {response_url[:100]}"
                                )
                                break

                except (httpx.TimeoutException, httpx.RequestError) as exc:
                    logger.debug(f"[{self.CHECK_ID}] Request failed: {exc}")
                    continue

        if vulnerabilities:
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.MEDIUM,
                status=CheckStatus.VULNERABLE,
                description=(
                    f"Open redirect vulnerabilities found in {len(vulnerabilities)} parameter(s). "
                    "Attackers can exploit these to redirect users to malicious sites for phishing."
                ),
                evidence="\n".join(evidence_details[:5]),
                remediation=(
                    "1. Implement allowlist-based URL validation.\n"
                    "2. Avoid using user input directly in redirect URLs.\n"
                    "3. Use path normalization to detect traversal attempts.\n"
                    "4. Implement URL shortener with internal mappings.\n"
                    "5. Add Content-Security-Policy with 'frame-ancestors' directive."
                ),
                cvss_score=6.0,
                references=[
                    "https://owasp.org/www-community/attacks/Open_redirect",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                ],
            )

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=Severity.MEDIUM,
            status=CheckStatus.SAFE,
            description="No obvious open redirect vulnerabilities detected.",
        )

    @staticmethod
    def _is_external_redirect(location: str, payload: str) -> bool:
        """Check if the redirect leads to an external domain."""
        if not location:
            return False

        external_domains = ["evil.com", "google.com", "example.com"]
        
        for domain in external_domains:
            if domain in location.lower():
                return True
        
        if location.startswith("//") or location.startswith("///"):
            return True
        
        if payload in location:
            return True
        
        return False