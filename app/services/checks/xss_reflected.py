"""
Check: Reflected Cross-Site Scripting (XSS) detection.

Tests URL parameters and form inputs for reflected XSS vulnerabilities
by injecting common XSS payloads and checking for reflection in response.

Severity: HIGH — XSS can lead to session hijacking, defacement, or phishing attacks.
"""
from __future__ import annotations

import re
from urllib.parse import urlencode

import httpx

from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "\"><script>alert(1)</script>",
    "'><script>alert(String.fromCharCode(88,83,83))</script>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
]


XSS_REFLECTION_PATTERNS = [
    r"<script.*alert",
    r"on(error|click|load|focus|blur)\s*=",
    r"javascript:",
    r"<img.*onerror",
    r"<svg.*onload",
    r"<iframe.*src",
]


class XSSReflectedCheck(BaseCheck):
    CHECK_ID = "XSS_REFLECTED"
    TITLE = "Reflected Cross-Site Scripting (XSS)"

    async def run(self, target: ScanTarget) -> Finding:
        """
        Test URL parameters for reflected XSS by injecting payloads
        and analyzing response for proper encoding or reflection.
        """
        vulnerabilities: list[str] = []
        evidence_details: list[str] = []

        test_params = ["q", "search", "id", "name", "redirect", "next", "url", "param"]
        
        for param in test_params:
            for payload in XSS_PAYLOADS[:5]:
                try:
                    test_url = f"{target.url}/?{param}={payload}"
                    response = await self._client.get(
                        test_url,
                        headers=target.headers,
                        follow_redirects=True,
                    )
                    
                    response_text = response.text
                    
                    if payload in response_text:
                        reflection = re.findall(
                            rf'.{{0,30}}{re.escape(payload)}.{{0,30}}',
                            response_text
                        )
                        
                        is_encoded = self._is_properly_encoded(payload, response_text)
                        
                        if not is_encoded:
                            vulnerabilities.append(f"{param}={payload}")
                            evidence_details.append(
                                f"Parameter: {param} | Payload: {payload} | "
                                f"Reflection: {reflection[0][:80] if reflection else 'N/A'}"
                            )
                            break

                except (httpx.TimeoutException, httpx.RequestError) as exc:
                    logger.debug(f"[{self.CHECK_ID}] Request failed: {exc}")
                    continue

        if vulnerabilities:
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.HIGH,
                status=CheckStatus.VULNERABLE,
                description=(
                    f"Reflected XSS vulnerabilities found in {len(vulnerabilities)} parameter(s). "
                    "User input is reflected without proper encoding, allowing attackers "
                    "to execute arbitrary JavaScript in victim's browser."
                ),
                evidence="\n".join(evidence_details[:5]),
                remediation=(
                    "1. Implement context-aware output encoding.\n"
                    "2. Use Content-Security-Policy (CSP) headers.\n"
                    "3. Validate and sanitize all user input.\n"
                    "4. Use template engines with auto-escaping (Blade in Laravel).\n"
                    "5. Set HttpOnly and Secure flags on session cookies."
                ),
                cvss_score=7.5,
                references=[
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                ],
            )

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=Severity.HIGH,
            status=CheckStatus.SAFE,
            description="No obvious reflected XSS vulnerabilities detected.",
        )

    @staticmethod
    def _is_properly_encoded(payload: str, response: str) -> bool:
        """Check if payload is properly HTML-encoded."""
        html_encoded_payloads = [
            payload.replace("<", "&lt;").replace(">", "&gt;"),
            payload.replace("<", "&#60;").replace(">", "&#62;"),
            payload.replace("'", "&#x27;").replace('"', "&quot;"),
        ]
        
        for encoded in html_encoded_payloads:
            if encoded in response:
                return True
        
        script_pattern = r'<script[^>]*>.*?</script>'
        if re.search(script_pattern, response, re.IGNORECASE):
            if payload not in response:
                return True
        
        return False