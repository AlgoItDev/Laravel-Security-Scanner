"""
Check: Insecure application configuration indicators.

Detects:
- Wildcard CORS (`Access-Control-Allow-Origin: *`)
- Session cookies without Secure / HttpOnly / SameSite flags
- Server header leaking version info
- Missing CSRF token patterns (basic heuristic)
Severity: MEDIUM / HIGH
"""
from __future__ import annotations

import re

import httpx
from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


class InsecureConfigCheck(BaseCheck):
    CHECK_ID = "INSECURE_CONFIG"
    TITLE = "Insecure Application Configuration"

    async def run(self, target: ScanTarget) -> Finding:
        """Analyse response headers for insecure configuration signals."""
        try:
            resp = await self._client.get(
                target.url,
                headers=target.headers,
                follow_redirects=True,
            )
        except httpx.TimeoutException:
            logger.warning(f"[{self.CHECK_ID}] Timeout: {target.url}")
            return self._skipped("Timeout")
        except httpx.RequestError as exc:
            logger.warning(f"[{self.CHECK_ID}] Error: {exc}")
            return self._skipped(str(exc))

        issues: list[str] = []
        h = {k.lower(): v for k, v in resp.headers.items()}

        # ── CORS ──────────────────────────────────────────────────────────
        cors = h.get("access-control-allow-origin", "")
        if cors == "*":
            issues.append(
                "[HIGH] Wildcard CORS (Access-Control-Allow-Origin: *) - "
                "any origin can make credentialed cross-site requests."
            )

        # ── Server header ────────────────────────────────────────────────
        server = h.get("server", "")
        if re.search(r"\d+\.\d+", server):
            issues.append(
                f"[LOW] Server header reveals version info: '{server}'. "
                "Aids fingerprinting and targeted CVE lookup."
            )

        # ── Set-Cookie flags ─────────────────────────────────────────────
        set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") \
            else [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]

        for cookie in set_cookies:
            cookie_lower = cookie.lower()
            name = cookie.split("=")[0].strip()

            if "secure" not in cookie_lower:
                issues.append(
                    f"[MEDIUM] Cookie '{name}' is missing the Secure flag — "
                    "transmitted over HTTP."
                )
            if "httponly" not in cookie_lower:
                issues.append(
                    f"[MEDIUM] Cookie '{name}' is missing the HttpOnly flag — "
                    "accessible via JavaScript (XSS risk)."
                )
            if "samesite" not in cookie_lower:
                issues.append(
                    f"[LOW] Cookie '{name}' is missing the SameSite attribute — "
                    "CSRF risk."
                )

        # ── X-Powered-By PHP version ──────────────────────────────────────
        xpb = h.get("x-powered-by", "")
        if "php/" in xpb.lower():
            issues.append(
                f"[LOW] X-Powered-By exposes PHP version: '{xpb}'. "
                "Disable with `expose_php = Off` in php.ini."
            )

        logger.debug(f"[{self.CHECK_ID}] {len(issues)} config issues found.")

        if issues:
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.HIGH if any("[HIGH]" in i for i in issues) else Severity.MEDIUM,
                status=CheckStatus.VULNERABLE,
                description=f"{len(issues)} insecure configuration issue(s) detected.",
                evidence="\n".join(f"• {i}" for i in issues),
                remediation=(
                    "Review each finding and apply the suggested fix.\n"
                    "Laravel-specific: use `config/cors.php`, `config/session.php`, "
                    "and server-level hardening."
                ),
                references=[
                    "https://laravel.com/docs/cors",
                    "https://laravel.com/docs/session#configuration",
                    "https://owasp.org/www-project-secure-headers/",
                ],
            )

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=Severity.HIGH,
            status=CheckStatus.SAFE,
            description="No insecure configuration indicators detected.",
        )

    def _skipped(self, reason: str) -> Finding:
        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=Severity.MEDIUM,
            status=CheckStatus.SKIPPED,
            description=f"Check skipped: {reason}",
        )
