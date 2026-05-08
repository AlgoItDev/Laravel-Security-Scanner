"""
Check: Exposed Laravel Mix manifest.

Laravel Mix generates a manifest file (mix-manifest.json) that maps
original file names to versioned filenames. If exposed, it can reveal
asset structure and paths.
Severity: LOW
"""
from __future__ import annotations

import httpx
from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


class MixManifestExposedCheck(BaseCheck):
    CHECK_ID = "MIX_MANIFEST_EXPOSED"
    TITLE = "Laravel Mix Manifest Exposed"

    async def run(self, target: ScanTarget) -> Finding:
        """
        Check if mix-manifest.json is accessible.
        """
        url = self._build_url(target.url, "mix-manifest.json")
        try:
            resp = await self._client.get(
                url,
                headers=target.headers,
                follow_redirects=False,
            )
            logger.debug(f"[{self.CHECK_ID}] {url} → HTTP {resp.status_code}")

            if resp.status_code == 200:
                # Check if response looks like a valid mix manifest
                body = resp.text
                if body.strip().startswith("{") and (
                    "mix-manifest" in body.lower() or 
                    '"/css/' in body or 
                    '"/js/' in body or
                    ".js" in body.lower()
                ):
                    return Finding(
                        check_id=self.CHECK_ID,
                        title=self.TITLE,
                        severity=Severity.LOW,
                        status=CheckStatus.VULNERABLE,
                        description=(
                            "Laravel Mix manifest (mix-manifest.json) is publicly accessible. "
                            "This file reveals asset paths and versioning information."
                        ),
                        evidence=f"URL: {url}\nResponse: {body[:200]}...",
                        remediation=(
                            "ℹ️ LOW: mix-manifest.json public! Path bilgileri sızdırılabilir.\n\n"
                            "🛡️ Seçenek 1: Nginx ile Engelle:\n"
                            "   location = /mix-manifest.json {\n"
                            "       deny all;\n"
                            "       return 404;\n"
                            "   }\n\n"
                            "🛡️ Seçenek 2: Apache:\n"
                            "   <Files \"mix-manifest.json\">\n"
                            "       Order deny,allow\n"
                            "       Deny from all\n"
                            "   </Files>\n\n"
                            "🛡️ Seçenek 3: Vite (modern):\n"
                            "   # Vite kullanıyorsan bu sorun olmaz\n"
                            "   # mix-manifest.json yerine .vite manifest kullan\n"
                            "🔗 Ref: https://laravel.com/docs/mix"
                        ),
                        cvss_score=2.0,
                        references=[
                            "https://laravel.com/docs/mix",
                            "https://github.com/laravel-mix/laravel-mix",
                        ],
                    )

        except httpx.TimeoutException:
            logger.warning(f"[{self.CHECK_ID}] Timeout for {url}")
        except httpx.RequestError as exc:
            logger.warning(f"[{self.CHECK_ID}] Request error for {url}: {exc}")

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=Severity.LOW,
            status=CheckStatus.SAFE,
            description="Laravel Mix manifest is not publicly accessible.",
        )
