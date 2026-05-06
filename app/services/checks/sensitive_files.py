"""
Check: Sensitive files and directories exposed to the public.

Probes for common Laravel/PHP sensitive paths that should never be
publicly reachable: storage/, vendor/, .git/, phpinfo, etc.
Severity: varies per path.
"""
from __future__ import annotations

from dataclasses import dataclass

import httpx
from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


@dataclass(frozen=True)
class SensitivePath:
    path: str
    severity: Severity
    label: str
    # If True, we check the body for a confirming signature
    body_signature: str | None = None


SENSITIVE_PATHS: list[SensitivePath] = [
    SensitivePath("phpinfo.php",         Severity.CRITICAL, "phpinfo() page",                 "PHP Version"),
    SensitivePath("info.php",            Severity.CRITICAL, "phpinfo() page (info.php)",       "PHP Version"),
    SensitivePath(".git/config",         Severity.CRITICAL, "Git config exposed",              "[core]"),
    SensitivePath(".git/HEAD",           Severity.HIGH,     "Git HEAD exposed",                "ref: refs/"),
    SensitivePath("storage/logs/laravel.log", Severity.HIGH, "Laravel log file exposed",      "["),
    SensitivePath("storage/logs/",       Severity.HIGH,     "Storage/logs directory listing",  "Index of"),
    SensitivePath("vendor/autoload.php", Severity.HIGH,     "Vendor directory exposed",        "<?php"),
    SensitivePath("artisan",             Severity.MEDIUM,   "Artisan CLI accessible",          "#!/usr/bin/env php"),
    SensitivePath("composer.json",       Severity.MEDIUM,   "composer.json exposed",           "require"),
    SensitivePath("composer.lock",       Severity.MEDIUM,   "composer.lock exposed",           "packages"),
    SensitivePath("package.json",        Severity.LOW,      "package.json exposed",            "dependencies"),
    SensitivePath("webpack.mix.js",      Severity.LOW,      "webpack.mix.js exposed",          "mix"),
    SensitivePath("phpunit.xml",         Severity.LOW,      "phpunit.xml exposed",             "<phpunit"),
    SensitivePath(".htaccess",           Severity.INFO,     ".htaccess exposed",               "RewriteEngine"),
]


class SensitiveFilesCheck(BaseCheck):
    CHECK_ID = "SENSITIVE_FILES"
    TITLE = "Sensitive Files / Directories Exposed"

    async def run(self, target: ScanTarget) -> Finding:
        """
        Probe each sensitive path. Only report confirmed exposures
        (status 200 + optional body signature match).
        """
        exposed: list[tuple[SensitivePath, str]] = []  # (path_cfg, url)

        for cfg in SENSITIVE_PATHS:
            url = self._build_url(target.url, cfg.path)
            try:
                resp = await self._client.get(
                    url,
                    headers=target.headers,
                    follow_redirects=False,
                )
                logger.debug(f"[{self.CHECK_ID}] {url} → HTTP {resp.status_code}")

                if resp.status_code != 200:
                    continue

                # Confirm with body signature if required
                if cfg.body_signature:
                    if cfg.body_signature.lower() not in resp.text.lower():
                        continue

                exposed.append((cfg, url))

            except httpx.TimeoutException:
                logger.warning(f"[{self.CHECK_ID}] Timeout: {url}")
            except httpx.RequestError as exc:
                logger.warning(f"[{self.CHECK_ID}] Error: {exc}")

        if not exposed:
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.HIGH,
                status=CheckStatus.SAFE,
                description="No sensitive files or directories are publicly accessible.",
            )

        # Highest severity among found items
        top_severity = max((e[0].severity for e in exposed), key=lambda s: list(Severity).index(s))

        evidence_lines = [
            f"• [{cfg.severity.value}] {cfg.label} — {url}"
            for cfg, url in exposed
        ]

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=top_severity,
            status=CheckStatus.VULNERABLE,
            description=f"{len(exposed)} sensitive file(s)/directory(ies) found publicly accessible.",
            evidence="\n".join(evidence_lines),
            remediation=(
                "1. Configure your web server to serve only from /public.\n"
                "2. Add deny rules for .git, vendor, storage in Nginx/Apache.\n"
                "3. Remove debug/info PHP files from production.\n"
                "4. Ensure your document root is set to `/path/to/project/public`."
            ),
            references=[
                "https://laravel.com/docs/deployment",
                "https://owasp.org/www-project-web-security-testing-guide/",
            ],
        )
