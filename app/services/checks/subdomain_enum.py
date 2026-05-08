"""
Check: Subdomain Enumeration.

Discovers subdomains associated with the target domain to identify
exposed internal services, dev/staging environments, or forgotten assets.

Severity: INFO — Exposed subdomains may reveal additional attack surface.
"""
from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import httpx

from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


COMMON_SUBDOMAINS = [
    "api", "dev", "test", "staging", "stage", "admin", "administrator",
    "cdn", "assets", "static", "images", "img", "media", "files",
    "mail", "smtp", "pop", "imap", "webmail", "owa", "autodiscover",
    "db", "database", "mysql", "postgres", "mongo", "redis",
    "backup", "backups", "storage", "s3",
    "git", "gitlab", "github", "jenkins", "ci", "build",
    "monitor", "metrics", "grafana", "kibana", "prometheus",
    "vpn", "remote", "portal", "sso", "auth", "login",
    "shop", "store", "cart", "checkout", "payment",
    "blog", "forum", "cms", "wordpress", "joomla",
    "demo", "sandbox", "lab", "research",
    "status", "health", "ping", "monitor",
    "internal", "private", "corp",
]


class SubdomainEnumCheck(BaseCheck):
    CHECK_ID = "SUBDOMAIN_ENUM"
    TITLE = "Subdomain Enumeration"

    async def run(self, target: ScanTarget) -> Finding:
        """
        Enumerate subdomains by testing common subdomain prefixes
        against the target domain.
        """
        discovered: list[str] = []
        evidence_details: list[str] = []

        parsed = urlparse(target.url)
        base_domain = parsed.netloc or target.url

        domain_parts = base_domain.replace(":", "/").split("/")[0].split(".")
        if len(domain_parts) > 2:
            root_domain = ".".join(domain_parts[-2:])
        else:
            root_domain = base_domain

        async def check_subdomain(subdomain: str) -> str | None:
            full_host = f"{subdomain}.{root_domain}"
            url = f"{parsed.scheme or 'https'}://{full_host}"
            
            try:
                response = await self._client.get(
                    url,
                    headers=target.headers,
                    follow_redirects=False,
                    timeout=5.0,
                )
                
                if response.status_code < 500:
                    return full_host
                
            except (httpx.TimeoutException, httpx.RequestError):
                pass
            
            return None

        tasks = [check_subdomain(sub) for sub in COMMON_SUBDOMAINS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for subdomain, result in zip(COMMON_SUBDOMAINS, results):
            if isinstance(result, str) and result:
                discovered.append(result)
                evidence_details.append(f"Found subdomain: {result}")

        if discovered:
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.INFO,
                status=CheckStatus.VULNERABLE,
                description=(
                    f"Discovered {len(discovered)} subdomains. "
                    "These may expose additional attack surface including "
                    "internal services, dev environments, or forgotten assets."
                ),
                evidence="\n".join(evidence_details),
                remediation=(
                    "1. Audit all discovered subdomains for security.\n"
                    "2. Implement DNS filtering to block unauthorized subdomains.\n"
                    "3. Use CNAME records for proper subdomain management.\n"
                    "4. Ensure development/staging domains are not publicly accessible.\n"
                    "5. Implement subdomain takeover prevention."
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/",
                    "https://github.com/subjack/subjack",
                ],
            )

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=Severity.INFO,
            status=CheckStatus.SAFE,
            description="No subdomains discovered with common naming patterns.",
        )