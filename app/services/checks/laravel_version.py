"""
Check: Laravel version disclosure.

Attempts to detect Laravel version from HTTP headers or common endpoints.
Severity: LOW to MEDIUM depending on context (information disclosure).
"""
from __future__ import annotations

import re
from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


class LaravelVersionCheck(BaseCheck):
    CHECK_ID = "LARAVEL_VERSION"
    TITLE = "Laravel Version Disclosure"

    # Common headers that might expose Laravel version
    VERSION_HEADERS = [
        "x-powered-by",
        "laravel",
        "x-laravel-version",
    ]

    # Common endpoints that might expose version
    VERSION_ENDPOINTS = [
        "/",
        "/api/_version",
        "/version",
        "/laravel_version",
    ]

    async def run(self, target: ScanTarget) -> Finding:
        """
        Check for Laravel version disclosure in headers and common endpoints.
        """
        version_found = None
        source = None

        # Check headers first
        try:
            resp = await self._client.get(
                target.url,
                headers=target.headers,
                follow_redirects=True,
            )
            # Check headers
            for header in self.VERSION_HEADERS:
                if header in resp.headers:
                    header_value = resp.headers[header]
                    # Look for version pattern (e.g., Laravel 8.0.0)
                    version_match = re.search(r'laravel[/\s]*(\d+\.\d+\.\d+)', header_value, re.IGNORECASE)
                    if version_match:
                        version_found = version_match.group(1)
                        source = f"Header: {header}"
                        break
                    # Also check for just "Laravel" without version
                    if 'laravel' in header_value.lower() and version_found is None:
                        version_found = "unknown"
                        source = f"Header: {header}"

            # If not found in headers, check common endpoints
            if version_found is None:
                for endpoint in self.VERSION_ENDPOINTS:
                    url = self._build_url(target.url, endpoint)
                    try:
                        resp = await self._client.get(
                            url,
                            headers=target.headers,
                            follow_redirects=True,
                        )
                        # Check headers again for this endpoint
                        for header in self.VERSION_HEADERS:
                            if header in resp.headers:
                                header_value = resp.headers[header]
                                version_match = re.search(r'laravel[/\s]*(\d+\.\d+\.\d+)', header_value, re.IGNORECASE)
                                if version_match:
                                    version_found = version_match.group(1)
                                    source = f"Endpoint {endpoint} - Header: {header}"
                                    break
                                if 'laravel' in header_value.lower() and version_found is None:
                                    version_found = "unknown"
                                    source = f"Endpoint {endpoint} - Header: {header}"
                        if version_found:
                            break

                        # Check response body for version patterns
                        body = resp.text
                        # Look for patterns like "Laravel Framework 8.0.0"
                        body_match = re.search(r'Laravel[^\d]*(\d+\.\d+\.\d+)', body, re.IGNORECASE)
                        if body_match:
                            version_found = body_match.group(1)
                            source = f"Endpoint {endpoint} - Response Body"
                            break
                    except Exception:
                        continue  # Skip to next endpoint on error
        except Exception as exc:
            logger.warning(f"[{self.CHECK_ID}] Error checking Laravel version: {exc}")
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.LOW,
                status=CheckStatus.UNKNOWN,
                description=f"Error while checking for Laravel version: {exc}",
            )

        if version_found:
            # Determine severity: if exact version -> MEDIUM, just "Laravel" -> LOW
            severity = Severity.MEDIUM if version_found != "unknown" else Severity.LOW
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                description=f"Laravel version disclosed: {version_found} via {source}.",
                severity=severity,
                status=CheckStatus.VULNERABLE,
                evidence=f"Laravel version: {version_found}, Source: {source}",
                remediation=(
                    "1. Remove or obfuscate X-Powered-By and other headers that reveal Laravel.\n"
                    "2. Configure your web server to not expose framework details.\n"
                    "3. In Laravel, ensure APP_DEBUG is false in production.\n"
                    "4. Use middleware to remove sensitive headers."
                ),
                references=[
                    "https://laravel.com/docs/configuration#environment-configuration",
                    "https://owasp.org/www-project-web-security-testing-guide/",
                ],
            )

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=Severity.LOW,
            status=CheckStatus.SAFE,
            description="No Laravel version disclosure detected.",
        )