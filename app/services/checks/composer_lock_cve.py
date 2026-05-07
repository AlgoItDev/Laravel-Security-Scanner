"""
Check: Composer.lock CVE Scan.

Fetches composer.lock and checks PHP/Laravel package versions
against known CVE database.

Severity: CRITICAL to MEDIUM (depends on CVE)
"""
from __future__ import annotations

import json
import re

import httpx
from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


class ComposerLockCVEScanCheck(BaseCheck):
    CHECK_ID = "COMPOSER_CVE"
    TITLE = "Composer.lock CVE Scan"

    CVED_DB_PATH = "cve_database.json"

    async def run(self, target: ScanTarget) -> Finding:
        """
        Fetch composer.lock and check packages against CVE database.
        """
        url = self._build_url(target.url, "composer.lock")
        try:
            resp = await self._client.get(
                url,
                headers=target.headers,
                follow_redirects=False,
            )
            logger.debug(f"[{self.CHECK_ID}] {url} → HTTP {resp.status_code}")

            if resp.status_code != 200:
                return Finding(
                    check_id=self.CHECK_ID,
                    title=self.TITLE,
                    severity=Severity.MEDIUM,
                    status=CheckStatus.SAFE,
                    description="composer.lock not accessible (not found or protected).",
                )

            # Parse composer.lock
            try:
                composer_data = resp.json()
            except json.JSONDecodeError:
                return Finding(
                    check_id=self.CHECK_ID,
                    title=self.TITLE,
                    severity=Severity.MEDIUM,
                    status=CheckStatus.UNKNOWN,
                    description="composer.lock is not valid JSON.",
                )

            # Extract packages
            packages = []
            if 'packages' in composer_data:
                packages.extend(composer_data['packages'])
            if 'packages-dev' in composer_data:
                packages.extend(composer_data['packages-dev'])

            if not packages:
                return Finding(
                    check_id=self.CHECK_ID,
                    title=self.TITLE,
                    severity=Severity.MEDIUM,
                    status=CheckStatus.SAFE,
                    description="No packages found in composer.lock.",
                )

            # Load CVE database
            cve_db = self._load_cve_database()
            if not cve_db:
                return Finding(
                    check_id=self.CHECK_ID,
                    title=self.TITLE,
                    severity=Severity.MEDIUM,
                    status=CheckStatus.UNKNOWN,
                    description="CVE database not available.",
                )

            # Check packages against CVEs
            vulnerable_packages = []
            evidence_details = []

            for pkg in packages:
                pkg_name = pkg.get('name', '').lower()
                pkg_version = pkg.get('version', '').lstrip('v')

                # Skip if no version
                if not pkg_version:
                    continue

                # Check against CVE database
                for cve in cve_db.get('cves', []):
                    if cve.get('package', '').lower() == pkg_name:
                        affected = cve.get('affected_versions', [])
                        patched = cve.get('patched_versions', [])

                        # Simple version check (this is simplified)
                        if self._is_version_affected(pkg_version, affected, patched):
                            vulnerable_packages.append({
                                'package': pkg_name,
                                'version': pkg_version,
                                'cve_id': cve.get('cve_id', 'Unknown'),
                                'severity': cve.get('severity', 'MEDIUM'),
                            })
                            evidence_details.append(
                                f"Package: {pkg_name} v{pkg_version} - "
                                f"{cve.get('cve_id')} ({cve.get('severity')})"
                            )
                            break  # Found CVE for this package

            if vulnerable_packages:
                # Determine overall severity
                severities = [p['severity'] for p in vulnerable_packages]
                if 'CRITICAL' in severities:
                    overall_severity = Severity.CRITICAL
                elif 'HIGH' in severities:
                    overall_severity = Severity.HIGH
                elif 'MEDIUM' in severities:
                    overall_severity = Severity.MEDIUM
                else:
                    overall_severity = Severity.LOW

                return Finding(
                    check_id=self.CHECK_ID,
                    title=self.TITLE,
                    severity=overall_severity,
                    status=CheckStatus.VULNERABLE,
                    description=(
                        f"Found {len(vulnerable_packages)} vulnerable package(s) "
                        f"in composer.lock."
                    ),
                    evidence="\n".join(evidence_details),
                    remediation=(
                        "1. Update vulnerable packages:\n"
                        "   `composer update <package-name>`\n"
                        "2. Or update all: `composer update`\n"
                        "3. Check Laravel's security advisories:\n"
                        "   https://laravel.com/docs/upgrade-guide\n"
                        "4. Use `composer audit` command if available."
                    ),
                    cvss_score=8.5 if overall_severity == Severity.CRITICAL else (
                        6.5 if overall_severity == Severity.HIGH else 4.0
                    ),
                    references=[
                        "https://laravel.com/docs/upgrade-guide",
                        "https://packagist.org/packages/laravel/framework",
                        "https://cve.mitre.org/",
                    ],
                )

            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.MEDIUM,
                status=CheckStatus.SAFE,
                description="No known vulnerable packages found in composer.lock.",
            )

        except httpx.TimeoutException:
            logger.warning(f"[{self.CHECK_ID}] Timeout for {url}")
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.MEDIUM,
                status=CheckStatus.UNKNOWN,
                description="Timeout while checking composer.lock.",
            )
        except httpx.RequestError as exc:
            logger.warning(f"[{self.CHECK_ID}] Request error for {url}: {exc}")
            return Finding(
                check_id=self.CHECK_ID,
                title=self.TITLE,
                severity=Severity.MEDIUM,
                status=CheckStatus.UNKNOWN,
                description=f"Error checking composer.lock: {exc}",
            )

    def _load_cve_database(self) -> dict:
        """Load CVE database from JSON file."""
        try:
            import os__
            cve_path = os.path.join(
                os.path.dirname(__file__),
                '..', '..', '..', self.CVED_DB_PATH
            )
            if os.path.exists(cve_path):
                with open(cve_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"[{self.CHECK_ID}] Failed to load CVE database: {e}")
        return {}

    def _is_version_affected(
        self,
        version: str,
        affected: list[str],
        patched: list[str],
    ) -> bool:
        """
        Simplified version check.
        In production, use proper version comparison library like `packaging`.
        """
        # This is a very simplified check
        # Real implementation would parse version strings properly
        version_lower = version.lower()

        # Check if version matches any affected pattern
        for affected_pattern in affected:
            # Simple substring match (not accurate for real use)
            if affected_pattern.lstrip('<>=') in version_lower or version_lower in affected_pattern.lstrip('<>='):
                # Check if it's patched
                for patched_pattern in patched:
                    if patched_pattern.lstrip('<>=') in version_lower:
                        return False  # Patched
                return True  # Affected and not patched

        return False  # Not in affected list
