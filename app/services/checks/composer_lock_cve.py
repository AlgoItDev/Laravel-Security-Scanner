"""
Check: Composer.lock CVE Scan with OSV API Integration.

Fetches composer.lock and checks PHP/Laravel package versions
against known CVE database (local + OSV API hybrid approach).

Severity: CRITICAL to MEDIUM (depends on CVE)
"""
from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from packaging.version import InvalidVersion, parse as parse_version
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.specifiers import Specifier

from app.core.logging import logger
from app.core.settings import settings
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck


class ComposerLockCVEScanCheck(BaseCheck):
    CHECK_ID = "COMPOSER_CVE"
    TITLE = "Composer.lock CVE Scan"

    CVED_DB_PATH = "cve_database.json"
    OSV_API_URL = settings.OSV_API_URL
    OSV_ECOSYSTEM = settings.OSV_ECOSYSTEM
    CACHE_TTL_HOURS = settings.OSV_CACHE_TTL_HOURS

    _osv_cache: dict[str, dict] | None = None

    async def run(self, target: ScanTarget) -> Finding:
        url = self._build_url(target.url, "composer.lock")
        try:
            resp = await self._client.get(
                url,
                headers=target.headers,
                follow_redirects=False,
            )
            logger.debug(f"[{self.CHECK_ID}] {url} -> HTTP {resp.status_code}")

            if resp.status_code != 200:
                return Finding(
                    check_id=self.CHECK_ID,
                    title=self.TITLE,
                    severity=Severity.MEDIUM,
                    status=CheckStatus.SAFE,
                    description="composer.lock not accessible (not found or protected).",
                )

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

            packages = []
            if "packages" in composer_data:
                packages.extend(composer_data["packages"])
            if "packages-dev" in composer_data:
                packages.extend(composer_data["packages-dev"])

            if not packages:
                return Finding(
                    check_id=self.CHECK_ID,
                    title=self.TITLE,
                    severity=Severity.MEDIUM,
                    status=CheckStatus.SAFE,
                    description="No packages found in composer.lock.",
                )

            cve_db = self._load_cve_database()
            self._load_osv_cache()

            vulnerable_packages = []
            evidence_details = []
            osv_references = []
            osv_data = []

            for pkg in packages:
                pkg_name = pkg.get("name", "").lower()
                pkg_version = pkg.get("version", "").lstrip("v")

                if not pkg_version:
                    continue

                local_vulns = self._check_local_db(pkg_name, pkg_version, cve_db)
                if local_vulns:
                    vulnerable_packages.extend(local_vulns)
                    for v in local_vulns:
                        evidence_details.append(
                            f"Package: {v['package']} v{v['version']} - {v['cve_id']} ({v['severity']}) "
                            f"[LOCAL DB]"
                        )
                    continue

                osv_vulns = await self._check_osv_vulnerabilities(pkg_name, pkg_version)
                if osv_vulns:
                    vulnerable_packages.extend(osv_vulns)
                    for v in osv_vulns:
                        evidence_details.append(
                            f"Package: {v['package']} v{v['version']} - {v['cve_id']} ({v['severity']}) "
                            f"[OSV API]"
                        )
                    if v.get("osv_url"):
                        osv_references.append(v["osv_url"])
                    if v.get("osv_entry"):
                        osv_data.append(v["osv_entry"])

            self._save_osv_cache()

            if vulnerable_packages:
                severities = [p["severity"] for p in vulnerable_packages]
                if "CRITICAL" in severities:
                    overall_severity = Severity.CRITICAL
                elif "HIGH" in severities:
                    overall_severity = Severity.HIGH
                elif "MEDIUM" in severities:
                    overall_severity = Severity.MEDIUM
                else:
                    overall_severity = Severity.LOW

                base_refs = [
                    "https://laravel.com/docs/upgrade-guide",
                    "https://packagist.org/packages/laravel/framework",
                    "https://cve.mitre.org/",
                ]
                all_refs = list(set(base_refs + osv_references))

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
                        "4. Use `composer audit` command if available.\n"
                        "5. Review vulnerabilities at: https://osv.dev"
                    ),
                    cvss_score=8.5
                    if overall_severity == Severity.CRITICAL
                    else (6.5 if overall_severity == Severity.HIGH else 4.0),
                    references=all_refs,
                    osv_references=osv_references,
                    osv_data=osv_data,
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
        try:
            cve_path = Path(__file__).parent.parent.parent.parent / self.CVED_DB_PATH
            if cve_path.exists():
                with open(cve_path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"[{self.CHECK_ID}] Failed to load CVE database: {e}")
        return {}

    def _load_osv_cache(self) -> None:
        if self._osv_cache is not None:
            return

        self._osv_cache = {}
        cache_path = Path(self.CVED_DB_PATH).parent.parent / settings.OSV_CACHE_FILE
        cache_path = cache_path.parent.parent / settings.OSV_CACHE_FILE

        if cache_path.exists():
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    raw_cache = json.load(f)
                    ttl_hours = self.CACHE_TTL_HOURS
                    cutoff = datetime.now(timezone.utc) - timedelta(hours=ttl_hours)

                    for key, entry in raw_cache.items():
                        if isinstance(entry, dict) and entry.get("timestamp"):
                            entry_time = datetime.fromisoformat(entry["timestamp"])
                            if entry_time > cutoff:
                                self._osv_cache[key] = entry
            except Exception as e:
                logger.warning(f"[{self.CHECK_ID}] Failed to load OSV cache: {e}")

    def _save_osv_cache(self) -> None:
        if self._osv_cache is None:
            return

        cache_path = Path(settings.OSV_CACHE_FILE).resolve()
        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(self._osv_cache, f, indent=2)
            logger.debug(f"[{self.CHECK_ID}] OSV cache saved to {cache_path}")
        except Exception as e:
            logger.warning(f"[{self.CHECK_ID}] Failed to save OSV cache: {e}")

    async def _query_osv_api(self, package: str, version: str) -> dict | None:
        payload = {"package": {"name": package, "ecosystem": self.OSV_ECOSYSTEM}, "version": version}

        try:
            resp = await self._client.post(
                self.OSV_API_URL, json=payload, timeout=15.0, headers={"Content-Type": "application/json"}
            )

            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 429:
                logger.warning(f"[{self.CHECK_ID}] OSV API rate limited, using local DB fallback")
                time.sleep(1)
            else:
                logger.warning(f"[{self.CHECK_ID}] OSV API returned {resp.status_code}")

        except httpx.TimeoutException:
            logger.warning(f"[{self.CHECK_ID}] OSV API timeout for {package}@{version}")
        except httpx.RequestError as exc:
            logger.warning(f"[{self.CHECK_ID}] OSV API request error for {package}: {exc}")

        return None

    async def _check_osv_vulnerabilities(self, package: str, version: str) -> list[dict]:
        cache_key = f"{package}@{version}"

        if cache_key in self._osv_cache:
            cached = self._osv_cache[cache_key]
            if cached.get("vulnerabilities"):
                logger.debug(f"[{self.CHECK_ID}] OSV cache hit for {cache_key}")
                return self._parse_osv_response(cached["vulnerabilities"], package, version)
            return []

        result = await self._query_osv_api(package, version)

        if result:
            vulns = result.get("vulns", [])
            self._osv_cache[cache_key] = {"timestamp": datetime.now(timezone.utc).isoformat(), "vulnerabilities": vulns}

            if vulns:
                logger.info(f"[{self.CHECK_ID}] Found {len(vulns)} OSV vulnerabilities for {cache_key}")

            return self._parse_osv_response(vulns, package, version)

        self._osv_cache[cache_key] = {"timestamp": datetime.now(timezone.utc).isoformat(), "vulnerabilities": []}
        return []

    def _parse_osv_response(self, vulns: list[dict], package: str, version: str) -> list[dict]:
        results = []
        for vuln in vulns:
            cve_id = None
            for alias in vuln.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break

            if not cve_id:
                cve_id = vuln.get("id", "Unknown")

            severity = self._extract_severity(vuln)
            osv_url = f"https://osv.dev/vulnerability/{vuln.get('id', '')}"

            results.append(
                {
                    "package": package,
                    "version": version,
                    "cve_id": cve_id,
                    "severity": severity,
                    "description": vuln.get("summary", ""),
                    "osv_url": osv_url,
                    "osv_entry": vuln,
                }
            )

        return results

    def _extract_severity(self, vuln: dict) -> str:
        severity = "MEDIUM"

        for db in vuln.get("database_specific", {}).get("severity", []):
            if "CRITICAL" in db.upper():
                return "CRITICAL"
            elif "HIGH" in db.upper():
                severity = "HIGH"

        for sev in ["CVSS_V3", "CVSS_V2"]:
            if sev in vuln:
                cvss = vuln[sev]
                if isinstance(cvss, dict):
                    base_score = cvss.get("base_score", 0)
                    if base_score >= 9.0:
                        return "CRITICAL"
                    elif base_score >= 7.0:
                        severity = "HIGH"
                    elif base_score >= 4.0:
                        severity = "MEDIUM"

        return severity

    def _check_local_db(self, pkg_name: str, pkg_version: str, cve_db: dict) -> list[dict]:
        results = []
        for cve in cve_db.get("cves", []):
            if cve.get("package", "").lower() == pkg_name:
                affected = cve.get("affected_versions", [])
                patched = cve.get("patched_versions", [])

                if self._is_version_affected(pkg_version, affected, patched):
                    results.append(
                        {
                            "package": pkg_name,
                            "version": pkg_version,
                            "cve_id": cve.get("cve_id", "Unknown"),
                            "severity": cve.get("severity", "MEDIUM"),
                        }
                    )
                    break

        return results

    def _is_version_affected(self, version: str, affected: list[str], patched: list[str]) -> bool:
        parsed = self._parse_version(version)
        if parsed is None:
            return False

        for patched_pattern in patched:
            if self._matches_version_constraint(parsed, patched_pattern):
                return False

        for affected_pattern in affected:
            if self._matches_version_constraint(parsed, affected_pattern):
                return True

        return False

    def _parse_version(self, version: str) -> packaging.version.Version | None:
        try:
            cleaned = version.lstrip("v").split("-")[0]
            return parse_version(cleaned)
        except InvalidVersion:
            return None

    def _matches_version_constraint(self, version: packaging.version.Version, constraint: str) -> bool:
        try:
            constraint = constraint.strip()
            if constraint.startswith(">="):
                spec = SpecifierSet(f">={constraint[2:]}")
            elif constraint.startswith("<="):
                spec = SpecifierSet(f"<={constraint[2:]}")
            elif constraint.startswith(">"):
                spec = SpecifierSet(f">{constraint[1:]}")
            elif constraint.startswith("<"):
                spec = SpecifierSet(f"<{constraint[1:]}")
            elif constraint.startswith("="):
                spec = SpecifierSet(f"=={constraint[1:]}")
            else:
                spec = SpecifierSet(constraint)

            return version in spec
        except (InvalidSpecifier, ValueError):
            return constraint.lstrip("<>=") in str(version)

    def set_cache_ttl(self, hours: int) -> None:
        self.CACHE_TTL_HOURS = hours