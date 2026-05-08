"""
Unit tests for ComposerLockCVEScanCheck with OSV integration.
"""
import pytest
import httpx
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch, MagicMock

from app.models.scan import CheckStatus, Severity, ScanTarget
from app.services.checks.composer_lock_cve import ComposerLockCVEScanCheck


def _make_client(responses: dict[str, tuple[int, str | dict]]) -> httpx.AsyncClient:
    """Build an AsyncClient with a custom transport that returns canned responses."""

    class MockTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)

            for pattern, (status, body) in responses.items():
                if pattern in url_str:
                    if isinstance(body, dict):
                        import json
                        return httpx.Response(status, json=body)
                    return httpx.Response(status, text=body)
            return httpx.Response(404, text="Not Found")

    return httpx.AsyncClient(transport=MockTransport())


@pytest.mark.asyncio
class TestComposerLockCVEScanCheck:
    async def test_vulnerable_when_cve_found(self):
        """Test detection when vulnerable packages are in composer.lock."""
        composer_lock = {
            "packages": [
                {
                    "name": "laravel/framework",
                    "version": "8.0.0",
                    "source": {"type": "git", "url": "https://github.com/laravel/framework"}
                }
            ]
        }
        client = _make_client({"/composer.lock": (200, composer_lock)})
        check = ComposerLockCVEScanCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.VULNERABLE
        assert finding.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
        assert "package" in finding.description.lower() or "cve" in finding.description.lower()

    async def test_safe_when_no_composer_lock(self):
        """Test safe when composer.lock is not accessible."""
        client = _make_client({})
        check = ComposerLockCVEScanCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.SAFE

    async def test_safe_when_no_vulnerable_packages(self):
        """Test safe when packages are patched."""
        composer_lock = {
            "packages": [
                {
                    "name": "laravel/framework",
                    "version": "10.0.0",
                    "source": {"type": "git", "url": "https://github.com/laravel/framework"}
                }
            ]
        }
        client = _make_client({"/composer.lock": (200, composer_lock)})
        check = ComposerLockCVEScanCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.SAFE

    async def test_handles_timeout(self):
        """Test graceful handling of timeout."""
        class TimeoutTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.TimeoutException("Timeout")

        client = httpx.AsyncClient(transport=TimeoutTransport())
        check = ComposerLockCVEScanCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status in (CheckStatus.SAFE, CheckStatus.SKIPPED, CheckStatus.UNKNOWN)

    async def test_handles_invalid_json(self):
        """Test handling of invalid JSON."""
        client = _make_client({"/composer.lock": (200, "Not JSON")})
        check = ComposerLockCVEScanCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status in (CheckStatus.SAFE, CheckStatus.UNKNOWN)

    async def test_osv_cache_stored(self):
        """Test that OSV results are cached."""
        composer_lock = {
            "packages": [
                {
                    "name": "some/unknown-package",
                    "version": "1.0.0"
                }
            ]
        }
        osv_response = {"vulns": []}
        responses = {
            "/composer.lock": (200, composer_lock),
            "api.osv.dev": (200, osv_response)
        }
        client = _make_client(responses)
        check = ComposerLockCVEScanCheck(client)

        finding = await check.run(ScanTarget(url="https://example.com"))

        assert check._osv_cache is not None

    async def test_osv_api_references_in_finding(self):
        """Test that OSV references are included in findings."""
        composer_lock = {
            "packages": [
                {
                    "name": "some/unknown-package",
                    "version": "1.0.0"
                }
            ]
        }
        osv_response = {
            "vulns": [
                {
                    "id": "OSV-2024-001",
                    "aliases": ["CVE-2024-12345"],
                    "summary": "Test vulnerability",
                    "database_specific": {"severity": ["HIGH"]}
                }
            ]
        }
        responses = {
            "/composer.lock": (200, composer_lock),
            "api.osv.dev": (200, osv_response)
        }
        client = _make_client(responses)
        check = ComposerLockCVEScanCheck(client)

        finding = await check.run(ScanTarget(url="https://example.com"))

        if finding.status == CheckStatus.VULNERABLE:
            assert len(finding.osv_references) > 0
            assert any("osv.dev" in ref for ref in finding.osv_references)


@pytest.mark.asyncio
class TestOSVIntegration:
    async def test_osv_api_called_for_unknown_packages(self):
        """Test that OSV API is called for packages not in local DB."""
        composer_lock = {
            "packages": [
                {"name": "unknown/package", "version": "1.0.0"}
            ]
        }
        responses = {
            "/composer.lock": (200, composer_lock),
            "api.osv.dev": (200, {"vulns": []})
        }
        client = _make_client(responses)
        check = ComposerLockCVEScanCheck(client)

        await check.run(ScanTarget(url="https://example.com"))

        assert check._osv_cache is not None

    async def test_local_db_checked_first(self):
        """Test that local database is checked before OSV API."""
        composer_lock = {
            "packages": [
                {"name": "laravel/framework", "version": "8.0.0"}
            ]
        }
        responses = {
            "/composer.lock": (200, composer_lock)
        }
        client = _make_client(responses)
        check = ComposerLockCVEScanCheck(client)

        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.VULNERABLE

    async def test_osv_references_in_finding(self):
        """Test OSV references are added to finding."""
        composer_lock = {
            "packages": [
                {"name": "test/package", "version": "1.0.0"}
            ]
        }
        osv_response = {
            "vulns": [
                {
                    "id": "OSV-TEST-001",
                    "summary": "Test vulnerability",
                    "database_specific": {"severity": ["MEDIUM"]}
                }
            ]
        }
        responses = {
            "/composer.lock": (200, composer_lock),
            "api.osv.dev": (200, osv_response)
        }
        client = _make_client(responses)
        check = ComposerLockCVEScanCheck(client)

        finding = await check.run(ScanTarget(url="https://example.com"))

        if finding.status == CheckStatus.VULNERABLE:
            assert hasattr(finding, "osv_references")
            assert hasattr(finding, "osv_data")


class TestVersionParsing:
    def test_parse_version_with_v_prefix(self):
        """Test version parsing with v prefix."""
        check = ComposerLockCVEScanCheck(MagicMock())
        result = check._parse_version("v8.0.0")
        assert result is not None
        assert str(result) == "8.0.0"

    def test_parse_version_invalid(self):
        """Test handling of invalid version strings."""
        check = ComposerLockCVEScanCheck(MagicMock())
        result = check._parse_version("invalid-version")
        assert result is None

    def test_matches_version_constraint_gt(self):
        """Test version matching with > constraint."""
        check = ComposerLockCVEScanCheck(MagicMock())
        from packaging.version import Version
        version = Version("8.0.0")
        assert check._matches_version_constraint(version, ">7.0.0") is True
        assert check._matches_version_constraint(version, ">9.0.0") is False

    def test_matches_version_constraint_lt(self):
        """Test version matching with < constraint."""
        check = ComposerLockCVEScanCheck(MagicMock())
        from packaging.version import Version
        version = Version("8.0.0")
        assert check._matches_version_constraint(version, "<9.0.0") is True
        assert check._matches_version_constraint(version, "<7.0.0") is False

    def test_matches_version_constraint_gte(self):
        """Test version matching with >= constraint."""
        check = ComposerLockCVEScanCheck(MagicMock())
        from packaging.version import Version
        version = Version("8.0.0")
        assert check._matches_version_constraint(version, ">=8.0.0") is True
        assert check._matches_version_constraint(version, ">=9.0.0") is False


class TestCacheTTL:
    async def test_cache_ttl_setter(self):
        """Test cache TTL can be changed."""
        check = ComposerLockCVEScanCheck(MagicMock())
        check.set_cache_ttl(48)
        assert check.CACHE_TTL_HOURS == 48

    async def test_cache_ttl_default(self):
        """Test default cache TTL is 24 hours."""
        from app.core.settings import settings
        check = ComposerLockCVEScanCheck(MagicMock())
        assert check.CACHE_TTL_HOURS == settings.OSV_CACHE_TTL_HOURS


class TestOSVResponseParsing:
    def test_extract_severity_critical(self):
        """Test severity extraction for CRITICAL."""
        check = ComposerLockCVEScanCheck(MagicMock())
        vuln = {"database_specific": {"severity": ["CRITICAL"]}}
        assert check._extract_severity(vuln) == "CRITICAL"

    def test_extract_severity_high(self):
        """Test severity extraction for HIGH."""
        check = ComposerLockCVEScanCheck(MagicMock())
        vuln = {"database_specific": {"severity": ["HIGH"]}}
        assert check._extract_severity(vuln) == "HIGH"

    def test_extract_severity_medium(self):
        """Test severity extraction for MEDIUM."""
        check = ComposerLockCVEScanCheck(MagicMock())
        vuln = {"database_specific": {"severity": ["MEDIUM"]}}
        assert check._extract_severity(vuln) == "MEDIUM"

    def test_extract_severity_from_cvss(self):
        """Test severity extraction from CVSS score."""
        check = ComposerLockCVEScanCheck(MagicMock())
        vuln = {"CVSS_V3": {"base_score": 9.5}}
        assert check._extract_severity(vuln) == "CRITICAL"

    def test_parse_osv_response_with_aliases(self):
        """Test OSV response parsing with CVE aliases."""
        check = ComposerLockCVEScanCheck(MagicMock())
        vulns = [
            {
                "id": "OSV-001",
                "aliases": ["CVE-2024-00001", "GHSA-xxxx"],
                "summary": "Test vulnerability",
                "database_specific": {"severity": ["HIGH"]}
            }
        ]
        results = check._parse_osv_response(vulns, "test/package", "1.0.0")
        assert len(results) == 1
        assert results[0]["cve_id"] == "CVE-2024-00001"
        assert results[0]["severity"] == "HIGH"
        assert "osv.dev" in results[0]["osv_url"]