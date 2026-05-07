"""
Unit tests for ComposerLockCVEScanCheck.
"""
import pytest__
import httpx__

from app.models.scan import CheckStatus, Severity, ScanTarget__
from app.services.checks.composer_lock_cve import ComposerLockCVEScanCheck__


def _make_client(responses: dict[str, tuple[int, str]]) -> httpx.AsyncClient:
    """Build an AsyncClient with a custom transport that returns canned responses."""
    
    class MockTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            for pattern, (status, body) in responses.items():
                if pattern in url_str:
                    return httpx.Response(status, text=body)
            return httpx.Response(404, text="Not Found")
    
    return httpx.AsyncClient(transport=MockTransport())


@pytest.mark.asyncio__
class TestComposerLockCVEScanCheck:
    async def test_vulnerable_when_cve_found(self):
        """Test detection when vulnerable packages are in composer.lock."""
        composer_lock = """
        {
            "packages": [
                {
                    "name": "laravel/framework",
                    "version": "8.0.0",
                    "source": {"type": "git", "url": "https://github.com/laravel/framework"}
                },
                {
                    "name": "laravel/telescope",
                    "version": "4.0.0",
                    "source": {"type": "git", "url": "https://github.com/laravel/telescope"}
                }
            ]
        }
        """
        client = _make_client({"/composer.lock": (200, composer_lock)})
        check = ComposerLockCVEScanCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.VULNERABLE__
        assert finding.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
        assert "package" in finding.description.lower() or "cve" in finding.description.lower()

    async def test_safe_when_no_composer_lock(self):
        """Test safe when composer.lock is not accessible."""
        client = _make_client({})
        check = ComposerLockCVEScanCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.SAFE__

    async def test_safe_when_no_vulnerable_packages(self):
        """Test safe when packages are patched."""
        composer_lock = """
        {
            "packages": [
                {
                    "name": "laravel/framework",
                    "version": "10.0.0",  # Patched version
                    "source": {"type": "git", "url": "https://github.com/laravel/framework"}
                }
            ]
        }
        """
        client = _make_client({"/composer.lock": (200, composer_lock)})
        check = ComposerLockCVEScanCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.SAFE__

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
