"""
Unit tests for MixManifestExposedCheck.
"""
import pytest
import httpx

from app.models.scan import CheckStatus, Severity, ScanTarget
from app.services.checks.mix_manifest_exposed import MixManifestExposedCheck


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


@pytest.mark.asyncio
class TestMixManifestExposedCheck:
    async def test_vulnerable_when_manifest_accessible(self):
        """Test detection when mix-manifest.json is accessible."""
        manifest_content = '{"app.js": "js/app.12345.js", "app.css": "css/app.67890.css"}'
        client = _make_client({"/mix-manifest.json": (200, manifest_content)})
        check = MixManifestExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.VULNERABLE
        assert finding.severity == Severity.LOW
        assert "mix-manifest" in finding.description.lower()

    async def test_safe_when_manifest_returns_404(self):
        """Test safe result when mix-manifest.json returns 404."""
        client = _make_client({})  # all → 404
        check = MixManifestExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.SAFE

    async def test_safe_when_200_but_not_manifest(self):
        """Test safe when 200 but not a valid manifest."""
        client = _make_client({"/mix-manifest.json": (200, "Not a manifest")})
        check = MixManifestExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        # Should be SAFE because it doesn't look like a manifest
        assert finding.status == CheckStatus.SAFE

    async def test_handles_timeout(self):
        """Test graceful handling of timeout."""
        class TimeoutTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.TimeoutException("Timeout")
        
        client = httpx.AsyncClient(transport=TimeoutTransport())
        check = MixManifestExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        # Should not crash, but might return SAFE or SKIPPED
        assert finding.status in (CheckStatus.SAFE, CheckStatus.SKIPPED, CheckStatus.UNKNOWN)
