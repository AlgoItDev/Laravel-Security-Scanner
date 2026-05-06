"""
Unit tests for NovaExposedCheck.
"""
import pytest
import httpx

from app.models.scan import CheckStatus, Severity, ScanTarget
from app.services.checks.nova_exposed import NovaExposedCheck


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
class TestNovaExposedCheck:
    async def test_vulnerable_when_nova_accessible(self):
        """Test detection when Nova is accessible."""
        body = """
        <html>
        <head><title>Laravel Nova</title></head>
        <body>
        <div class="nova-dashboard">
            <h1>Laravel Nova</h1>
            <script src="/nova/js/app.js"></script>
        </div>
        </body>
        </html>
        """
        client = _make_client({"/nova": (200, body)})
        check = NovaExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.VULNERABLE
        assert finding.severity == Severity.HIGH
        assert "nova" in finding.description.lower()

    async def test_safe_when_nova_returns_404(self):
        """Test safe result when Nova endpoints return 404."""
        client = _make_client({})  # all → 404
        check = NovaExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.SAFE

    async def test_safe_when_200_but_not_nova(self):
        """Test safe when 200 but not Nova."""
        body = "<html><body>Normal page without Nova</body></html>"
        client = _make_client({"/nova": (200, body)})
        check = NovaExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        # Should be SAFE because not enough indicators
        assert finding.status == CheckStatus.SAFE

    async def test_handles_timeout(self):
        """Test graceful handling of timeout."""
        class TimeoutTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.TimeoutException("Timeout")
        
        client = httpx.AsyncClient(transport=TimeoutTransport())
        check = NovaExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        # Should not crash, but might return SAFE or SKIPPED
        assert finding.status in (CheckStatus.SAFE, CheckStatus.SKIPPED, CheckStatus.UNKNOWN)
