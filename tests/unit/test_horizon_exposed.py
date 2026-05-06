"""
Unit tests for HorizonExposedCheck.
"""
import pytest
import httpx

from app.models.scan import CheckStatus, Severity, ScanTarget
from app.services.checks.horizon_exposed import HorizonExposedCheck


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
class TestHorizonExposedCheck:
    async def test_vulnerable_when_horizon_accessible(self):
        """Test detection when Horizon is accessible."""
        body = """
        <html>
        <head><title>Horizon</title></head>
        <body>
        <div class="horizon-dashboard">
            <h1>Laravel Horizon</h1>
            <p>Queue metrics and job monitoring</p>
        </div>
        <script src="/horizon/js/app.js"></script>
        </body>
        </html>
        """
        client = _make_client({"/horizon": (200, body)})
        check = HorizonExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.VULNERABLE
        assert finding.severity == Severity.MEDIUM
        assert "horizon" in finding.description.lower()

    async def test_safe_when_horizon_returns_404(self):
        """Test safe result when Horizon endpoints return 404."""
        client = _make_client({})  # all → 404
        check = HorizonExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.SAFE

    async def test_safe_when_200_but_not_horizon(self):
        """Test safe when 200 but not Horizon."""
        body = "<html><body>Normal page without Horizon</body></html>"
        client = _make_client({"/horizon": (200, body)})
        check = HorizonExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        # Should be SAFE because not enough indicators
        assert finding.status == CheckStatus.SAFE

    async def test_handles_timeout(self):
        """Test graceful handling of timeout."""
        class TimeoutTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.TimeoutException("Timeout")
        
        client = httpx.AsyncClient(transport=TimeoutTransport())
        check = HorizonExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        # Should not crash, but might return SAFE or SKIPPED
        assert finding.status in (CheckStatus.SAFE, CheckStatus.SKIPPED, CheckStatus.UNKNOWN)
