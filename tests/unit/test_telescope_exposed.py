"""
Unit tests for TelescopeExposedCheck.
"""
import pytest
import httpx

from app.models.scan import CheckStatus, Severity, ScanTarget
from app.services.checks.telescope_exposed import TelescopeExposedCheck


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
class TestTelescopeExposedCheck:
    async def test_vulnerable_when_telescope_accessible(self):
        """Test detection when Telescope is accessible with indicators."""
        body = """
        <html>
        <head><title>Telescope</title></head>
        <body>
        <div class="telescope">Laravel Telescope</div>
        <table>
            <tr><td class="request-path">/api/users</td></tr>
            <tr><td class="request-method">GET</td></tr>
            <tr><td class="response-status">200</td></tr>
        </table>
        </body>
        </html>
        """
        client = _make_client({"/telescope": (200, body)})
        check = TelescopeExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.VULNERABLE
        assert finding.severity == Severity.HIGH
        assert "telescope" in finding.description.lower()

    async def test_safe_when_telescope_returns_404(self):
        """Test safe result when Telescope endpoints return 404."""
        client = _make_client({})  # all → 404
        check = TelescopeExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.SAFE

    async def test_safe_when_telescope_returns_200_but_not_telescope(self):
        """Test safe when 200 but not Telescope (false positive check)."""
        body = "<html><body>Not Telescope</body></html>"
        client = _make_client({"/telescope": (200, body)})
        check = TelescopeExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        # Not enough indicators (needs at least 2)
        assert finding.status == CheckStatus.SAFE

    async def test_handles_timeout(self):
        """Test graceful handling of timeout."""
        class TimeoutTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.TimeoutException("Timeout")
        
        client = httpx.AsyncClient(transport=TimeoutTransport())
        check = TelescopeExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        # Should not crash, but might return SAFE or SKIPPED
        assert finding.status in (CheckStatus.SAFE, CheckStatus.SKIPPED, CheckStatus.UNKNOWN)