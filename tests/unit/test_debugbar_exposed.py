"""
Unit tests for DebugbarExposedCheck.
"""
import pytest
import httpx
from unittest.mock import AsyncMock

from app.models.scan import CheckStatus, Severity, ScanTarget
from app.services.checks.debugbar_exposed import DebugbarExposedCheck


class MockTransport(httpx.AsyncBaseTransport):
    """Custom transport that returns different responses based on URL path."""
    
    def __init__(self, debugbar_endpoints_status=404, main_page_body="", main_page_status=200):
        self.debugbar_endpoints_status = debugbar_endpoints_status
        self.main_page_body = main_page_body
        self.main_page_status = main_page_status
    
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        path = request.url.path
        
        # Check if this is a Debugbar endpoint
        if path in ["/_debugbar", "/_debugbar/clockwork", "/debugbar"]:
            if self.debugbar_endpoints_status == 200:
                return httpx.Response(200, text='<html><div class="phpdebugbar"></div></html>')
            else:
                return httpx.Response(404, text="Not Found")
        else:
            # Main page request
            return httpx.Response(self.main_page_status, text=self.main_page_body)


@pytest.mark.asyncio
class TestDebugbarExposedCheck:
    async def test_vulnerable_when_debugbar_endpoint_accessible(self):
        """Test detection when Debugbar endpoint is accessible."""
        client = httpx.AsyncClient(transport=MockTransport(debugbar_endpoints_status=200))
        check = DebugbarExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.VULNERABLE
        assert finding.severity == Severity.MEDIUM
        assert "debugbar" in finding.description.lower()

    async def test_vulnerable_when_debugbar_in_page_html(self):
        """Test detection when Debugbar is embedded in main page."""
        body = """
        <html>
        <head><title>My Laravel App</title></head>
        <body>
        <h1>Welcome</h1>
        <script src="/_debugbar/assets/debugbar.js"></script>
        <div class="phpdebugbar-open"></div>
        </body>
        </html>
        """
        # Debugbar endpoints return 404, but main page has Debugbar indicators
        client = httpx.AsyncClient(transport=MockTransport(
            debugbar_endpoints_status=404,
            main_page_body=body,
            main_page_status=200
        ))
        check = DebugbarExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.VULNERABLE
        assert "embedded" in finding.evidence.lower() or "page" in finding.evidence.lower()

    async def test_safe_when_debugbar_returns_404(self):
        """Test safe result when Debugbar endpoints return 404."""
        client = httpx.AsyncClient(transport=MockTransport(debugbar_endpoints_status=404))
        check = DebugbarExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.SAFE

    async def test_safe_when_no_debugbar_indicators(self):
        """Test safe when page has no Debugbar indicators."""
        body = "<html><body>Normal page without debugging tools</body></html>"
        client = httpx.AsyncClient(transport=MockTransport(
            debugbar_endpoints_status=404,
            main_page_body=body,
            main_page_status=200
        ))
        check = DebugbarExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.SAFE

    async def test_handles_timeout(self):
        """Test graceful handling of timeout."""
        class TimeoutTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.TimeoutException("Timeout")
        
        client = httpx.AsyncClient(transport=TimeoutTransport())
        check = DebugbarExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        # Should not crash, but might return SAFE or SKIPPED
        assert finding.status in (CheckStatus.SAFE, CheckStatus.SKIPPED, CheckStatus.UNKNOWN)
