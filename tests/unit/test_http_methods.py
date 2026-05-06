"""
Unit tests for HTTPMethodsCheck.
"""
import pytest
import httpx

from app.models.scan import CheckStatus, Severity, ScanTarget
from app.services.checks.http_methods import HTTPMethodsCheck


def _make_client(responses: dict[str, tuple[int, str]]) -> httpx.AsyncClient:
    """Build an AsyncClient with a custom transport that returns canned responses."""
    
    class MockTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            method = request.method
            for pattern, (status, body) in responses.items():
                if pattern in url_str:
                    # Return different status for dangerous methods
                    if method in ["PUT", "DELETE", "TRACE"]:
                        return httpx.Response(200, text="Method allowed")
                    return httpx.Response(status, text=body)
            return httpx.Response(404, text="Not Found")
    
    return httpx.AsyncClient(transport=MockTransport())


@pytest.mark.asyncio
class TestHTTPMethodsCheck:
    async def test_vulnerable_when_dangerous_methods_allowed(self):
        """Test detection when dangerous methods are accessible."""
        client = _make_client({"/": (200, "OK")})
        check = HTTPMethodsCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.VULNERABLE
        assert finding.severity == Severity.MEDIUM
        assert "method" in finding.description.lower()

    async def test_safe_when_methods_not_allowed(self):
        """Test safe when dangerous methods return 405/403."""
        # Mock transport that returns 405 for dangerous methods
        class MockTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                if request.method in ["PUT", "DELETE", "TRACE"]:
                    return httpx.Response(405, text="Method Not Allowed")
                return httpx.Response(200, text="OK")
        
        client = httpx.AsyncClient(transport=MockTransport())
        check = HTTPMethodsCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.SAFE

    async def test_safe_when_methods_return_404(self):
        """Test safe when dangerous methods return 404."""
        class MockTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                if request.method in ["PUT", "DELETE", "TRACE"]:
                    return httpx.Response(404, text="Not Found")
                return httpx.Response(200, text="OK")
        
        client = httpx.AsyncClient(transport=MockTransport())
        check = HTTPMethodsCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.SAFE

    async def test_handles_timeout(self):
        """Test graceful handling of timeout."""
        class TimeoutTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.TimeoutException("Timeout")
        
        client = httpx.AsyncClient(transport=TimeoutTransport())
        check = HTTPMethodsCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status in (CheckStatus.SAFE, CheckStatus.UNKNOWN, CheckStatus.SKIPPED)
