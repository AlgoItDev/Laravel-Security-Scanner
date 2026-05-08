"""
Unit tests for HTTPMethodsCheck.
"""
import pytest
import httpx

from app.models.scan import CheckStatus, Severity, ScanTarget
from app.services.checks.http_methods import HTTPMethodsCheck


def _make_client(responses: dict[tuple[str, str], int]) -> httpx.AsyncClient:
    """Build an AsyncClient with a custom transport that returns canned responses.

    Args:
        responses: Dict of (method, url_pattern) -> status_code
    """

    class MockTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            method = request.method
            for (m, pattern), status in responses.items():
                if m == method and pattern in url_str:
                    return httpx.Response(status, text="Response")
            return httpx.Response(404, text="Not Found")

    return httpx.AsyncClient(transport=MockTransport())


@pytest.mark.asyncio
class TestHTTPMethodsCheck:
    async def test_vulnerable_when_dangerous_methods_allowed(self):
        """Test detection when dangerous methods are accessible."""
        responses = {
            ("PUT", "example.com"): 200,
            ("DELETE", "example.com"): 200,
            ("TRACE", "example.com"): 200,
            ("PATCH", "example.com"): 200,
            ("GET", "example.com"): 200,
        }
        client = _make_client(responses)
        check = HTTPMethodsCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.VULNERABLE
        assert finding.severity == Severity.MEDIUM
        assert "method" in finding.description.lower()

    async def test_safe_when_methods_not_allowed(self):
        """Test safe when dangerous methods return 405/403."""
        responses = {
            ("PUT", "example.com"): 405,
            ("DELETE", "example.com"): 405,
            ("TRACE", "example.com"): 405,
            ("PATCH", "example.com"): 405,
            ("GET", "example.com"): 200,
        }
        client = _make_client(responses)
        check = HTTPMethodsCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.SAFE

    async def test_safe_when_methods_return_404(self):
        """Test safe when dangerous methods return 404."""
        responses = {
            ("PUT", "example.com"): 404,
            ("DELETE", "example.com"): 404,
            ("TRACE", "example.com"): 404,
            ("PATCH", "example.com"): 404,
            ("GET", "example.com"): 200,
        }
        client = _make_client(responses)
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