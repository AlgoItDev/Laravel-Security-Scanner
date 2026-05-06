"""
Unit tests for LaravelVersionCheck.
"""
import pytest
import httpx
from unittest.mock import AsyncMock, patch

from app.models.scan import CheckStatus, Severity, ScanTarget
from app.services.checks.laravel_version import LaravelVersionCheck


def _make_client(responses: dict[str, tuple[int, str, dict]]) -> httpx.AsyncClient:
    """Build an AsyncClient with a custom transport that returns canned responses."""
    
    class MockTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            for pattern, (status, body, headers) in responses.items():
                if pattern in url_str:
                    return httpx.Response(status, text=body, headers=headers)
            return httpx.Response(404, text="Not Found", headers={})
    
    return httpx.AsyncClient(transport=MockTransport())


@pytest.mark.asyncio
class TestLaravelVersionCheck:
    async def test_vulnerable_when_version_in_header(self):
        """Test detection of Laravel version in X-Powered-By header."""
        headers = {"x-powered-by": "PHP/8.0, Laravel 8.0.0"}
        client = _make_client({"": (200, "OK", headers)})
        check = LaravelVersionCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.VULNERABLE
        assert finding.severity == Severity.MEDIUM
        assert "8.0.0" in finding.description
        assert "Header: x-powered-by" in finding.evidence

    async def test_vulnerable_when_version_in_response_body(self):
        """Test detection of Laravel version in response body."""
        body = "<html>Laravel Framework 9.2.0</html>"
        client = _make_client({"": (200, body, {})})
        check = LaravelVersionCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.VULNERABLE
        assert finding.severity == Severity.MEDIUM
        assert "9.2.0" in finding.description
        assert "Response Body" in finding.evidence

    async def test_vulnerable_when_laravel_header_present_no_version(self):
        """Test detection when Laravel header present but no version."""
        headers = {"x-powered-by": "Laravel"}
        client = _make_client({"": (200, "OK", headers)})
        check = LaravelVersionCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.VULNERABLE
        assert finding.severity == Severity.LOW
        assert "unknown" in finding.description
        assert "Header: x-powered-by" in finding.evidence

    async def test_safe_when_no_version_disclosed(self):
        """Test safe result when no version information is disclosed."""
        headers = {"x-powered-by": "PHP/8.0"}
        client = _make_client({"": (200, "OK", headers)})
        check = LaravelVersionCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.SAFE
        assert finding.severity == Severity.LOW
        assert "No Laravel version disclosure detected" in finding.description

    async def test_handles_request_errors(self):
        """Test graceful handling of request errors."""
        # This simulates a connection error
        class ErrorTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.RequestError("Connection failed")
        
        client = httpx.AsyncClient(transport=ErrorTransport())
        check = LaravelVersionCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.UNKNOWN
        assert "Error while checking for Laravel version" in finding.description