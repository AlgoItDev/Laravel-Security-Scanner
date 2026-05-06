"""
Unit tests for SessionSecurityCheck.
"""
import pytest
import httpx

from app.models.scan import CheckStatus, Severity, ScanTarget
from app.services.checks.session_security import SessionSecurityCheck


def _make_client(responses: dict[str, tuple[int, str, dict]]) -> httpx.AsyncClient:
    """Build an AsyncClient with a custom transport that returns canned responses."""
    
    class MockTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            for pattern, (status, body, headers) in responses.items():
                if pattern in url_str:
                    return httpx.Response(status, text=body, headers=headers)
            return httpx.Response(404, text="Not Found")
    
    return httpx.AsyncClient(transport=MockTransport())


@pytest.mark.asyncio
class TestSessionSecurityCheck:
    async def test_vulnerable_all_flags_missing(self):
        """Test detection when all security flags are missing."""
        headers = {
            "Set-Cookie": "laravel_session=abc123; path=/"
        }
        client = _make_client({"/": (200, "Welcome", headers)})
        check = SessionSecurityCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.VULNERABLE
        assert finding.severity == Severity.HIGH
        assert "secure" in finding.description.lower() or "flag" in finding.description.lower()

    async def test_vulnerable_partial_flags(self):
        """Test detection when some flags are missing."""
        headers = {
            "Set-Cookie": "laravel_session=abc123; secure; path=/"
            # Missing httponly and samesite
        }
        client = _make_client({"/": (200, "Welcome", headers)})
        check = SessionSecurityCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.VULNERABLE
        assert finding.severity == Severity.MEDIUM

    async def test_safe_with_all_flags(self):
        """Test safe when all security flags are present."""
        headers = {
            "Set-Cookie": "laravel_session=abc123; secure; httponly; samesite=lax; path=/"
        }
        client = _make_client({"/": (200, "Welcome", headers)})
        check = SessionSecurityCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.SAFE

    async def test_safe_no_session_cookie(self):
        """Test safe when no session cookie (might be token-based auth)."""
        client = _make_client({"/": (200, "Welcome", {})})
        check = SessionSecurityCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status == CheckStatus.SAFE

    async def test_handles_timeout(self):
        """Test graceful handling of timeout."""
        class TimeoutTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.TimeoutException("Timeout")
        
        client = httpx.AsyncClient(transport=TimeoutTransport())
        check = SessionSecurityCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))
        
        assert finding.status in (CheckStatus.SAFE, CheckStatus.UNKNOWN, CheckStatus.SKIPPED)
