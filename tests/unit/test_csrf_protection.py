"""
Unit tests for CSRFProtectionCheck.
"""
import pytest
import httpx

from app.models.scan import CheckStatus, Severity, ScanTarget
from app.services.checks.csrf_protection import CSRFProtectionCheck


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
class TestCSRFProtectionCheck:
    async def test_vulnerable_when_form_without_token(self):
        """Test detection when forms without CSRF token exist."""
        body = """
        <html>
        <form method="POST" action="/submit">
            <input type="text" name="name">
            <input type="submit" value="Submit">
        </form>
        </html>
        """
        client = _make_client({"example.com": (200, body)})
        check = CSRFProtectionCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.VULNERABLE
        assert finding.severity == Severity.HIGH
        assert "csrf" in finding.description.lower() or "form" in finding.description.lower()

    async def test_safe_when_forms_have_tokens(self):
        """Test safe when forms have CSRF tokens and meta tag."""
        body = """
        <html>
        <meta name="csrf-token" content="abc123">
        <form method="POST" action="/submit">
            <input type="hidden" name="_token" value="abc123">
            <input type="text" name="name">
            <input type="submit" value="Submit">
        </form>
        </html>
        """
        client = _make_client({"example.com": (200, body)})
        check = CSRFProtectionCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.SAFE

    async def test_safe_when_only_get_forms(self):
        """Test safe when only GET forms (no CSRF needed)."""
        body = """
        <html>
        <form method="GET" action="/search">
            <input type="text" name="q">
            <input type="submit" value="Search">
        </form>
        </html>
        """
        client = _make_client({"example.com": (200, body)})
        check = CSRFProtectionCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.SAFE

    async def test_handles_timeout(self):
        """Test graceful handling of timeout."""
        class TimeoutTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                raise httpx.TimeoutException("Timeout")

        client = httpx.AsyncClient(transport=TimeoutTransport())
        check = CSRFProtectionCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status in (CheckStatus.SAFE, CheckStatus.UNKNOWN, CheckStatus.SKIPPED)