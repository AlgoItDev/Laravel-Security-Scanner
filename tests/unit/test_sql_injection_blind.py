"""
Unit tests for SQLInjectionBlindCheck.
"""
import pytest
import httpx

from app.models.scan import CheckStatus, Severity, ScanTarget
from app.services.checks.sql_injection_blind import SQLInjectionBlindCheck


def _make_client(responses: dict[str, tuple[int, str]]) -> httpx.AsyncClient:
    class MockTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            for pattern, (status, body) in responses.items():
                if pattern in url_str:
                    return httpx.Response(status, text=body)
            return httpx.Response(404, text="Not Found")

    return httpx.AsyncClient(transport=MockTransport())


@pytest.mark.asyncio
class TestSQLInjectionBlindCheck:
    async def test_vulnerable_when_sqli_error_detected(self):
        body = "SQL syntax error near 'OR' at line 1"
        client = _make_client({
            "/?id=": (200, body)
        })
        check = SQLInjectionBlindCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.VULNERABLE
        assert finding.severity == Severity.CRITICAL

    async def test_safe_when_no_sqli_indicators(self):
        client = _make_client({
            "/?id=": (200, "Welcome to our website")
        })
        check = SQLInjectionBlindCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.SAFE

    async def test_safe_when_404(self):
        client = _make_client({})
        check = SQLInjectionBlindCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.SAFE