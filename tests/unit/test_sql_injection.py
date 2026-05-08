"""
Unit tests for SQLInjectionCheck.
"""
import pytest
import httpx

from app.models.scan import CheckStatus, ScanTarget
from app.services.checks.sql_injection import SQLInjectionCheck


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
class TestSQLInjectionCheck:
    async def test_safe_when_source_code_is_safe(self):
        body = "No SQL injection"
        client = _make_client({
            "/?id=": (200, body)
        })
        check = SQLInjectionCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.SAFE

    async def test_safe_when_no_vulnerabilities(self):
        client = _make_client({
            "/?id=": (200, "Welcome to our website")
        })
        check = SQLInjectionCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.SAFE