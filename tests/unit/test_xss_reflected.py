"""
Unit tests for XSSReflectedCheck.
"""
import pytest
import httpx

from app.models.scan import CheckStatus, Severity, ScanTarget
from app.services.checks.xss_reflected import XSSReflectedCheck


def _make_client(responses: dict[str, tuple[int, str]]) -> httpx.AsyncClient:
    class MockTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            for pattern, (status, body) in responses.items():
                if pattern in url_str or pattern.replace("/", "") in url_str.replace("/", ""):
                    return httpx.Response(status, text=body)
            return httpx.Response(404, text="Not Found")

    return httpx.AsyncClient(transport=MockTransport())


@pytest.mark.asyncio
class TestXSSReflectedCheck:
    async def test_safe_when_properly_encoded(self):
        body = "Search results for: &lt;script&gt;alert(1)&lt;/script&gt;"
        client = _make_client({
            "?q=": (200, body)
        })
        check = XSSReflectedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.SAFE

    async def test_safe_when_no_reflection(self):
        client = _make_client({
            "?q=": (200, "No results found")
        })
        check = XSSReflectedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.SAFE