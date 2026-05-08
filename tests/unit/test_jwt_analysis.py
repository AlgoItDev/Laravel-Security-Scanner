"""
Unit tests for JWTAnalysisCheck.
"""
import pytest
import httpx

from app.models.scan import CheckStatus, Severity, ScanTarget
from app.services.checks.jwt_analysis import JWTAnalysisCheck


def _make_client(responses: dict) -> httpx.AsyncClient:
    class MockTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            for pattern, resp_data in responses.items():
                if pattern in url_str:
                    if isinstance(resp_data, tuple) and len(resp_data) == 3:
                        status, body, headers = resp_data
                    else:
                        status, body = resp_data
                        headers = {}
                    h = httpx.Headers(headers) if headers else httpx.Headers()
                    return httpx.Response(status, text=body, headers=h)
            return httpx.Response(200, text='{"message":"ok"}')

    return httpx.AsyncClient(transport=MockTransport())


@pytest.mark.asyncio
class TestJWTAnalysisCheck:
    async def test_safe_when_no_jwt_found(self):
        client = _make_client({
            "/api": (200, '{"message":"ok"}')
        })
        check = JWTAnalysisCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.SAFE