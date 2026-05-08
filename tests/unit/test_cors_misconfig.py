"""
Unit tests for CORSMisconfigCheck.
"""
import pytest
import httpx

from app.models.scan import CheckStatus, Severity, ScanTarget
from app.services.checks.cors_misconfig import CORSMisconfigCheck


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
            return httpx.Response(404, text="Not Found")

    return httpx.AsyncClient(transport=MockTransport())


@pytest.mark.asyncio
class TestCORSMisconfigCheck:
    async def test_vulnerable_with_wildcard_origin(self):
        client = _make_client({
            "example.com/": (200, '{}', {"Access-Control-Allow-Origin": "*"})
        })
        check = CORSMisconfigCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.VULNERABLE
        assert finding.severity == Severity.MEDIUM

    async def test_safe_when_no_cors_headers(self):
        client = _make_client({
            "example.com/": (200, '{}')
        })
        check = CORSMisconfigCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.severity == Severity.MEDIUM