"""
Unit tests for SubdomainEnumCheck.
"""
import pytest
import httpx

from app.models.scan import CheckStatus, Severity, ScanTarget
from app.services.checks.subdomain_enum import SubdomainEnumCheck


def _make_client(responses: dict[str, tuple[int, str]]) -> httpx.AsyncClient:
    class MockTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            for pattern, (status, body) in responses.items():
                if pattern in url_str:
                    return httpx.Response(status, text=body)
            return httpx.Response(500, text="Server Error")

    return httpx.AsyncClient(transport=MockTransport())


@pytest.mark.asyncio
class TestSubdomainEnumCheck:
    async def test_vulnerable_when_subdomains_found(self):
        client = _make_client({
            "api.example.com": (200, '{"status":"ok"}'),
            "dev.example.com": (200, '{"version":"dev"}'),
        })
        check = SubdomainEnumCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.VULNERABLE
        assert finding.severity == Severity.INFO

    async def test_safe_when_no_subdomains_found(self):
        client = _make_client({})
        check = SubdomainEnumCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.SAFE