"""
Unit tests for EnvExposedCheck.
Uses httpx mock transport — no real HTTP calls.
"""
import pytest
import httpx
from unittest.mock import AsyncMock, patch

from app.models.scan import CheckStatus, Severity, ScanTarget
from app.services.checks.env_exposed import EnvExposedCheck


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
class TestEnvExposedCheck:
    async def test_vulnerable_when_env_exposed(self):
        body = "APP_KEY=base64:abc123\nAPP_ENV=production\nDB_PASSWORD=secret"
        client = _make_client({".env": (200, body)})
        check = EnvExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.VULNERABLE
        assert finding.severity == Severity.CRITICAL
        assert ".env" in finding.description

    async def test_safe_when_env_returns_404(self):
        client = _make_client({})  # all → 404
        check = EnvExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.SAFE

    async def test_safe_when_200_but_no_signatures(self):
        # Imagine a CMS 200 page with no env content
        client = _make_client({".env": (200, "<html>Not Found</html>")})
        check = EnvExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.status == CheckStatus.SAFE

    async def test_evidence_is_redacted(self):
        body = "APP_KEY=base64:supersecret\nDB_PASSWORD=hunter2"
        client = _make_client({".env": (200, body)})
        check = EnvExposedCheck(client)
        finding = await check.run(ScanTarget(url="https://example.com"))

        assert finding.evidence is not None
        assert "supersecret" not in finding.evidence
        assert "hunter2" not in finding.evidence
        assert "[REDACTED]" in finding.evidence
