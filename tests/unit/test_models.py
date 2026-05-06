"""Tests for app.models.scan"""
import pytest
from app.models.scan import Finding, ScanResult, ScanTarget, Severity, CheckStatus


def make_finding(severity: Severity, status: CheckStatus = CheckStatus.VULNERABLE) -> Finding:
    return Finding(
        check_id="TEST",
        title="Test Finding",
        severity=severity,
        status=status,
        description="A test finding.",
    )


class TestScanResult:
    def _result(self, findings):
        target = ScanTarget(url="https://example.com")
        return ScanResult(target=target, findings=findings)

    def test_is_successful_no_error(self):
        r = self._result([])
        assert r.is_successful is True

    def test_is_successful_with_error(self):
        target = ScanTarget(url="https://example.com")
        r = ScanResult(target=target, error="timeout")
        assert r.is_successful is False

    def test_critical_count(self):
        r = self._result([
            make_finding(Severity.CRITICAL),
            make_finding(Severity.CRITICAL),
            make_finding(Severity.HIGH),
        ])
        assert r.critical_count == 2

    def test_high_count(self):
        r = self._result([make_finding(Severity.HIGH), make_finding(Severity.MEDIUM)])
        assert r.high_count == 1

    def test_vulnerable_findings_excludes_safe(self):
        r = self._result([
            make_finding(Severity.CRITICAL, CheckStatus.VULNERABLE),
            make_finding(Severity.HIGH, CheckStatus.SAFE),
        ])
        assert len(r.vulnerable_findings) == 1

    def test_risk_score_zero_when_no_vulns(self):
        r = self._result([make_finding(Severity.CRITICAL, CheckStatus.SAFE)])
        assert r.risk_score == 0.0

    def test_risk_score_capped_at_10(self):
        r = self._result([make_finding(Severity.CRITICAL)] * 20)
        assert r.risk_score <= 10.0

    def test_risk_score_reflects_severity(self):
        r_crit = self._result([make_finding(Severity.CRITICAL)])
        r_low  = self._result([make_finding(Severity.LOW)])
        assert r_crit.risk_score > r_low.risk_score


class TestFinding:
    def test_immutable(self):
        f = make_finding(Severity.HIGH)
        with pytest.raises(Exception):
            f.severity = Severity.LOW  # type: ignore

    def test_cvss_bounds(self):
        with pytest.raises(Exception):
            Finding(
                check_id="X",
                title="T",
                severity=Severity.LOW,
                status=CheckStatus.SAFE,
                description="",
                cvss_score=11.0,  # invalid
            )
