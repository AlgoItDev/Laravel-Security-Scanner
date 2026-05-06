"""
Domain models for scan results and findings.
All models are immutable value objects (frozen=True where applicable).
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field, HttpUrl


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CheckStatus(str, Enum):
    VULNERABLE = "VULNERABLE"
    SAFE = "SAFE"
    UNKNOWN = "UNKNOWN"
    SKIPPED = "SKIPPED"


class Finding(BaseModel):
    """A single security finding from one check."""

    check_id: str = Field(..., description="Unique identifier for the check, e.g. 'ENV_EXPOSED'")
    title: str
    severity: Severity
    status: CheckStatus
    description: str
    evidence: str | None = None
    remediation: str | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    references: list[str] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True}


class ScanTarget(BaseModel):
    """Represents a scan target with normalised URL."""

    url: str  # raw string — we normalise in service layer
    label: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    verify_ssl: bool = True


class ScanResult(BaseModel):
    """Aggregated result for a single target URL."""

    target: ScanTarget
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None

    # Convenience properties
    @property
    def is_successful(self) -> bool:
        return self.error is None

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def vulnerable_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.status == CheckStatus.VULNERABLE]

    @property
    def risk_score(self) -> float:
        """Weighted risk score 0–10."""
        weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 1.5,
            Severity.INFO: 0.0,
        }
        vuln = self.vulnerable_findings
        if not vuln:
            return 0.0
        total = sum(weights[f.severity] for f in vuln)
        return min(round(total / len(vuln), 2), 10.0)
