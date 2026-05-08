"""
Security Score Models - Category-based scoring system.

Provides:
- Category scores (Config, Auth, Headers, Secrets, Database, Input)
- Overall security score (0-100)
- Grade system (A+ to F)
- Risk level assessment
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Category(str, Enum):
    CONFIG = "config"
    AUTH = "auth"
    HEADERS = "headers"
    SECRETS = "secrets"
    DATABASE = "database"
    INPUT = "input"


class Grade(str, Enum):
    APLUS = "A+"
    A = "A"
    BPLUS = "B+"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class RiskLevel(str, Enum):
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM_LOW = "medium_low"
    MEDIUM = "medium"
    MEDIUM_HIGH = "medium_high"
    HIGH = "high"
    CRITICAL = "critical"


# Check ID to Category mapping
CHECK_CATEGORIES: dict[str, Category] = {
    # Config
    "ENV_EXPOSED": Category.CONFIG,
    "DEBUG_MODE": Category.CONFIG,
    "LARAVEL_VERSION": Category.CONFIG,
    "INSECURE_CONFIG": Category.CONFIG,
    "SENSITIVE_FILES": Category.CONFIG,
    # Auth
    "CSRF_PROTECTION": Category.AUTH,
    "SESSION_SECURITY": Category.AUTH,
    "AUTH_BYPASS": Category.AUTH,
    # Headers
    "SECURITY_HEADERS": Category.HEADERS,
    "CORS_MISCONFIG": Category.HEADERS,
    # Secrets
    "COMPOSER_CVE": Category.SECRETS,
    "JWT_ANALYSIS": Category.SECRETS,
    # Database
    "SQL_INJECTION": Category.DATABASE,
    "DATABASE_EXPOSED": Category.DATABASE,
    # Input/Output
    "XSS": Category.INPUT,
    "OPEN_REDIRECT": Category.INPUT,
    # Tools/Exposed (others)
    "TELESCOPE_EXPOSED": Category.CONFIG,
    "DEBUGBAR_EXPOSED": Category.CONFIG,
    "MIX_MANIFEST_EXPOSED": Category.CONFIG,
    "HORIZON_EXPOSED": Category.CONFIG,
    "NOVA_EXPOSED": Category.CONFIG,
    "RATE_LIMITING": Category.AUTH,
    "HTTP_METHODS": Category.CONFIG,
    "SUBDOMAIN_ENUM": Category.SECRETS,
}

# Category weights (higher = more important)
CATEGORY_WEIGHTS: dict[Category, float] = {
    Category.AUTH: 2.0,
    Category.DATABASE: 2.0,
    Category.INPUT: 1.5,
    Category.SECRETS: 1.5,
    Category.CONFIG: 1.2,
    Category.HEADERS: 1.0,
}

# Severity penalties (points to deduct)
SEVERITY_PENALTIES: dict[str, int] = {
    "CRITICAL": 15,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
    "INFO": 0,
}


@dataclass
class CategoryScore:
    """Score for a single category."""
    category: Category
    score: int = 100
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    grade: Grade = Grade.APLUS
    risk_level: RiskLevel = RiskLevel.VERY_LOW

    @property
    def letter_grade(self) -> str:
        return self.grade.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "score": self.score,
            "findings_count": self.findings_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "grade": self.grade.value,
            "risk_level": self.risk_level.value,
        }


@dataclass
class SecurityScore:
    """Overall security score with category breakdown."""
    overall_score: int = 100
    grade: Grade = Grade.APLUS
    risk_level: RiskLevel = RiskLevel.VERY_LOW
    categories: list[CategoryScore] = field(default_factory=list)
    total_findings: int = 0
    total_critical: int = 0
    total_high: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_score": self.overall_score,
            "grade": self.grade.value,
            "risk_level": self.risk_level.value,
            "total_findings": self.total_findings,
            "total_critical": self.total_critical,
            "total_high": self.total_high,
            "categories": [c.to_dict() for c in self.categories],
        }


def get_score_for_severity(severity: str) -> int:
    """Get penalty points for severity."""
    return SEVERITY_PENALTIES.get(severity.upper(), 0)


def get_grade_for_score(score: int) -> Grade:
    """Convert numeric score to letter grade."""
    if score >= 90:
        return Grade.APLUS
    if score >= 80:
        return Grade.A
    if score >= 70:
        return Grade.BPLUS
    if score >= 60:
        return Grade.B
    if score >= 50:
        return Grade.C
    if score >= 40:
        return Grade.D
    return Grade.F


def get_risk_level_for_score(score: int) -> RiskLevel:
    """Convert numeric score to risk level."""
    if score >= 90:
        return RiskLevel.VERY_LOW
    if score >= 80:
        return RiskLevel.LOW
    if score >= 70:
        return RiskLevel.MEDIUM_LOW
    if score >= 60:
        return RiskLevel.MEDIUM
    if score >= 50:
        return RiskLevel.MEDIUM_HIGH
    if score >= 40:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL