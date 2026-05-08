"""
Security Score Calculator - Calculate scores from findings.

Provides:
- Category-based scoring
- Weighted overall score calculation
- Grade and risk level assignment
"""
from __future__ import annotations

from app.models.scan import Finding, ScanResult
from app.models.score import (
    Category,
    CategoryScore,
    CHECK_CATEGORIES,
    CATEGORY_WEIGHTS,
    Grade,
    RiskLevel,
    SecurityScore,
    get_grade_for_score,
    get_risk_level_for_score,
    get_score_for_severity,
)


class ScoreCalculator:
    """Calculate security scores from scan findings."""

    def calculate(self, scan_result: ScanResult) -> SecurityScore:
        """Calculate security score from scan result."""
        if not scan_result.findings:
            return SecurityScore(
                overall_score=100,
                grade=Grade.APLUS,
                risk_level=RiskLevel.VERY_LOW,
                categories=self._get_empty_categories(),
                total_findings=0,
            )

        # Group findings by category
        category_findings: dict[Category, list[Finding]] = self._group_by_category(
            scan_result.findings
        )

        # Calculate category scores
        categories = []
        for category in Category:
            findings = category_findings.get(category, [])
            cat_score = self._calculate_category_score(category, findings)
            categories.append(cat_score)

        # Calculate weighted overall score
        overall_score = self._calculate_weighted_score(categories)

        # Get totals
        total_findings = len(scan_result.findings)
        total_critical = scan_result.critical_count
        total_high = scan_result.high_count

        # Get grade and risk level
        grade = get_grade_for_score(overall_score)
        risk_level = get_risk_level_for_score(overall_score)

        return SecurityScore(
            overall_score=overall_score,
            grade=grade,
            risk_level=risk_level,
            categories=categories,
            total_findings=total_findings,
            total_critical=total_critical,
            total_high=total_high,
        )

    def _group_by_category(self, findings: list[Finding]) -> dict[Category, list[Finding]]:
        """Group findings by their category."""
        grouped: dict[Category, list[Finding]] = {cat: [] for cat in Category}

        for finding in findings:
            category = CHECK_CATEGORIES.get(
                finding.check_id.upper(), Category.CONFIG
            )
            grouped[category].append(finding)

        return grouped

    def _calculate_category_score(
        self, category: Category, findings: list[Finding]
    ) -> CategoryScore:
        """Calculate score for a single category."""
        if not findings:
            return CategoryScore(
                category=category,
                score=100,
                grade=Grade.APLUS,
                risk_level=RiskLevel.VERY_LOW,
            )

        # Count severities
        critical_count = sum(1 for f in findings if f.severity.value == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity.value == "HIGH")
        medium_count = sum(1 for f in findings if f.severity.value == "MEDIUM")
        low_count = sum(1 for f in findings if f.severity.value == "LOW")

        # Calculate penalty
        total_penalty = 0
        for f in findings:
            severity_str = f.severity.value
            total_penalty += get_score_for_severity(severity_str)

        # Score = 100 - penalty (minimum 0)
        score = max(100 - total_penalty, 0)

        # Get grade and risk
        grade = get_grade_for_score(score)
        risk_level = get_risk_level_for_score(score)

        return CategoryScore(
            category=category,
            score=score,
            findings_count=len(findings),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            grade=grade,
            risk_level=risk_level,
        )

    def _calculate_weighted_score(self, categories: list[CategoryScore]) -> int:
        """Calculate weighted overall score."""
        total_weight = 0.0
        weighted_score = 0.0

        for cat_score in categories:
            weight = CATEGORY_WEIGHTS.get(cat_score.category, 1.0)
            total_weight += weight
            weighted_score += cat_score.score * weight

        if total_weight == 0:
            return 100

        return round(weighted_score / total_weight)

    def _get_empty_categories(self) -> list[CategoryScore]:
        """Return empty score for all categories."""
        return [
            CategoryScore(
                category=cat,
                score=100,
                grade=Grade.APLUS,
                risk_level=RiskLevel.VERY_LOW,
            )
            for cat in Category
        ]


def calculate_security_score(scan_result: ScanResult) -> SecurityScore:
    """Convenience function to calculate security score."""
    calculator = ScoreCalculator()
    return calculator.calculate(scan_result)