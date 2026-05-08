"""
Static Code Analyzer - Analyzes Laravel source code for security vulnerabilities.

Detects patterns that indicate potential SQL injection and XSS vulnerabilities
by analyzing source code without executing it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class VulnerabilityType(str, Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


@dataclass
class StaticFinding:
    """A static code analysis finding."""
    file_path: str
    line_number: int
    code_snippet: str
    vulnerability_type: VulnerabilityType
    risk_level: RiskLevel
    reason: str
    confidence: float


class StaticCodeAnalyzer:
    """Analyzes Laravel source code for security issues."""

    SQL_DANGEROUS_PATTERNS = [
        (r'DB::select\s*\(\s*"[^"]*\."', "Direct string concatenation in DB::select", 0.95),
        (r'DB::raw\s*\(\s*"[^"]*\."', "Direct string concatenation in DB::raw", 0.95),
        (r'DB::statement\s*\(\s*"[^"]*\."', "Direct string concatenation in DB::statement", 0.95),
        (r'whereRaw\s*\(\s*"[^"]*\."', "Direct string concatenation in whereRaw", 0.90),
        (r'orderByRaw\s*\(\s*"[^"]*\."', "Direct string concatenation in orderByRaw", 0.90),
        (r'joinRaw\s*\(\s*"[^"]*\."', "Direct string concatenation in joinRaw", 0.90),
        (r'execute\s*\(\s*"[^"]*\."', "Direct string concatenation in execute", 0.90),
        (r'use\s+Illuminate\\\\Support\\\\Facades\\\\DB', "DB facade imported", 0.2),
    ]

    SQL_SAFE_PATTERNS = [
        (r'where\s*\(\s*[\'"][^\'"]+[\'"]\s*,\s*[\'?]', "Parameterized where clause"),
        (r'whereIn\s*\(', "whereIn (parameterized)"),
        (r'whereNull\s*\(', "whereNull (safe)"),
        (r'whereNotNull\s*\(', "whereNotNull (safe)"),
        (r'whereBetween\s*\(', "whereBetween (parameterized)"),
        (r'orWhere\s*\(\s*function', "Closure in orWhere (parameterized)"),
        (r'->where\s*\(\s*[\'"][^\'"]+[\'"]', "Eloquent where (parameterized)"),
        (r'find\s*\(\s*\d+', "find with ID"),
        (r'first\s*\(\s*\)', "first() method"),
    ]

    SQL_INPUT_SOURCES = [
        r"$request->input\s*\(",
        r"$request->get\s*\(",
        r"$request->all\s*\(",
        r"$request->only\s*\(",
        r"$request->except\s*\(",
        r"Request::input\s*\(",
        r"\$_GET\[",
        r"\$_POST\[",
        r"\$_REQUEST\[",
        r"auth\s*\(\s*\)\s*->\s*user\s*\(\s*\)",
    ]

    XSS_DANGEROUS_PATTERNS = [
        (r'\{\{\s*\$[a-zA-Z_][\w]*\}\}', "Blade {{ }} - escaped by default", 0.3),
        (r'\{!!\s*\$[a-zA-Z_][\w]*\s*!!\}', "Blade raw {!! !!} output - HIGH risk", 0.85),
        (r'echo\s+\$', "PHP echo without escape", 0.6),
        (r'print\s+\$', "PHP print without escape", 0.6),
        (r'Response::make\s*\(\s*\$', "Direct response with user input", 0.7),
    ]

    XSS_SAFE_PATTERNS = [
        (r'\{\{\s*\$[\w]+\s*\}\}', "Blade escaped {{ }} (safe by default)"),
        (r'e\(\s*\$', "e() helper (escapes output)"),
        (r'\{\{!\$', "Blade comment marker"),
    ]

    XSS_INPUT_SOURCES = [
        r"\$request->input",
        r"\$request->get",
        r"\$request->all",
        r"auth\s*\(\s*\)\s*->\s*user",
    ]

    def analyze(self, source_files: dict[str, str]) -> list[StaticFinding]:
        """Analyze all source files and return findings."""
        findings = []

        for file_path, content in source_files.items():
            lines = content.split("\n")
            for finding in self._analyze_file(file_path, lines):
                findings.append(finding)

        return findings

    def _analyze_file(self, file_path: str, lines: list[str]) -> list[StaticFinding]:
        """Analyze a single file for vulnerabilities."""
        findings = []

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()

            sql_findings = self._analyze_sql_line(stripped, file_path, line_num, line)
            findings.extend(sql_findings)

            xss_findings = self._analyze_xss_line(stripped, file_path, line_num, line)
            findings.extend(xss_findings)

        return findings

    def _analyze_sql_line(
        self, line: str, file_path: str, line_num: int, original_line: str
    ) -> list[StaticFinding]:
        """Analyze a single line for SQL injection patterns."""
        findings = []

        has_input = any(re.search(p, line, re.IGNORECASE) for p in self.SQL_INPUT_SOURCES)

        for pattern, reason, confidence in self.SQL_DANGEROUS_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                risk = RiskLevel.HIGH if confidence >= 0.9 else RiskLevel.MEDIUM

                if has_input:
                    confidence = min(confidence + 0.1, 1.0)
                    reason = f"{reason} (user input detected)"
                    risk = RiskLevel.CRITICAL

                findings.append(
                    StaticFinding(
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=original_line[:100],
                        vulnerability_type=VulnerabilityType.SQL_INJECTION,
                        risk_level=risk,
                        reason=reason,
                        confidence=confidence,
                    )
                )
                break

        return findings

    def _analyze_xss_line(
        self, line: str, file_path: str, line_num: int, original_line: str
    ) -> list[StaticFinding]:
        """Analyze a single line for XSS patterns."""
        findings = []

        if not file_path.endswith((".php", ".blade.php")):
            return findings

        has_input = any(
            re.search(p, line, re.IGNORECASE) for p in self.XSS_INPUT_SOURCES
        )

        raw_output_patterns = [
            (r'\{!!\s*\$[\w]+', "Blade raw output {!! !!}", RiskLevel.HIGH, 0.85),
            (r'<\?php\s+echo\s+\$', "PHP echo without escape", RiskLevel.MEDIUM, 0.60),
            (r'<\?=\s*\$', "PHP short echo without escape", RiskLevel.MEDIUM, 0.60),
        ]

        for pattern, reason, risk_level, base_confidence in raw_output_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                confidence = base_confidence

                if has_input:
                    confidence = min(confidence + 0.15, 1.0)
                    reason = f"{reason} (user input in output)"

                findings.append(
                    StaticFinding(
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=original_line[:100],
                        vulnerability_type=VulnerabilityType.XSS,
                        risk_level=risk_level,
                        reason=reason,
                        confidence=confidence,
                    )
                )
                break

        return findings

    def filter_by_type(
        self, findings: list[StaticFinding], vuln_type: VulnerabilityType
    ) -> list[StaticFinding]:
        """Filter findings by vulnerability type."""
        return [f for f in findings if f.vulnerability_type == vuln_type]

    def get_high_risk_only(self, findings: list[StaticFinding]) -> list[StaticFinding]:
        """Return only high/critical risk findings."""
        return [
            f
            for f in findings
            if f.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        ]