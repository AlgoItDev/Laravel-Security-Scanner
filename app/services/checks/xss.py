"""
Check: XSS (Hybrid Static + Dynamic).

Combines static code analysis with dynamic probing for accurate
XSS detection with reduced false positives.

Severity: HIGH — XSS can lead to session hijacking, defacement, or phishing attacks.
"""
from __future__ import annotations

import re
from urllib.parse import urlencode

import httpx

from app.core.logging import logger
from app.models.scan import CheckStatus, Finding, Severity, ScanTarget
from app.services.checks.base import BaseCheck
from app.services.source_fetcher import SourceFetcher
from app.services.static_analyzer import (
    RiskLevel,
    StaticCodeAnalyzer,
    StaticFinding,
    VulnerabilityType,
)


XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "\"><script>alert(1)</script>",
]

XSS_REFLECTION_PATTERNS = [
    r"<script.*alert",
    r"on(error|click|load|focus|blur)\s*=",
    r"javascript:",
    r"<img.*onerror",
    r"<svg.*onload",
    r"<iframe.*src",
]

CONFIDENT_THRESHOLD = 0.5


class XSSCheck(BaseCheck):
    CHECK_ID = "XSS"
    TITLE = "Cross-Site Scripting (XSS) (Hybrid)"

    async def run(self, target: ScanTarget) -> Finding:
        static_findings = await self._analyze_source(target)
        dynamic_findings = await self._probe_xss(target)

        combined = self._combine_results(static_findings, dynamic_findings)

        if combined["confidence"] >= CONFIDENT_THRESHOLD:
            return self._create_finding(combined, static_findings, dynamic_findings)

        if dynamic_findings["vulnerable"]:
            return self._create_finding(dynamic_findings, static_findings, dynamic_findings)

        if static_findings["findings"]:
            medium_conf = self._calculate_static_confidence(static_findings["findings"])
            if medium_conf >= 0.5:
                return self._create_finding(
                    {"confidence": medium_conf, **static_findings},
                    static_findings,
                    dynamic_findings,
                )

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=Severity.MEDIUM,
            status=CheckStatus.SAFE,
            description="No XSS vulnerabilities detected (hybrid analysis).",
        )

    async def _analyze_source(self, target: ScanTarget) -> dict:
        """Static code analysis."""
        try:
            fetcher = SourceFetcher(self._client)
            source_files = await fetcher.fetch_all(target.url)

            if not source_files:
                return {"findings": [], "has_source": False}

            analyzer = StaticCodeAnalyzer()
            all_findings = analyzer.analyze(source_files)

            xss_findings = analyzer.filter_by_type(all_findings, VulnerabilityType.XSS)
            high_risk = analyzer.get_high_risk_only(xss_findings)

            logger.debug(f"[{self.CHECK_ID}] Static: {len(high_risk)} high-risk XSS findings")

            return {"findings": xss_findings, "high_risk": high_risk, "has_source": True}

        except Exception as e:
            logger.warning(f"[{self.CHECK_ID}] Static analysis failed: {e}")
            return {"findings": [], "has_source": False}

    async def _probe_xss(self, target: ScanTarget) -> dict:
        """Dynamic XSS probing."""
        vulnerabilities = []
        evidence_details = []

        test_params = ["q", "search", "name", "redirect", "next", "url", "param"]

        for param in test_params:
            for payload in XSS_PAYLOADS[:3]:
                try:
                    test_url = f"{target.url}/?{param}={payload}"
                    response = await self._client.get(
                        test_url,
                        headers=target.headers,
                        follow_redirects=True,
                    )

                    if self._is_xss_vulnerable(response.text, payload):
                        vulnerabilities.append(f"{param}={payload}")
                        evidence_details.append(
                            f"Parameter: {param} | Payload: {payload}"
                        )
                        break

                except (httpx.TimeoutException, httpx.RequestError):
                    continue

        is_vulnerable = len(vulnerabilities) > 0
        confidence = 0.7 if is_vulnerable else 0.0

        return {
            "vulnerable": is_vulnerable,
            "vulnerabilities": vulnerabilities,
            "evidence": evidence_details,
            "confidence": confidence,
        }

    def _is_xss_vulnerable(self, response: str, payload: str) -> bool:
        """Check if response is vulnerable to XSS."""
        if payload in response:
            if self._is_properly_encoded(payload, response):
                return False
            return True

        for pattern in XSS_REFLECTION_PATTERNS:
            if re.search(pattern, response, re.IGNORECASE):
                return True

        return False

    def _is_properly_encoded(self, payload: str, response: str) -> bool:
        """Check if payload is properly HTML-encoded."""
        html_encoded = (
            payload.replace("<", "&lt;").replace(">", "&gt;")
        )

        if html_encoded in response:
            return True

        numeric = payload.replace("<", "&#60;").replace(">", "&#62;")
        if numeric in response:
            return True

        return False

    def _combine_results(self, static: dict, dynamic: dict) -> dict:
        """Combine static and dynamic findings."""
        if not static.get("has_source"):
            return dynamic

        if static.get("findings") and dynamic.get("vulnerable"):
            combined_confidence = min(
                static.get("confidence", 0.5) + dynamic.get("confidence", 0.5) + 0.1,
                1.0,
            )

            return {
                "confidence": combined_confidence,
                "vulnerable": True,
                "source": "both",
                "static_findings": static.get("findings", []),
                "dynamic_vulns": dynamic.get("vulnerabilities", []),
            }

        if static.get("findings") and not dynamic.get("vulnerable"):
            static_conf = self._calculate_static_confidence(static.get("findings", []))

            return {
                "confidence": static_conf,
                "vulnerable": static_conf >= 0.7,
                "source": "static",
                "static_findings": static.get("findings", []),
            }

        return dynamic

    def _calculate_static_confidence(
        self, findings: list[StaticFinding]
    ) -> float:
        """Calculate confidence from static findings."""
        if not findings:
            return 0.0

        max_confidence = max(f.confidence for f in findings)
        high_risk_count = sum(
            1 for f in findings if f.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        )

        if high_risk_count > 0:
            return min(max_confidence + 0.1, 1.0)

        return max_confidence * 0.7

    def _create_finding(
        self, combined: dict, static: dict, dynamic: dict
    ) -> Finding:
        """Create Finding object from results."""
        evidence_parts = []

        if static.get("findings"):
            for f in static.get("findings", [])[:3]:
                evidence_parts.append(
                    f"STATIC: {f.file_path}:{f.line_number} - {f.reason}"
                )

        if dynamic.get("vulnerabilities"):
            for v in dynamic.get("vulnerabilities", [])[:3]:
                evidence_parts.append(f"DYNAMIC: {v}")

        confidence = combined.get("confidence", 0.5)

        if confidence >= 0.7:
            severity = Severity.HIGH
        elif confidence >= 0.5:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        return Finding(
            check_id=self.CHECK_ID,
            title=self.TITLE,
            severity=severity,
            status=CheckStatus.VULNERABLE,
            description=(
                f"XSS vulnerability detected (confidence: {confidence:.0%}). "
                f"Static: {len(static.get('findings', []))} findings. "
                f"Dynamic: {len(dynamic.get('vulnerabilities', []))} reflections."
            ),
            evidence="\n".join(evidence_parts[:8]),
            remediation=(
                "⚠️ HIGH: XSS - Stored/Reflected script çalıştırılabilir!\n\n"
                "🛡️ 1. Blade Auto-Escape (EN İYİ):\n"
                "   # ❌ KULLANMA:\n"
                "   {!! $input !!}\n\n"
                "   # ✅ KULLAN:\n"
                "   {{ $input }}\n"
                "   {{ e($input) }}  # Manual escape\n\n"
                "📝 2. Input Validation:\n"
                "   $request->validate(['input' => 'string|max:100']);\n\n"
                "🍪 3. Cookie Güvenliği:\n"
                "   # Kernel.php (Http/Kernel)\n"
                "   protected $middleware = [\n"
                "       \\Illuminate\\Cookie\\Middleware\\EncryptCookies::class,\n"
                "       // ...\n"
                "   ];\n\n"
                "🛡️ 4. CSP Header:\n"
                "   # config/security_headers.php ekle:\n"
                "   'Content-Security-Policy' => \"default-src 'self'\",\n\n"
                "🔗 Ref: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
            ),
            cvss_score=7.5 if confidence >= 0.7 else (5.0 if confidence >= 0.5 else 3.0),
            references=[
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            ],
        )