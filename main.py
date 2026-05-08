"""
main.py — CLI entry point for Laravel Security Scanner.

Usage:
    python main.py https://target.example.com
    python main.py https://target.example.com --format json
    python main.py https://target.example.com --format txt --output ./my_reports
    python main.py https://t1.com https://t2.com --no-ssl-verify
    python main.py https://target.com --fail-on critical  # Exit code based on severity

Exit Codes:
    0 = Clean (no vulnerabilities)
    1 = Low/Info vulnerabilities found
    2 = Medium vulnerabilities found
    3 = High vulnerabilities found
    4 = Critical vulnerabilities found
    5 = Scan error/failure
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from app.core.logging import logger
from app.core.settings import settings
from app.models.scan import ScanTarget, Severity
from app.services.reporter import ReportService
from app.services.scanner import ScannerService
from app.utils.url import InvalidURLError, normalise_url


EXIT_CODES = {
    0: "Clean - no vulnerabilities",
    1: "Low/Info vulnerabilities found",
    2: "Medium vulnerabilities found",
    3: "High vulnerabilities found",
    4: "Critical vulnerabilities found",
    5: "Scan error or failure",
}

FAIL_ON_LEVELS = ["critical", "high", "medium", "low", "info", "none"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="laravel-sec-scanner",
        description="Laravel Security Scanner - production-grade security auditing CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python main.py https://myapp.com
  python main.py https://myapp.com --format json --output ./reports
  python main.py https://myapp.com --timeout 15 --no-ssl-verify
  python main.py https://myapp.com --fail-on critical  # Exit 4 if critical found
  python main.py https://myapp.com --min-severity high   # Only show high+

Exit Codes (progressive):
{chr(10).join(f"  {k} = {v}" for k, v in EXIT_CODES.items())}
        """,
    )
    parser.add_argument(
        "targets",
        nargs="+",
        metavar="URL",
        help="One or more target URLs to scan",
    )
    parser.add_argument(
        "--format",
        choices=["console", "json", "txt", "html", "sarif", "all"],
        default="all",
        help="Output format (default: all)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=settings.REPORT_OUTPUT_DIR,
        help=f"Directory for file reports (default: {settings.REPORT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=settings.SCAN_TIMEOUT,
        help=f"Request timeout in seconds (default: {settings.SCAN_TIMEOUT})",
    )
    parser.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Disable SSL certificate verification (use with caution)",
    )
    parser.add_argument(
        "--checks",
        type=str,
        default=None,
        help="Comma-separated list of check IDs to run (e.g. ENV_EXPOSED,DEBUG_MODE). "
             "By default, all checks are run.",
    )
    parser.add_argument(
        "--cache-ttl",
        type=int,
        default=settings.OSV_CACHE_TTL_HOURS,
        help=f"OSV cache TTL in hours (default: {settings.OSV_CACHE_TTL_HOURS}). "
             "Set to 0 to disable cache.",
    )
    parser.add_argument(
        "--fail-on",
        choices=FAIL_ON_LEVELS,
        default="none",
        help="Failure severity threshold - exit code based on highest severity found "
             "(default: none - always exit 0 for CI compatibility)",
    )
    parser.add_argument(
        "--min-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        help="Minimum severity to report (default: all severities)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {settings.APP_VERSION}",
    )
    return parser.parse_args()


def get_highest_severity(findings: list) -> int:
    """Get exit code based on highest severity found."""
    if not findings:
        return 0

    has_critical = any(f.severity == Severity.CRITICAL for f in findings)
    has_high = any(f.severity == Severity.HIGH for f in findings)
    has_medium = any(f.severity == Severity.MEDIUM for f in findings)
    has_low = any(f.severity == Severity.LOW for f in findings)

    if has_critical:
        return 4
    if has_high:
        return 3
    if has_medium:
        return 2
    if has_low:
        return 1

    return 0


def should_fail(fail_on: str, exit_code: int) -> bool:
    """Determine if should fail based on fail-on threshold."""
    if fail_on == "none":
        return False

    severity_levels = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
    }

    threshold = severity_levels.get(fail_on, 0)
    return exit_code >= threshold


async def run_scans(args: argparse.Namespace) -> int:
    """Run security scans and return progressive exit code."""
    check_ids = None
    if args.checks:
        check_ids = [check_id.strip() for check_id in args.checks.split(",")]

    scanner = ScannerService(timeout=args.timeout, check_ids=check_ids, cache_ttl=args.cache_ttl)
    reporter = ReportService()

    max_exit_code = 0
    scan_error = False

    for raw_url in args.targets:
        try:
            url = normalise_url(raw_url)
        except InvalidURLError as exc:
            logger.error(f"Invalid URL skipped: {raw_url!r} — {exc}")
            scan_error = True
            continue

        target = ScanTarget(
            url=url,
            verify_ssl=not args.no_ssl_verify,
        )

        try:
            result = await scanner.scan(target)
        except Exception as exc:
            logger.error(f"Scan failed for {url}: {exc}")
            scan_error = True
            continue

        findings = result.vulnerable_findings

        # Filter by minimum severity if specified
        if args.min_severity:
            severity_order = {
                "CRITICAL": 5,
                "HIGH": 4,
                "MEDIUM": 3,
                "LOW": 2,
                "INFO": 1,
            }
            min_level = severity_order.get(args.min_severity, 0)
            findings = [
                f for f in findings
                if severity_order.get(str(f.severity), 0) >= min_level
            ]

        # Track highest exit code
        exit_code = get_highest_severity(findings)
        max_exit_code = max(max_exit_code, exit_code)

        # Output reports
        fmt = args.format
        if fmt in ("console", "all"):
            reporter.print_console(result)
        if fmt in ("json", "all"):
            reporter.save_json(result, output_dir=args.output)
        if fmt in ("txt", "all"):
            reporter.save_txt(result, output_dir=args.output)
        if fmt in ("html", "all"):
            reporter.save_html(result, output_dir=args.output)
        if fmt in ("sarif", "all"):
            reporter.save_sarif(result, output_dir=args.output)

    # Handle scan errors
    if scan_error:
        return 5

    # Check fail-on threshold for CI
    if should_fail(args.fail_on, max_exit_code):
        return max_exit_code

    return 0


def main() -> None:
    args = parse_args()
    logger.info(f"{settings.APP_NAME} v{settings.APP_VERSION} starting")

    exit_code = asyncio.run(run_scans(args))

    # Log exit code for CI/CD visibility
    if exit_code > 0:
        exit_desc = EXIT_CODES.get(exit_code, "Unknown")
        logger.warning(f"Exit code: {exit_code} - {exit_desc}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()