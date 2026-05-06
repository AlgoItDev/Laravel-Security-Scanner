"""
main.py — CLI entry point for Laravel Security Scanner.

Usage:
    python main.py https://target.example.com
    python main.py https://target.example.com --format json
    python main.py https://target.example.com --format txt --output ./my_reports
    python main.py https://t1.com https://t2.com --no-ssl-verify
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from app.core.logging import logger
from app.core.settings import settings
from app.models.scan import ScanTarget
from app.services.reporter import ReportService
from app.services.scanner import ScannerService
from app.utils.url import InvalidURLError, normalise_url


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="laravel-sec-scanner",
        description="🔍 Laravel Security Scanner — production-grade security auditing CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py https://myapp.com
  python main.py https://myapp.com --format json --output ./reports
  python main.py https://myapp.com --timeout 15 --no-ssl-verify
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
        "--version",
        action="version",
        version=f"%(prog)s {settings.APP_VERSION}",
    )
    return parser.parse_args()


async def run_scans(args: argparse.Namespace) -> int:
    """Scan all targets and return exit code (0 = clean, 1 = vulnerabilities found)."""
    # Parse check IDs if provided
    check_ids = None
    if args.checks:
        check_ids = [check_id.strip() for check_id in args.checks.split(",")]
    
    scanner = ScannerService(timeout=args.timeout, check_ids=check_ids)
    reporter = ReportService()
    any_vulnerable = False

    for raw_url in args.targets:
        try:
            url = normalise_url(raw_url)
        except InvalidURLError as exc:
            logger.error(f"Invalid URL skipped: {raw_url!r} — {exc}")
            continue

        target = ScanTarget(
            url=url,
            verify_ssl=not args.no_ssl_verify,
        )

        result = await scanner.scan(target)
        if result.vulnerable_findings:
            any_vulnerable = True

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

    return 1 if any_vulnerable else 0


def main() -> None:
    args = parse_args()
    logger.info(f"{settings.APP_NAME} v{settings.APP_VERSION} starting")
    exit_code = asyncio.run(run_scans(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
