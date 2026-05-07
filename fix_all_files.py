"""
Script to fix all corrupted files in the Laravel Security Scanner project.
Writes files with proper Python syntax.
"""
import os__

# Define the correct content for each file
files_to_write = {}

# 1. main.py
files_to_write[r'D:\PROJELER\Python Projeler\Laravel Security  Scanner\main.py'] = '''
"""
main.py - CLI entry point for Laravel Security Scanner.

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
        description="🔍 Laravel Security Scanner - production-grade security auditing CLI",
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
            logger.error(f"Invalid URL skipped: {raw_url!r} - {exc}")
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
'''

# 2. app/services/scanner.py
files_to_write[r'D:\PROJELER\Python Projeler\Laravel Security  Scanner\app\services\scanner.py'] = '''
"""
ScannerService - orchestrates all security checks for a given target.

Uses asyncio + httpx.AsyncClient with a shared connection pool.
Checks run concurrently (bounded by semaphore) for performance.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

import httpx

from app.core.logging import logger
from app.core.settings import settings
from app.models.scan import ScanResult, ScanTarget
from app.services.checks import ALL_CHECKS, BaseCheck
from app.services.rate_limiter import RetryableClient, RateLimiter


class ScannerService:
    """Runs all registered checks against a ScanTarget concurrently."""

    def __init__(
        self,
        checks: list[type[BaseCheck]] | None = None,
        check_ids: list[str] | None = None,
        timeout: int | None = None,
        max_concurrent: int | None = None,
    ) -> None:
        self._check_classes = checks or ALL_CHECKS
        if check_ids:
            # Filter checks by CHECK_ID
            self._check_classes = [
                cls for cls in self._check_classes
                if cls.CHECK_ID in check_ids
            ]
            if not self._check_classes:
                logger.warning(f"No checks found matching IDs: {check_ids}. Running all checks.")
                self._check_classes = checks or ALL_CHECKS
        self._timeout = timeout or settings.SCAN_TIMEOUT
        self._semaphore = asyncio.Semaphore(max_concurrent or settings.CONCURRENT_CHECKS)

    async def scan(self, target: ScanTarget) -> ScanResult:
        """
        Execute all checks against `target` and return aggregated ScanResult.

        Args:
            target: The ScanTarget to scan.

        Returns:
            ScanResult with all findings populated.
        """
        result = ScanResult(target=target)
        logger.info(f"Starting scan for: {target.url}")

        timeout_cfg = httpx.Timeout(self._timeout, connect=5.0)
        limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)

        # Create rate limiter and retryable client
        rate_limiter = RateLimiter(rate=10.0, burst=10)  # 10 requests per second, burst of 10
        
        async with httpx.AsyncClient(
            timeout=timeout_cfg,
            limits=limits,
            headers={"User-Agent": settings.USER_AGENT},
            verify=target.verify_ssl,
        ) as base_client:
            client = RetryableClient(
                base_client, 
                rate_limiter=rate_limiter,
                max_retries=3,
                retry_delay=1.0,
                max_retry_delay=10.0,
            )
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
            ) as progress:
                task = progress.add_task("Scanning...", total=len(self._check_classes))
                
                async def _run_check_with_progress(check_cls, target, progress, task):
                    async with self._semaphore:
                        logger.debug(f"Running check: {check_cls.CHECK_ID}")
                        finding = await check_cls(client).run(target)
                        progress.advance(task)
                        return finding
                
                tasks = [
                    _run_check_with_progress(check_cls, target, progress, task)
                    for check_cls in self._check_classes
                ]
                findings = await asyncio.gather(*tasks, return_exceptions=True)

        for idx, item in enumerate(findings):
            if isinstance(item, Exception):
                check_id = self._check_classes[idx].CHECK_ID
                logger.error(f"Check {check_id} raised an exception: {item}")
            else:
                result.findings.append(item)

        result = result.model_copy(update={"finished_at": datetime.now(timezone.utc)})
        self._log_summary(result)
        return result

    @staticmethod
    def _log_summary(result: ScanResult) -> None:
        duration = (
            (result.finished_at - result.started_at).total_seconds()
            if result.finished_at else 0
        )
        logger.info(
            f"Scan complete | target={result.target.url} | "
            f"findings={len(result.findings)} | "
            f"vulnerable={len(result.vulnerable_findings)} | "
            f"risk_score={result.risk_score} | "
            f"duration={duration:.2f}s"
        )
'''

# 3. app/services/checks/base.py
files_to_write[r'D:\PROJELER\Python Projeler\Laravel Security  Scanner\app\services\checks\base.py'] = '''
"""
Abstract base class for all security checks.
Every check must implement `run()` and declare its metadata.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

import httpx

from app.models.scan import Finding, ScanTarget


class BaseCheck(ABC):
    """All security checks inherit from this."""

    # Subclasses must declare these
    CHECK_ID: str
    TITLE: str

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    @abstractmethod
    async def run(self, target: ScanTarget) -> Finding:
        """Execute the check and return a Finding."""
        ...

    def _build_url(self, base: str, path: str) -> str:
        """Append a path to a base URL, handling trailing slashes."""
        return base.rstrip("/") + "/" + path.lstrip("/")
'''

# 4. app/services/rate_limiter.py
files_to_write[r'D:\PROJELER\Python Projeler\Laravel Security  Scanner\app\services\rate_limiter.py'] = '''
"""
Rate limiting utilities for controlling request rates.
"""
from __future__ import annotations

import asyncio
import time
from typing import Optional, Callable, Any


class RateLimiter:
    """
    Token bucket rate limiter for controlling request rates.
    
    Args:
        rate: Number of requests allowed per second
        burst: Maximum burst size (token bucket capacity)
    """
    
    def __init__(self, rate: float = 10.0, burst: int = 10) -> None:
        self._rate = rate  # requests per second
        self._burst = burst  # max tokens
        self._tokens = float(burst)  # current tokens
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()
    
    async def acquire(self, tokens: int = 1) -> None:
        """
        Acquire tokens for making a request.
        Blocks until enough tokens are available.
        """
        async with self._lock:
            while self._tokens < tokens:
                # Refill tokens based on elapsed time
                now = time.monotonic()
                elapsed = now - self._last_refill
                refill = elapsed * self._rate
                if refill > 0:
                    self._tokens = min(self._burst, self._tokens + refill)
                    self._last_refill = now
                
                if self._tokens >= tokens:
                    break
                
                # Calculate sleep time
                sleep_time = (tokens - self._tokens) / self._rate
                # Release lock while sleeping
                self._lock.release()
                try:
                    await asyncio.sleep(sleep_time)
                finally:
                    await self._lock.acquire()
            
            self._tokens -= tokens


class RetryableClient:
    """
    Wrapper around httpx.AsyncClient that adds rate limiting and retry support.
    """
    
    def __init__(
        self,
        client: httpx.AsyncClient,
        rate_limiter: Optional[RateLimiter] = None,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        max_retry_delay: float = 10.0,
    ) -> None:
        self._client = client
        self._limiter = rate_limiter or RateLimiter()
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._max_retry_delay = max_retry_delay
    
    async def _request_with_retry(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """
        Make an HTTP request with retry logic.
        """
        last_exception = None
        
        for attempt in range(self._max_retries + 1):
            try:
                await self._limiter.acquire()
                
                # Get the method from client (get, post, etc.)
                request_method = getattr(self._client, method.lower())
                resp = await request_method(url, **kwargs)
                return resp
                
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                last_exception = exc
                
                if attempt < self._max_retries:
                    # Calculate delay with exponential backoff
                    delay = min(
                        self._retry_delay * (2 ** attempt),
                        self._max_retry_delay
                    )
                    await asyncio.sleep(delay)
                else:
                    raise
        
        # This should never be reached due to the raise in the loop
        raise last_exception  # type: ignore
    
    async def get(self, *args, **kwargs) -> httpx.Response:
        # Extract url from args or kwargs
        if 'url' in kwargs:
            url = kwargs['url']
        elif len(args) > 0:
            url = args[0]
        else:
            return await self._client.get(*args, **kwargs)
        
        return await self._request_with_retry("get", url, **kwargs)
    
    async def post(self, *args, **kwargs) -> httpx.Response:
        if 'url' in kwargs:
            url = kwargs['url']
        elif len(args) > 0:
            url = args[0]
        else:
            return await self._client.post(*args, **kwargs)
        
        return await self._request_with_retry("post", url, **kwargs)
    
    # Add other HTTP methods as needed
    async def put(self, *args, **kwargs) -> httpx.Response:
        if 'url' in kwargs:
            url = kwargs['url']
        elif len(args) > 0:
            url = args[0]
        else:
            return await self._client.put(*args, **kwargs)
        
        return await self._request_with_retry("put", url, **kwargs)
    
    async def delete(self, *args, **kwargs) -> httpx.Response:
        if 'url' in kwargs:
            url = kwargs['url']
        elif len(args) > 0:
            url = args[0]
        else:
            return await self._client.delete(*args, **kwargs)
        
        return await self._request_with_retry("delete", url, **kwargs)
    
    # Context manager support
    async def __aenter__(self):
        await self._client.__aenter__()
        return self
    
    async def __aexit__(self, *args):
        return await self._client.__aexit__(*args)
    
    # Proxy attribute access
    def __getattr__(self, name):
        return getattr(self._client, name)
'''

# 5. app/services/checks/__init__.py
files_to_write[r'D:\PROJELER\Python Projeler\Laravel Security  Scanner\app\services\checks\__init__.py'] = '''
"""
Check registry - central list of all available checks.
New checks only need to be added here; the ScannerService discovers them automatically.
"""
from app.services.checks.env_exposed import EnvExposedCheck
from app.services.checks.debug_mode import DebugModeCheck
from app.services.checks.security_headers import SecurityHeadersCheck
from app.services.checks.sensitive_files import SensitiveFilesCheck
from app.services.checks.insecure_config import InsecureConfigCheck
from app.services.checks.laravel_version import LaravelVersionCheck
from app.services.checks.telescope_exposed import TelescopeExposedCheck
from app.services.checks.debugbar_exposed import DebugbarExposedCheck
from app.services.checks.mix_manifest_exposed import MixManifestExposedCheck
from app.services.checks.horizon_exposed import HorizonExposedCheck
from app.services.checks.nova_exposed import NovaExposedCheck
from app.services.checks.csrf_protection import CSRFProtectionCheck
from app.services.checks.session_security import SessionSecurityCheck
from app.services.checks.rate_limiting import RateLimitingCheck
from app.services.checks.http_methods import HTTPMethodsCheck
from app.services.checks.composer_lock_cve import ComposerLockCVEScanCheck
from app.services.checks.base import BaseCheck


# Ordered list - critical checks run first
ALL_CHECKS: list[type[BaseCheck]] = [
    EnvExposedCheck,
    DebugModeCheck,
    SensitiveFilesCheck,
    SecurityHeadersCheck,
    InsecureConfigCheck,
    LaravelVersionCheck,
    TelescopeExposedCheck,
    DebugbarExposedCheck,
    MixManifestExposedCheck,
    HorizonExposedCheck,
    NovaExposedCheck,
    CSRFProtectionCheck,
    SessionSecurityCheck,
    RateLimitingCheck,
    HTTPMethodsCheck,
    ComposerLockCVEScanCheck,
]

__all__ = ["ALL_CHECKS", "BaseCheck"]
'''

# Now write all files
print("Writing files...")
for filepath, content in files_to_write.items():
    # Create directory if it doesn't exist
    dirpath = os.path.dirname(filepath)
    if dirpath and not os.path.exists(dirpath):
        os.makedirs(dirpath)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Written: {filepath}")

print("\nAll files written successfully!")
print("Running syntax check...")
