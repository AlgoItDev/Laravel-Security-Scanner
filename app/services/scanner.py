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
