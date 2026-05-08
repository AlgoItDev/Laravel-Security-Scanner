"""
Source Fetcher - Auto-detect and fetch Laravel source code.

Attempts to fetch source code from:
1. Web-accessible paths (routes, config, etc.)
2. GitHub auto-detection via target URL
3. Common source file patterns
"""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

from app.core.logging import logger


class SourceFetcher:
    """Fetches Laravel source code from various sources."""

    LARAVEL_FILES = [
        "/routes/web.php",
        "/routes/api.php",
        "/routes/console.php",
        "/app/Http/Controllers/Controller.php",
        "/app/Http/Middleware/Authenticate.php",
        "/app/Providers/AppServiceProvider.php",
        "/app/Providers/RouteServiceProvider.php",
        "/config/app.php",
        "/config/database.php",
        "/config/auth.php",
        "/composer.json",
    ]

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client
        self._fetched_files: dict[str, str] = {}

    async def fetch_all(self, target_url: str) -> dict[str, str]:
        """Fetch all available Laravel source files."""
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        domain = parsed.netloc.replace("www.", "")

        await self._fetch_web_files(base_url)

        github_files = await self._fetch_github_repo(domain, target_url)
        if github_files:
            self._fetched_files.update(github_files)

        return self._fetched_files

    async def _fetch_web_files(self, base_url: str) -> None:
        """Fetch web-accessible Laravel files."""
        for file_path in self.LARAVEL_FILES:
            url = urljoin(base_url, file_path)
            try:
                resp = await self._client.get(url, timeout=10.0, follow_redirects=True)
                if resp.status_code == 200 and resp.text:
                    content_type = resp.headers.get("content-type", "")
                    if "php" in content_type or len(resp.text) > 50:
                        self._fetched_files[file_path] = resp.text
                        logger.debug(f"[SourceFetcher] Fetched {file_path}")
            except (httpx.RequestError, httpx.TimeoutException):
                continue

    async def _fetch_github_repo(self, domain: str, target_url: str) -> dict[str, str]:
        """Try to auto-detect GitHub repository."""
        source_files = {}

        project_name = self._extract_project_name(domain, target_url)
        if not project_name:
            return {}

        github_urls = [
            f"https://raw.githubusercontent.com/{project_name}/main",
            f"https://raw.githubusercontent.com/{project_name}/master",
            f"https://raw.githubusercontent.com/{project_name}/develop",
        ]

        for base_url in github_urls:
            for file_path in self.LARAVEL_FILES[:6]:
                url = urljoin(base_url, file_path.lstrip("/"))
                try:
                    resp = await self._client.get(url, timeout=10.0)
                    if resp.status_code == 200 and resp.text.startswith("<?php"):
                        full_path = f"github:{file_path}"
                        source_files[full_path] = resp.text
                        logger.debug(f"[SourceFetcher] GitHub: {file_path}")
                        break
                except (httpx.RequestError, httpx.TimeoutException):
                    continue

            if source_files:
                break

        return source_files

    def _extract_project_name(self, domain: str, target_url: str) -> str | None:
        """Extract project name from domain/URL."""
        common_patterns = [
            r"(?:github\.com/)?([^/]+/[^/]+)",  # org/repo or user/repo
            r"([a-zA-Z0-9_-]+)-laravel",
            r"laravel-([a-zA-Z0-9_-]+)",
        ]

        for pattern in common_patterns:
            match = re.search(pattern, domain.lower() + target_url.lower())
            if match:
                return match.group(1)

        return None

    @property
    def fetched_files(self) -> dict[str, str]:
        """Return all fetched files."""
        return self._fetched_files

    def has_source(self) -> bool:
        """Check if any source files were fetched."""
        return len(self._fetched_files) > 0