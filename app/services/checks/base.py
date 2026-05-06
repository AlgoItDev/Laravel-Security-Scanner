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
