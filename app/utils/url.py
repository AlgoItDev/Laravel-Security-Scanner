"""
URL utilities — normalise and validate scan targets.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse


class InvalidURLError(ValueError):
    """Raised when a URL cannot be normalised into a valid HTTP(S) target."""


def normalise_url(raw: str) -> str:
    """
    Normalise a raw URL string into a canonical form suitable for scanning.

    - Strips trailing slashes
    - Adds `https://` scheme if missing
    - Validates that the result is a reachable HTTP/HTTPS URL

    Args:
        raw: Raw URL string, e.g. "example.com" or "http://example.com/app"

    Returns:
        Normalised URL string, e.g. "https://example.com"

    Raises:
        InvalidURLError: If the URL cannot be made valid.
    """
    raw = raw.strip()
    if not raw:
        raise InvalidURLError("Empty URL provided.")

    # Add scheme if missing
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "https://" + raw

    parsed = urlparse(raw)

    if not parsed.netloc:
        raise InvalidURLError(f"Cannot determine host from URL: {raw!r}")

    # Rebuild without trailing slash on path
    normalised = urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path.rstrip("/"),
        parsed.params,
        parsed.query,
        "",  # drop fragment
    ))

    return normalised
