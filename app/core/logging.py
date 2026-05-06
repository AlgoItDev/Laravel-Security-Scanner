"""
Centralised logging configuration using loguru.
Provides structured, coloured console output + rotating file logs.
"""
import sys
from pathlib import Path

from loguru import logger

from app.core.settings import settings


def setup_logging() -> None:
    """Configure loguru handlers: stderr (console) + rotating file."""
    logger.remove()  # Remove default handler

    # Console — human-readable, coloured
    logger.add(
        sys.stderr,
        level=settings.LOG_LEVEL,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        ),
        colorize=True,
    )

    # File — structured, rotated daily / 10 MB
    log_path: Path = settings.LOG_DIR / "scanner.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger.add(
        str(log_path),
        level=settings.LOG_LEVEL,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        rotation="10 MB",
        retention="14 days",
        compression="zip",
        enqueue=True,  # thread-safe
    )


# Initialise on import
setup_logging()

__all__ = ["logger"]
