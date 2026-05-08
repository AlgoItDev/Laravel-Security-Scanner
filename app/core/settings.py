"""
Core application settings.
Loaded from environment variables or .env file via pydantic-settings.
"""
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # App
    APP_NAME: str = "Laravel Security Scanner"
    APP_VERSION: str = "1.5.0"
    DEBUG: bool = False

    # Scanner Behaviour
    SCAN_TIMEOUT: int = Field(default=10, description="HTTP request timeout in seconds")
    MAX_REDIRECTS: int = Field(default=3, description="Max HTTP redirects to follow")
    USER_AGENT: str = Field(
        default="Mozilla/5.0 (compatible; LaravelSecScanner/1.0)",
        description="User-Agent for HTTP requests",
    )
    CONCURRENT_CHECKS: int = Field(default=5, description="Max concurrent async checks")

    # Reporting
    REPORT_OUTPUT_DIR: Path = Field(default=Path("reports"), description="Report output directory")
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    LOG_DIR: Path = Field(default=Path("logs"), description="Log directory")

    # OSV API
    OSV_CACHE_FILE: Path = Field(default=Path("osv_cache.json"), description="OSV API cache file")
    OSV_CACHE_TTL_HOURS: int = Field(default=24, description="OSV cache TTL in hours")
    OSV_API_URL: str = "https://api.osv.dev/v1/query"
    OSV_ECOSYSTEM: str = "Packagist"


settings = Settings()
