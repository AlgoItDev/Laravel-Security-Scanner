# Changelog

All notable changes to the Laravel Security Scanner project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Nothing unreleased yet.

## [1.1.0] - 2026-05-06

### Added
- **11 New Security Checks**:
  - `LaravelVersionCheck` - Detects Laravel version disclosure (MEDIUM)
  - `TelescopeExposedCheck` - Detects Laravel Telescope exposure (HIGH)
  - `DebugbarExposedCheck` - Detects Laravel Debugbar exposure (MEDIUM)
  - `MixManifestExposedCheck` - Detects Laravel Mix manifest exposure (LOW)
  - `HorizonExposedCheck` - Detects Laravel Horizon exposure (MEDIUM)
  - `NovaExposedCheck` - Detects Laravel Nova exposure (HIGH)
  - `CSRFProtectionCheck` - Checks CSRF protection (HIGH)
  - `SessionSecurityCheck` - Checks session security config (MEDIUM)
  - `RateLimitingCheck` - Checks rate limiting (MEDIUM)
  - `HTTPMethodsCheck` - Checks dangerous HTTP methods (MEDIUM)
  - `ComposerLockCVEScanCheck` - Scans composer.lock for CVEs (CRITICAL)

- **5 Report Formats**:
  - Console (coloured terminal output)
  - JSON (structured data)
  - TXT (plain text)
  - HTML (interactive web report)
  - SARIF (for GitHub Security tab integration)

- **Performance Improvements**:
  - Rate Limiting with `RateLimiter` class (token bucket algorithm)
  - Retry mechanism with `RetryableClient` (exponential backoff)
  - Connection Pooling with httpx.Limits
  - Concurrent checks with asyncio
  - Progress bar with `rich` library

- **CI/CD Integration**:
  - GitHub Actions workflow (`.github/workflows/ci.yml`)
  - Automated scanning on schedule and push
  - SARIF upload to GitHub Security tab
  - Multi-Python version testing (3.10, 3.11, 3.12)

- **CLI Improvements**:
  - `--checks` parameter to select specific checks
  - `--format` now supports: console, json, txt, html, sarif, all
  - Progress bar during scans
  - Coloured console output

- **Documentation**:
  - Updated README.md with new checks and features
  - Added project structure documentation
  - Added usage examples for all formats

### Changed
- Updated `ScannerService` to support:
  - Check filtering by ID
  - Rate-limited client
  - Retry mechanism
  
- Updated `ReportService` to support:
  - HTML report generation
  - SARIF format for GitHub Security tab

- Updated `BaseCheck` to remove unnecessary retry code (now handled by `RetryableClient`)

### Fixed
- `datetime.utcnow()` → `datetime.now(timezone.utc)` in scanner.py and models/scan.py
- Unicode encoding errors in console output (replaced problematic characters)
- SARIF file generation
- Test coverage: 51 tests passing

### Security
- Added 11 new security checks for comprehensive Laravel security auditing
- Added rate limiting to prevent overwhelming target servers
- Added retry mechanism with exponential backoff

## [1.0.0] - 2026-04-23 (Initial Release)

### Added
- Initial release with 5 security checks:
  - `EnvExposedCheck` - .env file exposure (CRITICAL)
  - `DebugModeCheck` - Laravel debug mode (HIGH)
  - `SensitiveFilesCheck` - Sensitive files exposure (HIGH)
  - `SecurityHeadersCheck` - Missing HTTP security headers (MEDIUM)
  - `InsecureConfigCheck` - CORS, cookies, server headers (MEDIUM)

- Basic reporting: Console, JSON, TXT
- Async scanning with httpx
- Loguru logging
- Pydantic settings management
