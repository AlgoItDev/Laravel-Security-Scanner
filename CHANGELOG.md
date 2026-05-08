# Changelog

All notable changes to the Laravel Security Scanner project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-05-08

### Added
- **Hybrid Static + Dynamic Scanning** for reduced false positives:
  - `SourceFetcher` - Auto-detect and fetch Laravel source code:
    - Web-accessible files (routes, config, controllers)
    - GitHub repository auto-detection from target URL
  - `StaticCodeAnalyzer` - Analyze Laravel code patterns:
    - SQL injection pattern detection (concatenation, bindings)
    - XSS pattern detection (Blade raw output, unescaped echo)
    - Confidence scoring based on code patterns

- **`SQL_INJECTION`** check (replaces `SQL_INJECTION_BLIND`):
  - Hybrid approach: static + dynamic analysis
  - DANGER patterns: `DB::select("..." . $input)`
  - SAFE patterns: `DB::select("...", [$input])` (parameterized)
  - Confidence threshold: 60% for vulnerability reporting
  - False positive reduction for safe queries

- **`XSS`** check (replaces `XSS_REFLECTED`):
  - Hybrid approach: static + dynamic analysis
  - DANGER patterns: `{!! $var !!}` (Blade raw)
  - SAFE patterns: `{{ $var }}` (Blade auto-escaped)
  - Confidence threshold: 50% for vulnerability reporting

- **2 new unit tests** for hybrid checks

### Changed
- `SQL_INJECTION_BLIND` → `SQL_INJECTION` (hybrid)
- `XSS_REFLECTED` → `XSS` (hybrid)
- Updated `ALL_CHECKS` with new hybrid checks
- Total security checks: 22 (unchanged)

- **False Positive Reduction Logic**:
  ```
  DB::select("SELECT * FROM users")
  → Before: VULNERABLE (SQL error detected)
  → After: SAFE (no concatenation, no user input in code)
  
  DB::select("SELECT * " . $request->input('id'))
  → Before: VULNERABLE
  → After: VULNERABLE (static confirms + dynamic verifies)
  ```

### Fixed
- Syntax errors in `static_analyzer.py` (regex escaping)
- Added missing confidence tuple values in XSS patterns

## [1.3.0] - 2026-05-08

### Added
- **OSV API Integration** for `COMPOSER_CVE` check (hybrid approach):
  - First checks local `cve_database.json`
  - Falls back to OSV.dev API for unknown packages
  - Proper semver comparison using `packaging` library
  - File-based cache with configurable TTL (`--cache-ttl`)
  - OSV references and raw data added to findings

- **`--cache-ttl` CLI argument**:
  - Default: 24 hours
  - Cache file: `osv_cache.json` in project root
  - Set to 0 to disable cache

- **22 new unit tests** for OSV integration:
  - Version parsing tests
  - Cache TTL tests
  - OSV response parsing tests

### Changed
- `composer_lock_cve.py` refactored with OSV integration
- `models/scan.py` - Added `osv_references` and `osv_data` fields to Finding
- `settings.py` - Added OSV configuration (cache TTL, API URL, ecosystem)
- `scanner.py` - Added `cache_ttl` parameter support
- `requirements.txt` - Added `packaging>=24.0` dependency

### Fixed
- `datetime.utcnow()` deprecated warnings → `datetime.now(timezone.utc)` in composer_lock_cve.py
- `session_security.py` - Fixed cookie iteration (`resp.cookies.items()` instead of `.values()`)
- `http_methods.py` - Simplified method dispatch, removed OPTIONS from dangerous methods
- `csrf_protection.py` - Fixed regex to properly match GET forms and detect CSRF tokens
- Fixed 7 failing unit tests (session security, HTTP methods, CSRF protection)
- Total tests increased from 93 to 100

## [1.2.0] - 2026-05-08

### Added
- **6 New Security Checks**:
  - `SQL_INJECTION_BLIND` - Blind SQL injection vulnerability detection (CRITICAL)
    - Tests URL parameters with various SQL injection payloads
    - Detects SQL error patterns in responses
    - CVSS Score: 9.5
  - `XSS_REFLECTED` - Reflected Cross-Site Scripting detection (HIGH)
    - Tests URL parameters for XSS payload reflection
    - Checks for proper HTML encoding
    - CVSS Score: 7.5
  - `JWT_ANALYSIS` - JWT token security analysis (HIGH)
    - Detects weak algorithms (HS256)
    - Checks for missing expiration claims
    - Identifies none algorithm vulnerabilities
    - CVSS Score: 7.0
  - `CORS_MISCONFIG` - CORS misconfiguration detection (MEDIUM)
    - Detects wildcard origins (*)
    - Identifies credentials with wildcard origins
    - CVSS Score: 5.5
  - `OPEN_REDIRECT` - Open redirect vulnerability detection (MEDIUM)
    - Tests redirect parameters with external payloads
    - Analyzes Location header behavior
    - CVSS Score: 6.0
  - `SUBDOMAIN_ENUM` - Subdomain enumeration (INFO)
    - Discovers subdomains with common naming patterns
    - Identifies exposed internal services
    - 40+ common subdomain prefixes tested

- **Test Coverage**: Added unit tests for all 6 new checks
  - Total: 11 new tests added

### Changed
- `__init__.py` updated to include 6 new checks in ALL_CHECKS list
- Total security checks increased from 16 to 22

### Fixed
- Syntax warning in `open_redirect.py` (invalid escape sequence)
- Fixed corrupted test files with double underscores (pytest__, httpx__, etc.)

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