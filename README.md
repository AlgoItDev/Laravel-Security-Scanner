# 🔍 Laravel Security Scanner

Production-grade Python CLI tool for auditing Laravel web applications for common security misconfigurations.

## 🎯 What It Checks

| Check ID | Title | Severity |
|---|---|---|
| `ENV_EXPOSED` | .env file publicly accessible | 🔴 CRITICAL |
| `DEBUG_MODE` | Laravel debug mode enabled | 🔴 HIGH |
| `SENSITIVE_FILES` | Sensitive files/directories exposed | 🔴 HIGH |
| `SECURITY_HEADERS` | Missing HTTP security headers | 🟠 MEDIUM |
| `INSECURE_CONFIG` | CORS, cookie flags, server headers | 🟠 MEDIUM |
| `LARAVEL_VERSION` | Laravel version disclosure | 🟠 MEDIUM |
| `TELESCOPE_EXPOSED` | Laravel Telescope exposed | 🔴 HIGH |
| `DEBUGBAR_EXPOSED` | Laravel Debugbar exposed | 🟠 MEDIUM |
| `MIX_MANIFEST_EXPOSED` | Laravel Mix manifest exposed | 🟢 LOW |
| `HORIZON_EXPOSED` | Laravel Horizon exposed | 🟠 MEDIUM |
| `NOVA_EXPOSED` | Laravel Nova exposed | 🔴 HIGH |

## 📁 Project Structure

```
laravel-security-scanner/
├── app/
│   ├── core/
│   │   ├── settings.py        # Pydantic settings + .env loader
│   │   └── logging.py         # Loguru structured logging
│   ├── models/
│   │   └── scan.py            # ScanTarget, Finding, ScanResult models
│   ├── services/
│   │   ├── scanner.py         # ScannerService — async orchestrator
│   │   ├── reporter.py        # Console / JSON / TXT / HTML report generator
│   │   └── checks/
│   │       ├── base.py        # BaseCheck abstract class
│   │       ├── __init__.py    # Check registry (ALL_CHECKS)
│   │       ├── env_exposed.py
│   │       ├── debug_mode.py
│   │       ├── security_headers.py
│   │       ├── sensitive_files.py
│   │       ├── insecure_config.py
│   │       ├── laravel_version.py
│   │       ├── telescope_exposed.py
│   │       ├── debugbar_exposed.py
│   │       ├── mix_manifest_exposed.py
│   │       ├── horizon_exposed.py
│   │       └── nova_exposed.py
│   └── utils/
│       └── url.py             # URL normalisation
├── tests/
│   └── unit/
│       ├── test_models.py
│       ├── test_url_utils.py
│       ├── test_env_check.py
│       ├── test_laravel_version.py
│       ├── test_telescope_exposed.py
│       ├── test_debugbar_exposed.py
│       └── test_mix_manifest_exposed.py
├── .github/
│   └── workflows/
│       └── ci.yml               # GitHub Actions CI/CD
├── logs/
├── reports/
├── .env.example
├── requirements.txt
├── pytest.ini
└── main.py
```

## 🔧 Setup

```bash
# 1. Clone / download
git clone https://github.com/AlgoItDev/Laravel-Security--Scanner.git
cd laravel-security-scanner

# 2. Create virtualenv
python3.11 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure
cp .env.example .env
# Edit .env as needed
```

## 🚀 Usage

```bash
# Scan a single target (all formats)
python main.py https://your-laravel-app.com

# Multiple targets
python main.py https://app1.com https://app2.com

# JSON report only
python main.py https://app.com --format json --output ./my-reports

# HTML report only
python main.py https://app.com --format html --output ./my-reports

# SARIF report for GitHub Security tab
python main.py https://app.com --format sarif --output ./my-reports

# Skip SSL verification (e.g. staging with self-signed cert)
python main.py https://staging.app.com --no-ssl-verify

# Set custom timeout
python main.py https://app.com --timeout 20
```

## 🎯 Features

- **Multiple Output Formats**: Console, JSON, TXT, HTML, and SARIF reports
- **Progress Bar**: Real-time progress tracking with rich library during scans
- **CI/CD Integration**: GitHub Actions workflow included (`.github/workflows/ci.yml`) (Passive)
- **Async Scanning**: Concurrent checks for faster results
- **Comprehensive Checks**: 10 security checks covering critical Laravel vulnerabilities
- **SARIF Support**: SARIF format output for GitHub Security tab integration
- **Rate Limiting**: Built-in rate limiter to avoid overwhelming target servers
- **Retry Mechanism**: Automatic retry for failed requests with exponential backoff
- **Connection Pooling**: HTTP connection reuse for better performance

## 🧪 Running Tests

```bash
pytest tests/unit/ -v
pytest tests/ -v --tb=short   # all tests
```

## ➕ Adding a New Check

1. Create `app/services/checks/my_check.py` extending `BaseCheck`
2. Implement `async def run(self, target: ScanTarget) -> Finding`
3. Register in `app/services/checks/__init__.py → ALL_CHECKS`

That's it — the `ScannerService` picks it up automatically.

## 📤 Exit Codes

| Code | Meaning |
|---|---|
| `0` | All targets clean |
| `1` | One or more vulnerabilities found |

Useful for CI/CD pipelines: `python main.py https://app.com || echo "Security issues found!"`
