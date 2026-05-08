# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.6.x   | :white_check_mark: |
| 1.5.x   | :white_check_mark: |
| < 1.5   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in Laravel Security Scanner, please report it responsibly.

### How to Report

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Email: bug@algoit.co.uk
3. Include as much detail as possible:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

### Response Timeline

- **Acknowledge**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix Timeline**: Depending on severity
  - Critical: 24-72 hours
  - High: 7-14 days
  - Medium/Low: Next release cycle

### Scope

This security policy applies to:
- The scanner core functionality
- CI/CD integration
- Report generation (JSON, HTML, SARIF)
- AST analysis engine

### Out of Scope

- Third-party dependencies (report to upstream maintainers)
- User-scanned applications
- Misuse of the scanner tool

## Security Updates

Security fixes are released as patch versions and announced in:
- GitHub Releases
- CHANGELOG.md
- PyPI release notes

## Vulnerability Disclosure

We follow coordinated disclosure practices. Please give us reasonable time to issue a fix before public disclosure.