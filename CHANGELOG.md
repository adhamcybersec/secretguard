# Changelog

All notable changes to SecretGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-03-11

### Added

- **Configuration File Support** (.secretguard.yml)
  - Load project-specific settings
  - Configure exclude patterns, confidence thresholds
  - Define custom secret patterns
  - Manage allowlists for false positives
  - Command: `secretguard init` to create default config

- **Allowlist Functionality**
  - Ignore specific file:line combinations
  - Pattern-based allowlisting
  - Inline ignore comments (`# secretguard:ignore`)
  - Global ignore patterns
  - Reduces false positives significantly

- **HTML Report Generation**
  - Beautiful, responsive HTML reports
  - Summary dashboard with statistics
  - Color-coded findings by severity
  - Remediation suggestions included
  - Self-contained (no external dependencies)
  - Command: `secretguard scan --format html --output report.html`

- **Pre-commit Hook Integration**
  - Prevent secrets from being committed
  - Scans only staged files (fast)
  - Easy installation: `secretguard install-hook`
  - Status check: `secretguard hook-status`
  - Uninstall: `secretguard uninstall-hook`
  - Bypass option: `git commit --no-verify`

- **Custom Pattern Support**
  - Define organization-specific secret patterns
  - Configure confidence, severity, and remediation per pattern
  - Regex-based pattern matching
  - Loaded from .secretguard.yml

- **New CLI Commands**
  - `secretguard init` - Create default configuration
  - `secretguard install-hook` - Install pre-commit hook
  - `secretguard uninstall-hook` - Remove pre-commit hook
  - `secretguard hook-status` - Check hook installation status

### Changed

- Updated CLI scan command with new options:
  - `--config` - Specify custom config file path
  - `--no-config` - Ignore config file
  - HTML added to `--format` options
- Improved verbose output with allowlist filtering stats
- Better error messages for configuration issues

### Dependencies

- Added `PyYAML>=6.0.0` for config file parsing
- Added `jinja2>=3.0.0` for HTML template rendering

### Testing

- Added 10 new tests (total: 20 tests)
- Config loader tests
- Allowlist manager tests
- All tests passing (100% pass rate)

## [0.1.0] - 2026-03-11

### Added

- Initial release
- Regex-based secret detection (15+ patterns)
- Entropy-based secret detection (Shannon entropy analysis)
- CLI interface with Typer
- Multiple output formats: Console, JSON, Markdown
- Rich console output with tables
- File traversal with binary file detection
- False positive filtering
- Remediation suggestions
- GitHub Actions CI/CD workflow
- Comprehensive documentation
- MIT License
- 10 unit tests with pytest

### Supported Secret Types

- AWS Access Keys & Secret Keys
- GitHub Personal Access Tokens
- Google Cloud API Keys
- Stripe API Keys
- Private Keys (RSA, SSH, PGP)
- Database Connection Strings (PostgreSQL, MySQL)
- OAuth Tokens & JWT Tokens
- Generic API Keys
- Hardcoded Passwords

---

[0.2.0]: https://github.com/adhamrashed/secretguard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/adhamrashed/secretguard/releases/tag/v0.1.0
