# Changelog

All notable changes to SecretGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2026-03-14

### Added

- **Live credential verification** — `--verify` flag on `secretguard scan` attempts live verification of detected credentials (GitHub tokens via API, AWS keys via STS)
- **GitLab CI template** — `ci-templates/gitlab-ci.yml` for easy GitLab CI/CD integration with SARIF output
- **Enhanced SARIF output** — tool version, `fullDescription`, `properties.tags`, and `properties.precision` on rules

### Changed

- **Standardized GitHub URLs** — all URLs point to `adhamcybersec/secretguard`
- **Development status** — upgraded classifier to `"Development Status :: 4 - Beta"`
- **Extracted regex patterns** — patterns moved to `secretguard/detectors/patterns.py` data module, grouped by provider
- **Extracted HTML template** — moved to `secretguard/reporters/templates/report.html`, loaded via Jinja2 `FileSystemLoader`
- Added `Changelog` URL to PyPI project URLs
- Added `[project.optional-dependencies] verify = ["boto3>=1.26.0"]`

## [0.7.0] - 2026-03-14

### Added

- **Expanded ML training data** — 210 samples (100 secrets, 110 non-secrets) covering AWS, GitHub, Stripe, Google, SendGrid, Slack, JWTs, private keys, DB connection strings, and more
- **ML evaluation command** — `secretguard ml-evaluate` runs 5-fold stratified cross-validation and displays precision/recall/F1/accuracy (F1: 0.96)
- **Pre-commit framework integration** — `.pre-commit-hooks.yaml` for standard pre-commit framework usage
- **Git history scanning** — `secretguard scan-history` scans past commits for secrets with `--max-commits` and `--branch` flags
- Commit hash and author fields on `SecretFinding` for git history results
- `scan` command path argument now defaults to `"."` for pre-commit compatibility

### Changed

- ML model cache invalidated due to expanded training data
- Pre-commit hook installer now includes deprecation notice in favor of pre-commit framework

## [0.6.0] - 2026-03-14

### Security

- **Secret masking in all reporter outputs** — secrets are masked (first/last 4 chars visible) in JSON, Markdown, HTML, and SARIF reports to prevent leaking raw credentials in report files
- **Symlink safety** — scanner now skips symlinks and validates that resolved paths stay within the scan directory, preventing directory traversal attacks
- **Secure file permissions** — report files are written with `0o600` (owner-only) permissions
- **Hardened inline ignore** — `secretguard:ignore` markers now require a comment delimiter (`#`, `//`, `/*`, `--`) to prevent abuse via string values

### Fixed

- Fixed vacuous test assertions (`>= 0` replaced with `>= 1`) in entropy and ML detector tests
- Scan errors are now tracked in `ScanResults.scan_errors` instead of being silently swallowed
- CLI displays error count after scan when errors occur

### Changed

- **Deduplicated shared code** — `shannon_entropy()` and `extract_candidates()` extracted to `secretguard/utils/crypto.py`, removing 3 copies
- **O(1) set-based deduplication** — replaced O(n^2) finding dedup loop with set lookup
- **Streaming file reading** — files are now read line-by-line instead of loading entire contents into memory
- **ML model caching** — trained Random Forest model is cached to `~/.cache/secretguard/models/` using joblib, avoiding retraining on every scan

### Testing

- Added edge case tests: empty files, unicode content, large lines, binary detection, symlink handling
- Added masking utility tests
- Added shared utility tests
- 103 tests total, all passing

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
