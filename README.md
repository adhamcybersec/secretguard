# SecretGuard 🔐

> AI-enhanced secret detection and remediation tool for codebases

[![PyPI version](https://img.shields.io/pypi/v/secretguard)](https://pypi.org/project/secretguard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![GitHub Issues](https://img.shields.io/github/issues/adhamcybersec/secretguard)](https://github.com/adhamcybersec/secretguard/issues)
[![GitHub Stars](https://img.shields.io/github/stars/adhamcybersec/secretguard)](https://github.com/adhamcybersec/secretguard/stargazers)

SecretGuard scans your source code for exposed credentials, API keys, passwords, and sensitive data using a triple-layer detection engine: regex patterns, Shannon entropy analysis, and a Random Forest ML classifier (F1: 0.96).

## Features

- **Triple-Layer Detection**: 28+ regex patterns, entropy analysis, and ML classifier working together
- **ML-Powered**: Random Forest model trained on 210 samples with cross-validation (Precision: 0.95, Recall: 0.97)
- **Secret Masking**: All report outputs mask detected secrets to prevent secondary leakage
- **Git History Scanning**: Scan past commits for secrets with `scan-history`
- **Live Verification**: `--verify` flag checks if detected credentials are still active (GitHub, AWS)
- **SARIF Output**: IDE and CI/CD integration with enriched SARIF 2.1.0 reports
- **Pre-commit Framework**: Native `.pre-commit-hooks.yaml` for standard pre-commit integration
- **Secure by Default**: Report files written with 0o600 permissions, symlinks skipped
- **Multiple Formats**: Console, JSON, Markdown, HTML, and SARIF output
- **Configurable**: Project-specific settings via `.secretguard.yml`
- **Allowlist & Inline Ignore**: Reduce false positives with file/pattern allowlists and `# secretguard:ignore`

## Installation

```bash
pip install secretguard
```

With live credential verification support:

```bash
pip install secretguard[verify]
```

## Quick Start

```bash
# Scan current directory
secretguard scan

# Scan a specific path with JSON output
secretguard scan /path/to/project --format json --output report.json

# Generate HTML report
secretguard scan . --format html --output report.html

# Scan with remediation suggestions
secretguard scan . --remediate

# Disable ML for faster scans
secretguard scan . --no-ml

# Verify detected credentials are active
secretguard scan . --verify

# Scan git history for leaked secrets
secretguard scan-history --max-commits 200

# Evaluate ML model performance
secretguard ml-evaluate
```

## Pre-commit Framework Integration

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/adhamcybersec/secretguard
    rev: v0.8.0
    hooks:
      - id: secretguard
```

Then run:

```bash
pre-commit install
```

Alternatively, use the built-in hook installer:

```bash
secretguard install-hook
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Secret Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install secretguard
      - run: secretguard scan . --format sarif --output results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/adhamcybersec/secretguard/master/ci-templates/gitlab-ci.yml'
```

Or add manually:

```yaml
secretguard-scan:
  stage: test
  image: python:3.12-slim
  before_script:
    - pip install secretguard
  script:
    - secretguard scan . --format sarif --output gl-secretguard-report.sarif
  artifacts:
    reports:
      sast: gl-secretguard-report.sarif
```

## How It Works

SecretGuard uses a triple-layer detection approach:

1. **Regex Pattern Matching** (28+ patterns): Detects known secret formats — AWS keys, GitHub tokens, Stripe keys, private key headers, database connection strings, and more. Patterns are grouped by provider in `secretguard/detectors/patterns.py`.

2. **Shannon Entropy Analysis**: Identifies high-randomness strings (entropy >= 4.0) that could be passwords or keys. Applies confidence scoring based on entropy, length, and character diversity, with penalties for UUIDs and git hashes.

3. **ML Classification** (Random Forest): A classifier trained on 210 labeled samples catches secrets that don't match known patterns. Features include entropy, character ratios, diversity, common prefixes, and consecutive character runs. Cross-validated at F1: 0.96.

Results are deduplicated across detectors using O(1) set-based lookup, and the ML model is cached to disk for fast subsequent scans.

## Supported Secret Types

| Category | Types |
|----------|-------|
| **Cloud** | AWS Access Keys, AWS Secret Keys, Google API Keys, Azure Storage Keys |
| **Git Platforms** | GitHub PATs, GitHub OAuth, GitHub Fine-Grained, GitLab PATs |
| **Payment** | Stripe Live & Test Keys |
| **Communication** | Slack Webhooks, Slack Bot Tokens, Discord Bot Tokens |
| **Email** | SendGrid, Twilio, Mailgun API Keys |
| **Packages** | npm Tokens, PyPI Tokens |
| **Crypto** | RSA/SSH/PGP/EC/DSA Private Keys |
| **Databases** | PostgreSQL, MySQL, MongoDB, Redis connection strings |
| **Auth** | JWT Tokens, OAuth Bearer Tokens, Generic API Keys, Passwords |

## Configuration

Create `.secretguard.yml` with `secretguard init`, or manually:

```yaml
exclude:
  - "node_modules/**"
  - "*.test.js"
  - "vendor/**"

confidence_threshold: 0.75

custom_patterns:
  - name: "Internal API Key"
    pattern: "INTERNAL_[A-Z0-9]{32}"
    confidence: 0.95
    severity: high
    remediation: "Move to environment variables"

allowlist:
  - file: "tests/fixtures/secrets.py"
    line: 10
    reason: "Test fixture"
  - pattern: "example.*key"
    reason: "Documentation examples"

ignore_patterns:
  - "example_api_key_here"
  - "REPLACE_WITH_YOUR_KEY"
```

### Inline Ignoring

Ignore specific lines using comment markers:

```python
password = "test123"  # secretguard:ignore
api_key = "demo_key"  # sg:ignore
```

The marker must appear after a comment delimiter (`#`, `//`, `/*`, `--`) to prevent abuse via string values.

## CLI Reference

| Command | Description |
|---------|-------------|
| `secretguard scan [PATH]` | Scan files for secrets (default: `.`) |
| `secretguard scan-history` | Scan git commit history |
| `secretguard ml-evaluate` | Show ML model cross-validation metrics |
| `secretguard init` | Create `.secretguard.yml` template |
| `secretguard install-hook` | Install git pre-commit hook |
| `secretguard uninstall-hook` | Remove pre-commit hook |
| `secretguard hook-status` | Check hook installation |
| `secretguard version` | Show version |

### Scan Options

| Flag | Description |
|------|-------------|
| `--format` | Output format: `console`, `json`, `markdown`, `html`, `sarif` |
| `--output PATH` | Save report to file |
| `--confidence FLOAT` | Minimum confidence threshold (0.0-1.0) |
| `--exclude PATTERN` | Exclude file patterns |
| `--no-ml` | Disable ML detection (faster) |
| `--verify` | Attempt live credential verification |
| `--staged` | Only scan git-staged files |
| `--remediate` | Include fix suggestions |
| `--verbose` | Verbose output |
| `--config PATH` | Custom config file path |
| `--no-config` | Ignore config file |

## Security Features

- **Secret masking**: Reports never contain raw secret values (first/last 4 chars visible)
- **Secure permissions**: Report files are created with `0o600` (owner-only read/write)
- **Symlink protection**: Scanner skips symlinks and validates resolved paths stay within scan directory
- **Hardened ignores**: `secretguard:ignore` markers only work inside comments, not string values
- **Opt-in verification**: Live credential checks require explicit `--verify` flag

## Roadmap

SecretGuard is actively developed. Here's what's coming next:

- **v0.9.0** — MCP server for AI agent integration (Claude Code, Cursor, Windsurf), Python SDK, VS Code extension
- **v1.0.0** — PyPI stable release, Docker image, 90%+ test coverage, documentation site
- **v1.1.0** — Transformer-based ML model, additional credential verifiers (Stripe, Google, Slack), custom ML training
- **v1.2.0** — Team web dashboard, policy engine, multi-repo scanning, secret rotation assistance
- **v1.3.0** — Bitbucket/Jenkins integrations, Terraform/IaC scanning, Jupyter notebook support

## Development

```bash
git clone https://github.com/adhamcybersec/secretguard.git
cd secretguard
pip install -e ".[dev]"
pytest
```

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) first.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

**Adham Rashed**
Cybersecurity Researcher
[adhampx.com](https://adhampx.com) | [GitHub](https://github.com/adhamcybersec)

---

**Security Notice**: SecretGuard helps identify secrets but is not a replacement for proper secret management. Always use dedicated solutions (HashiCorp Vault, AWS Secrets Manager, etc.) for production systems.
