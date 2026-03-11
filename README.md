# SecretGuard 🔐

> AI-enhanced secret detection and remediation tool for codebases

SecretGuard scans your source code repositories for exposed credentials, API keys, passwords, and sensitive data using intelligent pattern recognition that goes beyond traditional regex-based scanners.

## Features

- 🔍 **Multi-Pattern Detection**: Regex + AI-powered anomaly detection
- 🧠 **Smart Entropy Analysis**: Identifies high-randomness strings likely to be secrets
- 🛠️ **Remediation Advisor**: Get actionable fix suggestions
- ⚡ **Fast Scanning**: Efficient file traversal with gitignore support
- 📊 **Multiple Output Formats**: JSON, HTML, and Markdown reports
- 🔗 **CI/CD Ready**: Easy integration with GitHub Actions, GitLab CI, etc.

## Installation

```bash
pip install secretguard
```

Or install from source:

```bash
git clone https://github.com/adhamrashed/secretguard.git
cd secretguard
pip install -e .
```

## Quick Start

Scan a directory:

```bash
secretguard scan /path/to/project
```

Scan with specific output format:

```bash
secretguard scan /path/to/project --format json --output report.json
```

Scan with remediation suggestions:

```bash
secretguard scan /path/to/project --remediate
```

## Usage

### Basic Scan

```bash
secretguard scan .
```

### Advanced Options

```bash
# Exclude specific paths
secretguard scan . --exclude "*.test.js" --exclude "node_modules/*"

# Set minimum confidence threshold (0.0-1.0)
secretguard scan . --confidence 0.8

# Scan with verbose output
secretguard scan . --verbose

# Generate HTML report
secretguard scan . --format html --output security-report.html
```

### CI/CD Integration

#### GitHub Actions

```yaml
name: Secret Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install secretguard
      - run: secretguard scan . --format json --output scan-results.json
      - uses: actions/upload-artifact@v3
        with:
          name: scan-results
          path: scan-results.json
```

## How It Works

SecretGuard uses a multi-layered detection approach:

1. **Regex Pattern Matching**: Detects known secret patterns (AWS keys, GitHub tokens, etc.)
2. **Entropy Analysis**: Identifies high-randomness strings that could be passwords/keys
3. **AI Pattern Recognition**: ML model trained to identify unknown secret patterns
4. **Context Analysis**: Examines surrounding code for secret-like usage patterns

## Supported Secret Types

- AWS Access Keys & Secret Keys
- GitHub Personal Access Tokens
- Google Cloud API Keys
- Stripe API Keys
- Private Keys (RSA, SSH, PGP)
- Database Connection Strings
- OAuth Tokens
- JWT Tokens
- Generic API Keys
- Passwords (in various formats)

## Configuration

Create a `.secretguard.yml` in your project root:

```yaml
# Paths to exclude from scanning
exclude:
  - "node_modules/**"
  - "*.test.js"
  - "vendor/**"

# Minimum confidence threshold (0.0-1.0)
confidence_threshold: 0.75

# Custom patterns (regex)
custom_patterns:
  - name: "Custom API Key"
    pattern: "CUSTOM_[A-Z0-9]{32}"
    severity: high

# False positive patterns to ignore
ignore_patterns:
  - "example_api_key_here"
  - "REPLACE_WITH_YOUR_KEY"
```

## Development

### Setup

```bash
git clone https://github.com/adhamrashed/secretguard.git
cd secretguard
pip install -e ".[dev]"
```

### Run Tests

```bash
pytest
```

### Code Quality

```bash
# Format code
black .

# Lint
ruff check .

# Type check
mypy secretguard
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
Database Security Researcher  
[adhampx.com](https://adhampx.com) | [LinkedIn](https://linkedin.com/in/adhamrashed)

## Acknowledgments

- Inspired by tools like TruffleHog, GitLeaks, and Detect-Secrets
- Built with ❤️ and a passion for security

---

**⚠️ Security Notice**: This tool helps identify secrets but is not a replacement for proper secret management practices. Always use dedicated secret management solutions (HashiCorp Vault, AWS Secrets Manager, etc.) for production systems.
