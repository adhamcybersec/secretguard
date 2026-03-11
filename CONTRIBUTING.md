# Contributing to SecretGuard

Thank you for your interest in contributing to SecretGuard! This guide will help you get started.

## Code of Conduct

Be respectful, inclusive, and professional in all interactions.

## How to Contribute

### Reporting Bugs

Before creating a bug report:
- Check [existing issues](https://github.com/adhamcybersec/secretguard/issues)
- Verify you're using the latest version
- Test with the default configuration

When reporting, include:
- Clear description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Python version and OS
- Sample code (sanitized, no real secrets!)
- SecretGuard version (`secretguard --version`)

### Suggesting Features

Feature ideas are welcome! Please:
- Check if already suggested
- Explain the problem it solves
- Provide examples/use cases
- Consider backwards compatibility

### Pull Requests

1. **Fork and clone**
   ```bash
   gh repo fork adhamcybersec/secretguard --clone
   cd secretguard
   ```

2. **Create a branch**
   ```bash
   git checkout -b feature/your-feature
   ```

3. **Make changes**
   - Follow existing code style
   - Add tests for new functionality
   - Update documentation

4. **Test thoroughly**
   ```bash
   # Run tests
   pytest
   
   # Format
   black .
   
   # Lint
   ruff check .
   
   # Type check
   mypy secretguard
   ```

5. **Commit with conventional commits**
   ```bash
   git commit -m "feat: Add new detection pattern for X"
   ```
   
   Prefixes:
   - `feat:` - New features
   - `fix:` - Bug fixes
   - `perf:` - Performance improvements
   - `docs:` - Documentation
   - `test:` - Tests
   - `refactor:` - Code restructuring
   - `chore:` - Maintenance

6. **Push and create PR**
   ```bash
   git push origin feature/your-feature
   gh pr create --fill
   ```

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/secretguard.git
cd secretguard

# Virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dev dependencies
pip install -e ".[dev]"
```

## Testing

```bash
# All tests
pytest

# With coverage
pytest --cov=secretguard --cov-report=html

# Specific module
pytest tests/test_detectors.py -v

# Run against demo files
secretguard scan demo-scan/
```

## Code Style

- **PEP 8** compliant
- **Type hints** for function signatures
- **Max line length:** 100 characters
- **Docstrings** for public APIs

Example:
```python
def detect_secrets(content: str, file_path: str) -> list[Finding]:
    """Detect secrets in file content.
    
    Args:
        content: File content to scan
        file_path: Path to the file
        
    Returns:
        List of detected secret findings
    """
    # Implementation
```

## Adding Detection Patterns

To add a new secret pattern:

1. **Add to `secretguard/detectors/regex_detector.py`:**
   ```python
   {
       "name": "New Service API Key",
       "pattern": r"newservice_[a-f0-9]{32}",
       "confidence": 0.9,
       "severity": "high",
       "remediation": "Revoke key and use environment variables"
   }
   ```

2. **Add test in `tests/test_detectors.py`:**
   ```python
   def test_detect_new_service_key():
       content = "API_KEY=newservice_abc123..."
       findings = detector.scan(content, "test.py")
       assert len(findings) > 0
       assert findings[0].secret_type == "New Service API Key"
   ```

3. **Update documentation** in README.md

## Project Structure

```
secretguard/
├── cli/              # CLI commands
├── config/           # Configuration handling
├── detectors/        # Detection engines
│   ├── regex_detector.py
│   ├── entropy_analyzer.py
│   └── ai_detector.py
├── scanners/         # File scanning
├── reporters/        # Report generation
└── utils/            # Utilities

tests/
├── test_detectors.py
├── test_scanners.py
└── fixtures/         # Test data
```

## Adding New Report Formats

To add a new output format:

1. Create `secretguard/reporters/format_reporter.py`
2. Extend `BaseReporter`
3. Implement `generate()` method
4. Add format option to CLI
5. Add tests and examples

## Documentation

- Update README for user-facing changes
- Add docstrings for new functions/classes
- Include examples in docs
- Update configuration reference if needed

## Security

**Important:** When contributing:
- Never commit real secrets in tests
- Use fake/dummy credentials
- Sanitize logs and error messages
- Test with safe data only

## Questions?

- Open a [Discussion](https://github.com/adhamcybersec/secretguard/discussions)
- Contact [@adhamcybersec](https://github.com/adhamcybersec)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
