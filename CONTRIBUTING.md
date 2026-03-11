# Contributing to SecretGuard

Thank you for your interest in contributing to SecretGuard! 🎉

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Python version, etc.)

### Suggesting Features

Feature requests are welcome! Please:
- Explain the use case
- Describe the proposed solution
- Discuss alternatives you've considered

### Code Contributions

1. **Fork the repository**
   ```bash
   git clone https://github.com/adhamrashed/secretguard.git
   cd secretguard
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install development dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

5. **Make your changes**
   - Write clean, documented code
   - Add tests for new functionality
   - Update documentation as needed

6. **Run tests**
   ```bash
   pytest
   ```

7. **Check code quality**
   ```bash
   # Format code
   black .

   # Lint
   ruff check .

   # Type check
   mypy secretguard
   ```

8. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add awesome new feature"
   ```

   We follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` New feature
   - `fix:` Bug fix
   - `docs:` Documentation changes
   - `test:` Adding tests
   - `refactor:` Code refactoring
   - `chore:` Maintenance tasks

9. **Push and create a Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

   Then open a PR on GitHub with:
   - Clear title and description
   - Link to related issues
   - Screenshots (if UI-related)

## Code Standards

### Style Guide

- Follow PEP 8
- Use type hints
- Maximum line length: 100 characters
- Use meaningful variable names

### Testing

- Write unit tests for new code
- Aim for >80% code coverage
- Test edge cases and error conditions

### Documentation

- Add docstrings to functions and classes
- Update README if adding features
- Include examples in docstrings

## Adding New Detection Patterns

To add a new secret detection pattern:

1. Add pattern to `secretguard/detectors/regex_detector.py`:
   ```python
   (
       "Pattern Name",
       r"regex_pattern_here",
       0.95,  # confidence score
       "Remediation advice here",
   ),
   ```

2. Add test in `tests/test_regex_detector.py`:
   ```python
   def test_your_pattern_detection(detector):
       line = 'example line with secret'
       findings = detector.detect(line, 1, Path("test.py"))
       assert len(findings) == 1
       assert findings[0].secret_type == "Pattern Name"
   ```

3. Update README with supported secret type

## Questions?

Feel free to open an issue or reach out to [adham@adhampx.com](mailto:adham@adhampx.com).

Thank you for contributing! 🚀
