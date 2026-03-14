"""Tests for inline ignore support in scanner"""

import tempfile
from pathlib import Path
from secretguard.scanner.engine import ScanEngine


def test_inline_ignore_hash_comment():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write('password = "SuperSecret123!"  # secretguard:ignore\n')
        f.write('api_key = "AKIAIOSFODNN7REALKEY"\n')
        tmp = Path(f.name)

    engine = ScanEngine(confidence_threshold=0.0)
    results = engine.scan(tmp)
    tmp.unlink()

    # Line 1 should be ignored, line 2 should be found
    for finding in results.findings:
        assert finding.line_number != 1, "Inline-ignored line should not produce findings"


def test_inline_ignore_slash_comment():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
        f.write('const token = "ghp_abcdefghijklmnopqrstuvwxyzABCDEF1234"; // secretguard:ignore\n')
        tmp = Path(f.name)

    engine = ScanEngine(confidence_threshold=0.0)
    results = engine.scan(tmp)
    tmp.unlink()

    assert len(results.findings) == 0


def test_sg_ignore_shorthand():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write('password = "SuperSecret123!"  # sg:ignore\n')
        tmp = Path(f.name)

    engine = ScanEngine(confidence_threshold=0.0)
    results = engine.scan(tmp)
    tmp.unlink()

    assert len(results.findings) == 0
