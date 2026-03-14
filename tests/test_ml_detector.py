"""Tests for ML detector integration"""

from pathlib import Path
from secretguard.detectors.ml_detector import MLDetector


def test_ml_detector_finds_secrets():
    detector = MLDetector()
    line = 'token = "dG9rZW4xMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFy"'
    findings = detector.detect(line, 1, Path("config.py"))
    # ML should flag the high-entropy base64 string
    assert len(findings) >= 1
    assert all(isinstance(f.confidence, float) for f in findings)


def test_ml_detector_ignores_normal_code():
    detector = MLDetector()
    line = "x = calculate_total(items)"
    findings = detector.detect(line, 1, Path("app.py"))
    assert len(findings) == 0


def test_ml_detector_respects_threshold():
    detector = MLDetector(threshold=0.99)
    line = 'key = "maybe_a_secret_maybe_not_1234"'
    findings = detector.detect(line, 1, Path("t.py"))
    assert len(findings) == 0
