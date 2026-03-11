"""Tests for data models"""
from pathlib import Path
from secretguard.models import SecretFinding, Severity


def test_severity_enum_values():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"


def test_finding_has_severity():
    finding = SecretFinding(
        file_path=Path("test.py"),
        line_number=1,
        line_content="secret",
        secret_type="Test",
        confidence=0.9,
        matched_text="secret",
        severity=Severity.HIGH,
    )
    assert finding.severity == Severity.HIGH


def test_finding_default_severity():
    finding = SecretFinding(
        file_path=Path("test.py"),
        line_number=1,
        line_content="secret",
        secret_type="Test",
        confidence=0.9,
        matched_text="secret",
    )
    assert finding.severity == Severity.MEDIUM
