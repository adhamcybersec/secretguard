"""Tests for SARIF reporter"""
import json
from pathlib import Path
from secretguard.reporters.sarif_reporter import SARIFReporter
from secretguard.models import ScanResults, SecretFinding, Severity


def test_sarif_valid_json():
    results = ScanResults(
        findings=[
            SecretFinding(
                file_path=Path("src/config.py"),
                line_number=10,
                line_content='API_KEY="secret"',
                secret_type="Generic API Key",
                confidence=0.85,
                matched_text="secret",
                severity=Severity.HIGH,
                remediation_suggestion="Use env vars",
            )
        ],
        files_scanned=5,
        total_secrets=1,
        scan_duration=1.23,
    )

    reporter = SARIFReporter()
    output = reporter.generate(results)
    sarif = json.loads(output)

    assert sarif["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert len(sarif["runs"][0]["results"]) == 1


def test_sarif_severity_mapping():
    results = ScanResults(
        findings=[
            SecretFinding(
                file_path=Path("t.py"), line_number=1, line_content="x",
                secret_type="Test", confidence=0.9, matched_text="x",
                severity=Severity.CRITICAL,
            )
        ],
        files_scanned=1, total_secrets=1, scan_duration=0.1,
    )

    reporter = SARIFReporter()
    sarif = json.loads(reporter.generate(results))
    assert sarif["runs"][0]["results"][0]["level"] == "error"


def test_sarif_empty_results():
    results = ScanResults()
    reporter = SARIFReporter()
    sarif = json.loads(reporter.generate(results))
    assert sarif["runs"][0]["results"] == []
