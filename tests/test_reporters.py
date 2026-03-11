"""Tests for all reporters"""
import json
import tempfile
from pathlib import Path
from secretguard.models import ScanResults, SecretFinding, Severity
from secretguard.reporters.json_reporter import JSONReporter
from secretguard.reporters.markdown_reporter import MarkdownReporter
from secretguard.reporters.html_reporter import HTMLReporter


def _make_results():
    return ScanResults(
        findings=[
            SecretFinding(
                file_path=Path("app.py"), line_number=5,
                line_content='key = "secret"', secret_type="Generic API Key",
                confidence=0.85, matched_text="secret",
                severity=Severity.HIGH,
                remediation_suggestion="Use env vars",
            )
        ],
        files_scanned=10, total_secrets=1, scan_duration=0.5,
    )


def test_json_reporter_output():
    data = json.loads(JSONReporter().generate(_make_results()))
    assert data["summary"]["total_secrets"] == 1
    assert len(data["findings"]) == 1


def test_json_reporter_includes_severity():
    data = json.loads(JSONReporter().generate(_make_results()))
    assert data["findings"][0]["severity"] == "high"


def test_json_reporter_save():
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        path = Path(f.name)
    try:
        reporter = JSONReporter()
        reporter.save(reporter.generate(_make_results()), path)
        assert path.exists()
        saved = json.loads(path.read_text())
        assert saved["summary"]["total_secrets"] == 1
    finally:
        path.unlink()


def test_markdown_reporter_output():
    md = MarkdownReporter().generate(_make_results())
    assert "# SecretGuard Scan Report" in md
    assert "Generic API Key" in md


def test_markdown_remediation():
    md = MarkdownReporter().generate(_make_results(), include_remediation=True)
    assert "Remediation" in md
    assert "Use env vars" in md


def test_html_reporter_output():
    html = HTMLReporter().generate(_make_results())
    assert "<html" in html
    assert "Generic API Key" in html


def test_empty_results_reporters():
    empty = ScanResults()
    json_out = JSONReporter().generate(empty)
    assert '"total_secrets": 0' in json_out

    md_out = MarkdownReporter().generate(empty)
    assert "No Secrets Detected" in md_out

    html_out = HTMLReporter().generate(empty)
    assert "No Secrets Detected" in html_out
