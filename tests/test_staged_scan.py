"""Tests for staged-files scanning"""
import tempfile
from pathlib import Path
from secretguard.scanner.engine import ScanEngine


def test_get_staged_files_returns_list():
    engine = ScanEngine()
    # Should not crash even outside a git repo
    result = engine.get_staged_files(Path("/tmp"))
    assert isinstance(result, list)


def test_scan_specific_files():
    """Test scanning a specific list of files (used by --staged)"""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create two files, only scan one
        secret_file = Path(tmpdir) / "secret.py"
        secret_file.write_text('password = "SuperSecret123!"\n')

        clean_file = Path(tmpdir) / "clean.py"
        clean_file.write_text('x = 42\n')

        engine = ScanEngine(confidence_threshold=0.0)
        results = engine.scan_files([secret_file])

        assert results.files_scanned == 1
        assert results.total_secrets > 0
