"""Tests for pathspec/gitignore integration"""
import tempfile
from pathlib import Path
from secretguard.scanner.engine import ScanEngine


def test_respects_gitignore():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / ".gitignore").write_text("ignored_dir/\n*.log\n")
        (root / "ignored_dir").mkdir()
        (root / "ignored_dir" / "secrets.py").write_text('key = "AKIAIOSFODNN7REALKEY"\n')
        (root / "app.py").write_text('key = "AKIAIOSFODNN7REALKEY"\n')
        (root / "debug.log").write_text('key = "AKIAIOSFODNN7REALKEY"\n')

        engine = ScanEngine(confidence_threshold=0.0)
        results = engine.scan(root)

        scanned_files = {str(f.file_path) for f in results.findings}
        assert any("app.py" in f for f in scanned_files)
        assert not any("ignored_dir" in f for f in scanned_files)
        assert not any(".log" in f for f in scanned_files)


def test_no_gitignore_scans_everything():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "app.py").write_text('key = "AKIAIOSFODNN7REALKEY"\n')

        engine = ScanEngine(confidence_threshold=0.0)
        results = engine.scan(root)

        assert results.files_scanned >= 1
