"""Comprehensive tests for ScanEngine"""
import tempfile
from pathlib import Path
import pytest
from secretguard.scanner.engine import ScanEngine
from secretguard.models import ScanResults


def test_scan_single_file():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('key = "AKIAIOSFODNN7REALKEY"\n')
        tmp = Path(f.name)
    engine = ScanEngine(confidence_threshold=0.0)
    results = engine.scan(tmp)
    tmp.unlink()
    assert results.files_scanned == 1
    assert results.total_secrets >= 1


def test_scan_empty_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = ScanEngine()
        results = engine.scan(Path(tmpdir))
        assert results.files_scanned == 0
        assert results.total_secrets == 0


def test_scan_excludes_binary():
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
        f.write(b'\x00\x01\x02\x03binary content')
        tmp = Path(f.name)
    engine = ScanEngine()
    results = engine.scan(tmp)
    tmp.unlink()
    assert results.files_scanned == 0


def test_confidence_threshold_filters():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('password = "weak1234"\n')
        tmp = Path(f.name)
    low = ScanEngine(confidence_threshold=0.0).scan(tmp)
    high = ScanEngine(confidence_threshold=0.99).scan(tmp)
    tmp.unlink()
    assert low.total_secrets >= high.total_secrets


def test_scan_nonexistent_path():
    engine = ScanEngine()
    with pytest.raises(ValueError, match="neither a file nor directory"):
        engine.scan(Path("/nonexistent/path/that/does/not/exist"))


def test_exclude_patterns():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "secret.py").write_text('key = "AKIAIOSFODNN7REALKEY"\n')
        (root / "secret.test.py").write_text('key = "AKIAIOSFODNN7REALKEY"\n')

        engine = ScanEngine(exclude_patterns=[".test.py"], confidence_threshold=0.0)
        results = engine.scan(root)

        files = [str(f.file_path) for f in results.findings]
        assert not any(".test.py" in f for f in files)


def test_scan_duration_tracked():
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = ScanEngine()
        results = engine.scan(Path(tmpdir))
        assert results.scan_duration >= 0


def test_scan_returns_scan_results_type():
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = ScanEngine()
        results = engine.scan(Path(tmpdir))
        assert isinstance(results, ScanResults)


def test_verbose_mode():
    """Verbose mode should not crash"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('x = 42\n')
        tmp = Path(f.name)
    engine = ScanEngine(verbose=True)
    results = engine.scan(tmp)
    tmp.unlink()
    assert results.files_scanned == 1


def test_empty_file_scan():
    """Scanning an empty file should not crash"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('')
        tmp = Path(f.name)
    engine = ScanEngine()
    results = engine.scan(tmp)
    tmp.unlink()
    assert results.files_scanned == 1
    assert results.total_secrets == 0


def test_unicode_content():
    """Files with unicode content should be handled gracefully"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
        f.write('# Comment with unicode: \u00e9\u00e8\u00ea\u00eb \u00fc\u00f6\u00e4\n')
        f.write('password = "normal_password_here_1234"\n')
        tmp = Path(f.name)
    engine = ScanEngine(confidence_threshold=0.0)
    results = engine.scan(tmp)
    tmp.unlink()
    assert results.files_scanned == 1


def test_large_line():
    """Lines larger than typical should not crash the scanner"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('x = "' + 'A' * 10000 + '"\n')
        tmp = Path(f.name)
    engine = ScanEngine()
    results = engine.scan(tmp)
    tmp.unlink()
    assert results.files_scanned == 1


def test_binary_detection_accuracy():
    """Binary files with null bytes should be skipped"""
    with tempfile.NamedTemporaryFile(suffix='.dat', delete=False) as f:
        f.write(b'AKIAIOSFODNN7REALKEY\x00\x00binary')
        tmp = Path(f.name)
    engine = ScanEngine()
    results = engine.scan(tmp)
    tmp.unlink()
    assert results.files_scanned == 0


def test_symlink_skipped():
    """Symlinks should be skipped to prevent directory traversal"""
    import os
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        real_file = root / "real.py"
        real_file.write_text('key = "AKIAIOSFODNN7REALKEY"\n')
        link = root / "link.py"
        os.symlink(real_file, link)

        engine = ScanEngine(confidence_threshold=0.0)
        results = engine.scan(root)
        # Only the real file should be scanned, not the symlink
        assert results.files_scanned == 1
