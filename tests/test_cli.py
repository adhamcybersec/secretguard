"""Tests for CLI commands"""
import os
import tempfile
from pathlib import Path
from typer.testing import CliRunner
from secretguard.cli.main import app

runner = CliRunner()


def test_scan_clean_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        result = runner.invoke(app, ["scan", tmpdir, "--no-config"])
        assert result.exit_code == 0
        assert "No secrets detected" in result.output


def test_scan_nonexistent_path():
    result = runner.invoke(app, ["scan", "/nonexistent/path/xyz123"])
    assert result.exit_code == 1


def test_scan_with_secrets():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write('key = "AKIAIOSFODNN7REALKEY"\n')
        tmp = Path(f.name)
    try:
        result = runner.invoke(app, ["scan", str(tmp), "--no-config"])
        assert result.exit_code == 1
        assert "potential secrets" in result.output
    finally:
        tmp.unlink()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "SecretGuard" in result.output


def test_scan_json_format():
    with tempfile.TemporaryDirectory() as tmpdir:
        result = runner.invoke(app, ["scan", tmpdir, "--format", "json", "--no-config"])
        assert result.exit_code == 0


def test_scan_invalid_format():
    with tempfile.TemporaryDirectory() as tmpdir:
        result = runner.invoke(app, ["scan", tmpdir, "--format", "invalid", "--no-config"])
        assert result.exit_code == 1


def test_init_creates_config():
    with tempfile.TemporaryDirectory() as tmpdir:
        original_dir = os.getcwd()
        try:
            os.chdir(tmpdir)
            result = runner.invoke(app, ["init"])
            assert result.exit_code == 0
            assert (Path(tmpdir) / ".secretguard.yml").exists()
        finally:
            os.chdir(original_dir)
