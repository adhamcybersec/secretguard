"""Tests for pre-commit hook installer"""
import tempfile
from pathlib import Path
import pytest
from secretguard.hooks.installer import PreCommitInstaller


def _make_git_dir():
    tmpdir = tempfile.mkdtemp()
    git_dir = Path(tmpdir) / ".git" / "hooks"
    git_dir.mkdir(parents=True)
    return Path(tmpdir)


def test_install_hook():
    repo = _make_git_dir()
    assert PreCommitInstaller.install(repo) is True
    hook = repo / ".git" / "hooks" / "pre-commit"
    assert hook.exists()
    assert "SecretGuard" in hook.read_text()


def test_install_hook_idempotent():
    repo = _make_git_dir()
    PreCommitInstaller.install(repo)
    assert PreCommitInstaller.install(repo) is False


def test_uninstall_hook():
    repo = _make_git_dir()
    PreCommitInstaller.install(repo)
    assert PreCommitInstaller.uninstall(repo) is True
    assert not (repo / ".git" / "hooks" / "pre-commit").exists()


def test_uninstall_nonexistent():
    repo = _make_git_dir()
    assert PreCommitInstaller.uninstall(repo) is False


def test_is_installed():
    repo = _make_git_dir()
    assert PreCommitInstaller.is_installed(repo) is False
    PreCommitInstaller.install(repo)
    assert PreCommitInstaller.is_installed(repo) is True


def test_install_not_git_repo():
    with tempfile.TemporaryDirectory() as tmpdir:
        with pytest.raises(ValueError, match="not a git repository"):
            PreCommitInstaller.install(Path(tmpdir))
