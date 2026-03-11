"""
Tests for AllowlistManager
"""

from pathlib import Path
import pytest

from secretguard.config.allowlist import AllowlistManager
from secretguard.config.loader import AllowlistEntry
from secretguard.models import SecretFinding


@pytest.fixture
def sample_finding():
    """Create a sample finding for testing"""
    return SecretFinding(
        file_path=Path("src/config.py"),
        line_number=10,
        line_content='API_KEY = "secret123"',
        secret_type="Generic API Key",
        confidence=0.80,
        matched_text="secret123",
    )


def test_file_line_allowlist(sample_finding):
    """Test allowlist matching by file and line"""
    entry = AllowlistEntry(file="config.py", line=10, reason="Test")
    manager = AllowlistManager([entry], [])
    
    assert manager.should_ignore(sample_finding) is True


def test_file_only_allowlist(sample_finding):
    """Test allowlist matching by file only"""
    entry = AllowlistEntry(file="config.py", reason="All config secrets")
    manager = AllowlistManager([entry], [])
    
    assert manager.should_ignore(sample_finding) is True


def test_pattern_allowlist(sample_finding):
    """Test allowlist matching by pattern"""
    entry = AllowlistEntry(pattern="secret123", reason="Known test value")
    manager = AllowlistManager([entry], [])
    
    assert manager.should_ignore(sample_finding) is True


def test_ignore_patterns(sample_finding):
    """Test ignore patterns"""
    manager = AllowlistManager([], ["secret123"])
    
    assert manager.should_ignore(sample_finding) is True


def test_no_match(sample_finding):
    """Test when nothing matches"""
    entry = AllowlistEntry(file="other.py", line=20)
    manager = AllowlistManager([entry], ["other_pattern"])
    
    assert manager.should_ignore(sample_finding) is False


def test_inline_ignore():
    """Test inline ignore comment detection"""
    assert AllowlistManager.check_inline_ignore("password = 'test'  # secretguard:ignore") is True
    assert AllowlistManager.check_inline_ignore("password = 'test'  // secretguard:ignore") is True
    assert AllowlistManager.check_inline_ignore("password = 'test'") is False
