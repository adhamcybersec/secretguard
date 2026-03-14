"""
Tests for EntropyDetector
"""

from pathlib import Path
import pytest

from secretguard.detectors.entropy_detector import EntropyDetector
from secretguard.utils.crypto import shannon_entropy, extract_candidates


@pytest.fixture
def detector():
    """Create an EntropyDetector instance"""
    return EntropyDetector()


def test_entropy_calculation(detector):
    """Test Shannon entropy calculation"""
    # Low entropy (repeated characters)
    assert shannon_entropy("aaaaaaaaaa") < 1.0

    # High entropy (random-looking)
    assert shannon_entropy("aB3$xY9!mN2@pQ7&") > 3.0


def test_high_entropy_detection(detector):
    """Test detection of high-entropy strings"""
    line = 'SECRET_KEY="dG9rZW4xMjM0NTY3ODkwYWJjZGVmZ2hpamts"'
    findings = detector.detect(line, 15, Path("config.py"))
    
    # Should detect the base64-like string
    assert len(findings) >= 1
    assert all(isinstance(f.confidence, float) for f in findings)


def test_uuid_exclusion(detector):
    """Test that UUIDs are deprioritized"""
    uuid = "550e8400-e29b-41d4-a716-446655440000"
    assert detector._looks_like_uuid(uuid) is True


def test_git_hash_exclusion(detector):
    """Test that Git hashes are deprioritized"""
    git_hash = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
    assert detector._looks_like_hash(git_hash) is True


def test_candidate_extraction(detector):
    """Test extraction of candidate strings"""
    line = 'api_key = "some_long_random_key_12345678901234567890"'
    candidates = extract_candidates(line)
    
    assert len(candidates) > 0
    assert any("some_long_random_key" in c for c in candidates)
