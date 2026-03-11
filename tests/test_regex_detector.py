"""
Tests for RegexDetector
"""

from pathlib import Path
import pytest

from secretguard.detectors.regex_detector import RegexDetector


@pytest.fixture
def detector():
    """Create a RegexDetector instance"""
    return RegexDetector()


def test_aws_access_key_detection(detector):
    """Test detection of AWS access keys"""
    line = 'AWS_ACCESS_KEY_ID="AKIAIOSFODNN7REALKEY"'
    findings = detector.detect(line, 10, Path("test.py"))
    
    assert len(findings) == 1
    assert findings[0].secret_type == "AWS Access Key ID"
    assert findings[0].confidence >= 0.90


def test_github_token_detection(detector):
    """Test detection of GitHub tokens"""
    line = "token = 'ghp_abcdefghijklmnopqrstuvwxyzABCDEF1234'"
    findings = detector.detect(line, 5, Path("config.py"))
    
    assert len(findings) == 1
    assert findings[0].secret_type == "GitHub Personal Access Token"


def test_false_positive_filtering(detector):
    """Test that false positives are filtered"""
    line = 'API_KEY="your_api_key_here"'
    findings = detector.detect(line, 1, Path("example.py"))
    
    # Should be filtered as false positive
    assert len(findings) == 0


def test_multiple_secrets_in_line(detector):
    """Test detection of multiple secrets in one line"""
    line = 'aws="AKIAIOSFODNN7REALKEY" github="ghp_abcdefghijklmnopqrstuvwxyzABCDEF1234"'
    findings = detector.detect(line, 20, Path("secrets.py"))
    
    assert len(findings) == 2


def test_rsa_private_key_detection(detector):
    """Test detection of RSA private keys"""
    line = "-----BEGIN RSA PRIVATE KEY-----"
    findings = detector.detect(line, 1, Path("key.pem"))
    
    assert len(findings) == 1
    assert findings[0].confidence >= 0.95
    assert "CRITICAL" in findings[0].remediation_suggestion
