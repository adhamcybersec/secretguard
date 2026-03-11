"""Tests for new secret patterns added in v0.3.0"""
from pathlib import Path
import pytest
from secretguard.detectors.regex_detector import RegexDetector
from secretguard.models import Severity


@pytest.fixture
def detector():
    return RegexDetector()


def test_slack_webhook(detector):
    line = 'url = "https://hooks.slack.com/services/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"'
    findings = detector.detect(line, 1, Path("t.py"))
    assert any("Slack" in f.secret_type for f in findings)


def test_slack_bot_token(detector):
    line = 'SLACK_TOKEN="xoxb-8837610274-9927384610283-AbCdEfGhIjKlMnOpQrStUvWx"'
    findings = detector.detect(line, 1, Path("t.py"))
    assert any("Slack" in f.secret_type for f in findings)


def test_azure_storage_key(detector):
    line = 'conn = "DefaultEndpointProtocol=https;AccountName=myaccount;AccountKey=abc9def8ghi7jkl6mno5pqr4stu3vwx2yz1ABC0DEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn=="'
    findings = detector.detect(line, 1, Path("t.py"))
    assert any("Azure" in f.secret_type for f in findings)


def test_sendgrid_api_key(detector):
    line = 'SENDGRID_KEY="SG.abcdefghijklmnop.qrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZab"'
    findings = detector.detect(line, 1, Path("t.py"))
    assert any("SendGrid" in f.secret_type for f in findings)


def test_twilio_api_key(detector):
    line = 'TWILIO_KEY="SKa8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3"'
    findings = detector.detect(line, 1, Path("t.py"))
    assert any("Twilio" in f.secret_type for f in findings)


def test_mailgun_api_key(detector):
    line = 'MAILGUN_KEY="key-a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3"'
    findings = detector.detect(line, 1, Path("t.py"))
    assert any("Mailgun" in f.secret_type for f in findings)


def test_npm_token(detector):
    line = '//registry.npmjs.org/:_authToken=npm_a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3abcd'
    findings = detector.detect(line, 1, Path(".npmrc"))
    assert any("npm" in f.secret_type.lower() for f in findings)


def test_pypi_token(detector):
    line = 'password = "pypi-AgEIcHlwaS5vcmcCJGY4NjM1YjEyLTBiZDAtNGI1Zi1h"'
    findings = detector.detect(line, 1, Path(".pypirc"))
    assert any("PyPI" in f.secret_type for f in findings)


def test_github_fine_grained_token(detector):
    line = 'token = "github_pat_11AABBBCC_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopABCDEFG"'
    findings = detector.detect(line, 1, Path("t.py"))
    assert any("GitHub" in f.secret_type for f in findings)


def test_discord_bot_token(detector):
    line = 'DISCORD_TOKEN="NzY4OTAxMjM0NTY3ODkwMTIz.G1a2b3.AbCdEfGhIjKlMnOpQrStUvWxYzaBcDeFgH"'
    findings = detector.detect(line, 1, Path("t.py"))
    assert any("Discord" in f.secret_type for f in findings)


def test_gitlab_token(detector):
    line = 'GITLAB_TOKEN="glpat-aB3cD4eF5gH6iJ7kL8mN"'
    findings = detector.detect(line, 1, Path("t.py"))
    assert any("GitLab" in f.secret_type for f in findings)
