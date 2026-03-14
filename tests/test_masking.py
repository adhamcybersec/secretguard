"""Tests for secret masking utilities"""

from secretguard.utils.masking import mask_secret, mask_line_content


def test_mask_secret_long_string():
    secret = "AKIAIOSFODNN7REALKEY"
    masked = mask_secret(secret)
    assert masked.startswith("AKIA")
    assert masked.endswith("LKEY")
    assert "***" in masked
    assert len(masked) == len(secret)


def test_mask_secret_short_string():
    secret = "abcd1234"
    masked = mask_secret(secret)
    assert masked == "********"


def test_mask_secret_very_short():
    assert mask_secret("abc") == "***"


def test_mask_secret_custom_visible():
    secret = "AKIAIOSFODNN7REALKEY"
    masked = mask_secret(secret, visible=2)
    assert masked.startswith("AK")
    assert masked.endswith("EY")


def test_mask_line_content():
    line = 'api_key = "AKIAIOSFODNN7REALKEY"'
    masked = mask_line_content(line, "AKIAIOSFODNN7REALKEY")
    assert "AKIAIOSFODNN7REALKEY" not in masked
    assert "AKIA" in masked
    assert "LKEY" in masked


def test_mask_line_content_no_match():
    line = "normal code line"
    assert mask_line_content(line, "notfound") == line


def test_masked_output_never_contains_raw_secret():
    """Verify masked output contains ***, never raw secret text >8 chars"""
    secret = "sk_live_abcdefghijklmnopqrstuvwx"
    masked = mask_secret(secret)
    assert "***" in masked
    # The raw middle portion should not appear
    assert secret[4:-4] not in masked
