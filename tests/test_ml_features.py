"""Tests for ML feature extraction"""

from secretguard.ml.features import extract_features


def test_extract_features_returns_dict():
    features = extract_features("AKIAIOSFODNN7REALKEY")
    assert isinstance(features, dict)
    assert "entropy" in features
    assert "length" in features
    assert "digit_ratio" in features
    assert "upper_ratio" in features
    assert "lower_ratio" in features
    assert "special_ratio" in features
    assert "has_common_prefix" in features


def test_high_entropy_secret():
    features = extract_features("dG9rZW4xMjM0NTY3ODkwYWJjZGVmZ2hpamts")
    assert features["entropy"] > 3.5


def test_low_entropy_string():
    features = extract_features("aaaaaaaaaaaaaaaa")
    assert features["entropy"] < 1.0


def test_common_prefix_detected():
    features = extract_features("AKIAIOSFODNN7REALKEY")
    assert features["has_common_prefix"] == 1

    features = extract_features("randomstring12345678")
    assert features["has_common_prefix"] == 0
