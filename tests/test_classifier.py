"""Tests for ML classifier"""

from secretguard.ml.classifier import SecretClassifier


def test_classifier_train_and_predict():
    clf = SecretClassifier()
    clf.train()
    assert clf.is_trained

    # Known secret pattern
    score = clf.predict("AKIAIOSFODNN7REALKEY")
    assert score > 0.5

    # Known non-secret
    score = clf.predict("hello world")
    assert score < 0.5


def test_classifier_untrained_returns_none():
    clf = SecretClassifier()
    assert clf.predict("test") is None


def test_classifier_batch_predict():
    clf = SecretClassifier()
    clf.train()
    results = clf.predict_batch(
        ["AKIAIOSFODNN7REALKEY", "hello", "ghp_abcdefghijklmnopqrstuvwxyz123456"]
    )
    assert len(results) == 3
    assert results[0] > results[1]  # Secret should score higher than "hello"
