"""Tests for shared utility functions"""

from secretguard.utils.crypto import shannon_entropy, extract_candidates


def test_shannon_entropy_empty():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_single_char():
    assert shannon_entropy("aaaa") == 0.0


def test_shannon_entropy_high():
    result = shannon_entropy("aB3$xY9!mN2@pQ7&")
    assert result > 3.0


def test_shannon_entropy_low():
    result = shannon_entropy("aaaaaaaaaa")
    assert result < 1.0


def test_extract_candidates_quoted():
    line = 'token = "ABCDEFGHIJKLMNOPabcdefgh"'
    candidates = extract_candidates(line)
    assert any("ABCDEFGHIJKLMNOP" in c for c in candidates)


def test_extract_candidates_assignment():
    line = "SECRET_KEY=ABCDEFGHIJKLMNOPabcdefgh"
    candidates = extract_candidates(line)
    assert len(candidates) > 0


def test_extract_candidates_empty():
    assert extract_candidates("x = 42") == []


def test_extract_candidates_base64():
    line = "data = ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    candidates = extract_candidates(line)
    assert len(candidates) > 0
