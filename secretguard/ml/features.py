"""Feature extraction for ML-based secret detection"""

from secretguard.utils.crypto import shannon_entropy

SECRET_PREFIXES = [
    "AKIA",
    "ghp_",
    "gho_",
    "github_pat_",
    "glpat-",
    "sk_live_",
    "sk_test_",
    "SG.",
    "xoxb-",
    "xoxp-",
    "npm_",
    "pypi-",
    "SK",
    "key-",
]


def extract_features(candidate: str) -> dict:
    """Extract numerical features from a candidate string for ML classification."""
    length = len(candidate)

    digit_count = sum(c.isdigit() for c in candidate)
    upper_count = sum(c.isupper() for c in candidate)
    lower_count = sum(c.islower() for c in candidate)
    special_count = sum(not c.isalnum() for c in candidate)

    return {
        "entropy": shannon_entropy(candidate),
        "length": length,
        "digit_ratio": digit_count / length if length else 0,
        "upper_ratio": upper_count / length if length else 0,
        "lower_ratio": lower_count / length if length else 0,
        "special_ratio": special_count / length if length else 0,
        "char_diversity": len(set(candidate)) / length if length else 0,
        "has_common_prefix": int(any(candidate.startswith(p) for p in SECRET_PREFIXES)),
        "consecutive_digits_max": _max_consecutive(candidate, str.isdigit),
        "consecutive_upper_max": _max_consecutive(candidate, str.isupper),
    }


def _max_consecutive(s: str, predicate) -> int:
    max_run = current = 0
    for c in s:
        if predicate(c):
            current += 1
            max_run = max(max_run, current)
        else:
            current = 0
    return max_run
