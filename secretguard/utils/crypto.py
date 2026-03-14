"""Shared cryptographic and string analysis utilities"""

import math
import re
from typing import List


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string.

    Higher entropy = more randomness = more likely to be a secret.
    """
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def extract_candidates(line: str) -> List[str]:
    """Extract potential secret candidate strings from a line of code.

    Looks for quoted strings, assignment values, and base64-like tokens.
    """
    candidates = []

    # Pattern 1: Quoted strings
    for match in re.finditer(r'["\']([A-Za-z0-9+/=_\-]{16,200})["\']', line):
        candidates.append(match.group(1))

    # Pattern 2: Assignment values
    for match in re.finditer(r"=\s*([A-Za-z0-9+/=_\-]{16,200})(?:\s|$|;|,)", line):
        candidates.append(match.group(1))

    # Pattern 3: Base64-like strings
    for match in re.finditer(r"\b([A-Za-z0-9+/]{20,}={0,2})\b", line):
        candidates.append(match.group(1))

    return candidates
