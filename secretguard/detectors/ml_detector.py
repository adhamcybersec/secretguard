"""ML-based secret detection"""

import re
from pathlib import Path
from typing import List

from secretguard.models import SecretFinding, Severity
from secretguard.ml.classifier import SecretClassifier


class MLDetector:
    """Detects secrets using the trained ML classifier"""

    def __init__(self, threshold: float = 0.75):
        self.threshold = threshold
        self._classifier = SecretClassifier()
        self._classifier.train()

    def detect(self, line: str, line_num: int, file_path: Path) -> List[SecretFinding]:
        candidates = self._extract_candidates(line)
        findings = []

        if not candidates:
            return findings

        scores = self._classifier.predict_batch(candidates)

        for candidate, score in zip(candidates, scores):
            if score >= self.threshold:
                findings.append(SecretFinding(
                    file_path=file_path,
                    line_number=line_num,
                    line_content=line.strip(),
                    secret_type="ML-Detected Secret",
                    confidence=round(score, 2),
                    matched_text=candidate,
                    severity=Severity.MEDIUM if score < 0.9 else Severity.HIGH,
                    remediation_suggestion="ML model flagged this as a potential secret. Verify and move to secret management if confirmed.",
                ))

        return findings

    def _extract_candidates(self, line: str) -> List[str]:
        """Extract candidate strings from a line."""
        candidates = []
        for match in re.finditer(r'["\']([A-Za-z0-9+/=_\-]{16,200})["\']', line):
            candidates.append(match.group(1))
        for match in re.finditer(r'=\s*([A-Za-z0-9+/=_\-]{16,200})(?:\s|$|;|,)', line):
            candidates.append(match.group(1))
        return list(set(candidates))
