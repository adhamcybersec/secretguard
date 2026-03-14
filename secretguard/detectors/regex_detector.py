"""Regex-based secret detection"""

import re
from pathlib import Path
from typing import List

from secretguard.models import SecretFinding, Severity
from secretguard.detectors.patterns import ALL_PATTERNS


class RegexDetector:
    """Detects secrets using regex patterns"""

    def __init__(self, custom_patterns=None):
        self.custom_patterns = custom_patterns or []

    PATTERNS = ALL_PATTERNS

    def detect(self, line: str, line_num: int, file_path: Path) -> List[SecretFinding]:
        """Detect secrets in a line using regex patterns"""
        findings = []

        for pattern_name, pattern, confidence, severity, remediation in self.PATTERNS:
            matches = re.finditer(pattern, line, re.IGNORECASE)

            for match in matches:
                if self._is_false_positive(match.group(0)):
                    continue

                finding = SecretFinding(
                    file_path=file_path,
                    line_number=line_num,
                    line_content=line.strip(),
                    secret_type=pattern_name,
                    confidence=confidence,
                    matched_text=match.group(0),
                    remediation_suggestion=remediation,
                    severity=severity,
                )
                findings.append(finding)

        for custom_pattern in self.custom_patterns:
            try:
                matches = re.finditer(custom_pattern.pattern, line, re.IGNORECASE)

                for match in matches:
                    if self._is_false_positive(match.group(0)):
                        continue

                    finding = SecretFinding(
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line.strip(),
                        secret_type=f"{custom_pattern.name} (custom)",
                        confidence=custom_pattern.confidence,
                        matched_text=match.group(0),
                        remediation_suggestion=custom_pattern.remediation,
                    )
                    findings.append(finding)
            except re.error:
                pass

        return findings

    def _is_false_positive(self, matched_text: str) -> bool:
        """Check if a match is likely a false positive"""
        false_positive_indicators = [
            "example",
            "sample",
            "test",
            "demo",
            "placeholder",
            "your_",
            "YOUR_",
            "replace",
            "REPLACE",
            "xxxxx",
            "12345",
        ]

        matched_lower = matched_text.lower()
        return any(indicator in matched_lower for indicator in false_positive_indicators)
