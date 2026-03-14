"""
Allowlist manager for ignoring known false positives
"""

import re
from pathlib import Path
from typing import List

from secretguard.models import SecretFinding
from secretguard.config.loader import AllowlistEntry


class AllowlistManager:
    """Manage allowlist for ignoring findings"""

    def __init__(self, allowlist: List[AllowlistEntry], ignore_patterns: List[str]):
        self.allowlist = allowlist
        self.ignore_patterns = ignore_patterns

    def should_ignore(self, finding: SecretFinding) -> bool:
        """
        Check if a finding should be ignored based on allowlist

        Args:
            finding: SecretFinding to check

        Returns:
            True if should be ignored, False otherwise
        """
        # Check allowlist entries
        for entry in self.allowlist:
            if self._matches_entry(finding, entry):
                return True

        # Check ignore patterns
        for pattern in self.ignore_patterns:
            if pattern.lower() in finding.matched_text.lower():
                return True

        return False

    def _matches_entry(self, finding: SecretFinding, entry: AllowlistEntry) -> bool:
        """Check if a finding matches an allowlist entry"""
        # File + line match
        if entry.file and entry.line:
            if str(finding.file_path).endswith(entry.file) and finding.line_number == entry.line:
                return True

        # File-only match
        if entry.file and not entry.line:
            if str(finding.file_path).endswith(entry.file):
                return True

        # Pattern match
        if entry.pattern:
            if re.search(entry.pattern, finding.matched_text, re.IGNORECASE):
                return True

        return False

    @staticmethod
    def check_inline_ignore(line_content: str) -> bool:
        """
        Check if line has inline ignore comment.

        The marker must appear after a comment delimiter (#, //, /* , --)
        so that ``password = "secretguard:ignore"`` does NOT suppress scanning.
        """
        pattern = r"(?:#|//|/\*|--)\s*(?:secretguard[:\-]ignore|sg:ignore)"
        return bool(re.search(pattern, line_content, re.IGNORECASE))
