"""
Entropy-based secret detection
"""

import re
from pathlib import Path
from typing import List

from secretguard.models import SecretFinding, Severity
from secretguard.utils.crypto import shannon_entropy, extract_candidates


class EntropyDetector:
    """Detects secrets using entropy analysis"""
    
    # Thresholds
    MIN_ENTROPY = 4.0  # Shannon entropy threshold
    MIN_LENGTH = 16     # Minimum string length to analyze
    MAX_LENGTH = 200    # Maximum string length (avoid long base64 data)
    
    def detect(self, line: str, line_num: int, file_path: Path) -> List[SecretFinding]:
        """
        Detect high-entropy strings that could be secrets
        
        Args:
            line: Line content to scan
            line_num: Line number
            file_path: File being scanned
            
        Returns:
            List of SecretFinding objects
        """
        findings = []
        
        # Extract potential secret strings (quoted, assigned, etc.)
        candidates = extract_candidates(line)

        for candidate in candidates:
            entropy = shannon_entropy(candidate)
            
            if entropy >= self.MIN_ENTROPY and self.MIN_LENGTH <= len(candidate) <= self.MAX_LENGTH:
                # Calculate confidence based on entropy and other factors
                confidence = self._calculate_confidence(candidate, entropy)
                
                if confidence > 0.5:  # Only report if confidence is reasonable
                    finding = SecretFinding(
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line.strip(),
                        secret_type="High-Entropy String (Possible Secret)",
                        confidence=confidence,
                        matched_text=candidate,
                        remediation_suggestion="Verify if this is a secret. If so, move to environment variables or secret management",
                        severity=Severity.MEDIUM,
                    )
                    findings.append(finding)
        
        return findings
    
    def _calculate_confidence(self, candidate: str, entropy: float) -> float:
        """
        Calculate confidence that a string is a secret
        
        Factors:
        - Entropy (higher = more likely)
        - Length (moderate length better than very long)
        - Character diversity (mix of upper, lower, digits, special chars)
        - Context keywords nearby
        
        Args:
            candidate: Candidate string
            entropy: Shannon entropy
            
        Returns:
            Confidence score (0.0 to 1.0)
        """
        confidence = 0.0
        
        # Entropy contribution (0-0.5)
        # Map entropy 4.0-6.0 to confidence 0-0.5
        entropy_score = min((entropy - 4.0) / 2.0, 1.0) * 0.5
        confidence += entropy_score
        
        # Length sweet spot (0-0.2)
        # Prefer 20-60 character strings
        if 20 <= len(candidate) <= 60:
            confidence += 0.2
        elif 16 <= len(candidate) < 20 or 60 < len(candidate) <= 100:
            confidence += 0.1
        
        # Character diversity (0-0.3)
        has_upper = any(c.isupper() for c in candidate)
        has_lower = any(c.islower() for c in candidate)
        has_digit = any(c.isdigit() for c in candidate)
        has_special = any(not c.isalnum() for c in candidate)
        
        diversity_score = sum([has_upper, has_lower, has_digit, has_special]) / 4.0
        confidence += diversity_score * 0.3
        
        # Penalize common patterns that aren't secrets
        if self._looks_like_hash(candidate):
            confidence *= 0.7  # Git hashes, etc.
        
        if self._looks_like_uuid(candidate):
            confidence *= 0.6  # UUIDs are usually OK
        
        return min(confidence, 1.0)
    
    def _looks_like_hash(self, string: str) -> bool:
        """Check if string looks like a hash (git commit, etc.)"""
        # Git commits are 40 hex chars
        if len(string) == 40 and all(c in '0123456789abcdef' for c in string.lower()):
            return True
        # SHA-256 hashes are 64 hex chars
        if len(string) == 64 and all(c in '0123456789abcdef' for c in string.lower()):
            return True
        return False
    
    def _looks_like_uuid(self, string: str) -> bool:
        """Check if string looks like a UUID"""
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        return bool(re.match(uuid_pattern, string.lower()))
