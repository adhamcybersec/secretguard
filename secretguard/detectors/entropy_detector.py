"""
Entropy-based secret detection
"""

import math
import re
from pathlib import Path
from typing import List

from secretguard.models import SecretFinding


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
        candidates = self._extract_candidates(line)
        
        for candidate in candidates:
            entropy = self._calculate_entropy(candidate)
            
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
                    )
                    findings.append(finding)
        
        return findings
    
    def _extract_candidates(self, line: str) -> List[str]:
        """Extract potential secret strings from a line"""
        candidates = []
        
        # Pattern 1: Quoted strings
        quoted_pattern = r'["\']([A-Za-z0-9+/=_\-]{16,200})["\']'
        for match in re.finditer(quoted_pattern, line):
            candidates.append(match.group(1))
        
        # Pattern 2: Assignment values
        assignment_pattern = r'=\s*([A-Za-z0-9+/=_\-]{16,200})(?:\s|$|;|,)'
        for match in re.finditer(assignment_pattern, line):
            candidates.append(match.group(1))
        
        # Pattern 3: Base64-like strings
        base64_pattern = r'\b([A-Za-z0-9+/]{20,}={0,2})\b'
        for match in re.finditer(base64_pattern, line):
            candidates.append(match.group(1))
        
        return candidates
    
    def _calculate_entropy(self, string: str) -> float:
        """
        Calculate Shannon entropy of a string
        
        Higher entropy = more randomness = more likely to be a secret
        
        Args:
            string: Input string
            
        Returns:
            Shannon entropy value
        """
        if not string:
            return 0.0
        
        # Count character frequency
        char_counts = {}
        for char in string:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        string_len = len(string)
        
        for count in char_counts.values():
            probability = count / string_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
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
