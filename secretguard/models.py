"""
Data models for SecretGuard
"""

from pathlib import Path
from typing import List
from dataclasses import dataclass, field


@dataclass
class SecretFinding:
    """Represents a detected secret"""
    file_path: Path
    line_number: int
    line_content: str
    secret_type: str
    confidence: float
    matched_text: str
    remediation_suggestion: str = ""


@dataclass
class ScanResults:
    """Results from a scan operation"""
    findings: List[SecretFinding] = field(default_factory=list)
    files_scanned: int = 0
    total_secrets: int = 0
    scan_duration: float = 0.0
