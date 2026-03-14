"""
Data models for SecretGuard
"""

from enum import Enum
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass, field


class Severity(str, Enum):
    """Severity levels for secret findings"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


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
    severity: Severity = Severity.MEDIUM
    commit_hash: str = ""
    commit_author: str = ""
    is_verified: Optional[bool] = None


@dataclass
class ScanResults:
    """Results from a scan operation"""

    findings: List[SecretFinding] = field(default_factory=list)
    files_scanned: int = 0
    total_secrets: int = 0
    scan_duration: float = 0.0
    scan_errors: List[str] = field(default_factory=list)
