"""
Scanner Engine - Core scanning logic
"""

from pathlib import Path
from typing import List, Optional
import re
from dataclasses import dataclass, field

from secretguard.detectors.regex_detector import RegexDetector
from secretguard.detectors.entropy_detector import EntropyDetector


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


class ScanEngine:
    """Main scanning engine that orchestrates detection"""
    
    def __init__(
        self,
        exclude_patterns: Optional[List[str]] = None,
        confidence_threshold: float = 0.75,
        verbose: bool = False,
    ):
        self.exclude_patterns = exclude_patterns or []
        self.confidence_threshold = confidence_threshold
        self.verbose = verbose
        
        # Initialize detectors
        self.regex_detector = RegexDetector()
        self.entropy_detector = EntropyDetector()
    
    def scan(self, path: Path) -> ScanResults:
        """
        Scan a directory or file for secrets
        
        Args:
            path: Path to scan (file or directory)
            
        Returns:
            ScanResults object with all findings
        """
        import time
        start_time = time.time()
        
        results = ScanResults()
        
        if path.is_file():
            self._scan_file(path, results)
        elif path.is_dir():
            self._scan_directory(path, results)
        else:
            raise ValueError(f"Path {path} is neither a file nor directory")
        
        results.scan_duration = time.time() - start_time
        results.total_secrets = len(results.findings)
        
        return results
    
    def _scan_directory(self, directory: Path, results: ScanResults) -> None:
        """Recursively scan a directory"""
        for file_path in directory.rglob("*"):
            if file_path.is_file() and not self._should_exclude(file_path):
                self._scan_file(file_path, results)
    
    def _scan_file(self, file_path: Path, results: ScanResults) -> None:
        """Scan a single file for secrets"""
        try:
            # Skip binary files
            if self._is_binary(file_path):
                return
            
            results.files_scanned += 1
            
            if self.verbose:
                print(f"Scanning: {file_path}")
            
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
            
            for line_num, line in enumerate(lines, start=1):
                # Run regex detection
                regex_findings = self.regex_detector.detect(line, line_num, file_path)
                for finding in regex_findings:
                    if finding.confidence >= self.confidence_threshold:
                        results.findings.append(finding)
                
                # Run entropy detection on tokens
                entropy_findings = self.entropy_detector.detect(line, line_num, file_path)
                for finding in entropy_findings:
                    if finding.confidence >= self.confidence_threshold:
                        results.findings.append(finding)
        
        except Exception as e:
            if self.verbose:
                print(f"Error scanning {file_path}: {e}")
    
    def _should_exclude(self, file_path: Path) -> bool:
        """Check if a file should be excluded based on patterns"""
        path_str = str(file_path)
        
        # Common exclusions
        common_excludes = [
            ".git/",
            "node_modules/",
            "__pycache__/",
            ".venv/",
            "venv/",
            ".pyc",
            ".so",
            ".dll",
            ".exe",
        ]
        
        for pattern in common_excludes + self.exclude_patterns:
            if pattern in path_str:
                return True
        
        return False
    
    def _is_binary(self, file_path: Path) -> bool:
        """Check if a file is binary"""
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                return b'\x00' in chunk
        except Exception:
            return True
