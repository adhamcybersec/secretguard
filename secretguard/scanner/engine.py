"""
Scanner Engine - Core scanning logic
"""

from pathlib import Path
from typing import List, Optional
import re

import pathspec

from secretguard.models import SecretFinding, ScanResults
from secretguard.detectors.regex_detector import RegexDetector
from secretguard.detectors.entropy_detector import EntropyDetector
from secretguard.detectors.ml_detector import MLDetector
from secretguard.config.allowlist import AllowlistManager


class ScanEngine:
    """Main scanning engine that orchestrates detection"""
    
    def __init__(
        self,
        exclude_patterns: Optional[List[str]] = None,
        confidence_threshold: float = 0.75,
        verbose: bool = False,
        custom_patterns: Optional[List] = None,
        use_ml: bool = True,
    ):
        self.exclude_patterns = exclude_patterns or []
        self.confidence_threshold = confidence_threshold
        self.verbose = verbose

        # Initialize detectors
        self.regex_detector = RegexDetector(custom_patterns=custom_patterns)
        self.entropy_detector = EntropyDetector()
        self.ml_detector = MLDetector() if use_ml else None
    
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
    
    def _load_gitignore(self, directory: Path):
        """Load .gitignore patterns using pathspec"""
        gitignore = directory / ".gitignore"
        if gitignore.exists():
            patterns = gitignore.read_text().splitlines()
            return pathspec.PathSpec.from_lines("gitwildmatch", patterns)
        return None

    def _scan_directory(self, directory: Path, results: ScanResults) -> None:
        """Recursively scan a directory, respecting .gitignore"""
        spec = self._load_gitignore(directory)

        for file_path in directory.rglob("*"):
            if not file_path.is_file():
                continue

            # Check pathspec (gitignore)
            try:
                rel = file_path.relative_to(directory)
                if spec and spec.match_file(str(rel)):
                    continue
            except ValueError:
                pass

            # Check manual excludes
            if self._should_exclude(file_path):
                continue

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
                # Check inline ignore
                if AllowlistManager.check_inline_ignore(line):
                    continue

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

                # Run ML detection
                if self.ml_detector:
                    ml_findings = self.ml_detector.detect(line, line_num, file_path)
                    for finding in ml_findings:
                        if finding.confidence >= self.confidence_threshold:
                            # Avoid duplicates with regex/entropy findings
                            if not any(
                                f.line_number == finding.line_number and f.matched_text == finding.matched_text
                                for f in results.findings
                            ):
                                results.findings.append(finding)
        
        except Exception as e:
            if self.verbose:
                print(f"Error scanning {file_path}: {e}")
    
    def scan_files(self, files: List[Path]) -> ScanResults:
        """Scan a specific list of files"""
        import time
        start_time = time.time()
        results = ScanResults()

        for file_path in files:
            if file_path.is_file() and not self._should_exclude(file_path):
                self._scan_file(file_path, results)

        results.scan_duration = time.time() - start_time
        results.total_secrets = len(results.findings)
        return results

    def get_staged_files(self, repo_path: Path) -> List[Path]:
        """Get list of staged files from git"""
        import subprocess
        try:
            result = subprocess.run(
                ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                capture_output=True, text=True, cwd=repo_path
            )
            if result.returncode != 0:
                return []
            return [repo_path / f for f in result.stdout.strip().splitlines() if f]
        except Exception:
            return []

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
