"""Git history scanning for secrets in past commits"""

import subprocess
import re
from pathlib import Path
from typing import List, Optional

from secretguard.models import SecretFinding, ScanResults
from secretguard.detectors.regex_detector import RegexDetector
from secretguard.detectors.entropy_detector import EntropyDetector
from secretguard.config.allowlist import AllowlistManager


class GitHistoryScanner:
    """Scan git history for secrets in past commits"""

    def __init__(
        self,
        confidence_threshold: float = 0.75,
        custom_patterns: Optional[List] = None,
    ):
        self.confidence_threshold = confidence_threshold
        self.regex_detector = RegexDetector(custom_patterns=custom_patterns)
        self.entropy_detector = EntropyDetector()

    def scan_history(
        self,
        repo_path: Path,
        max_commits: int = 100,
        branch: Optional[str] = None,
    ) -> ScanResults:
        """Scan git history for secrets.

        Uses ``git log -p`` to iterate over diffs and scan added lines.
        """
        import time

        start_time = time.time()
        results = ScanResults()

        cmd = [
            "git",
            "log",
            "-p",
            f"--max-count={max_commits}",
            "--diff-filter=A",
            "--no-merges",
            "--format=commit %H%nauthor %an",
        ]
        if branch:
            cmd.append(branch)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=repo_path,
                timeout=120,
            )
            if proc.returncode != 0:
                results.scan_errors.append(f"git log failed: {proc.stderr.strip()}")
                return results
        except Exception as e:
            results.scan_errors.append(f"git log error: {e}")
            return results

        current_commit = ""
        current_author = ""
        current_file = ""
        seen: set[tuple[str, str]] = set()

        for raw_line in proc.stdout.splitlines():
            if raw_line.startswith("commit "):
                current_commit = raw_line[7:].strip()
                continue
            if raw_line.startswith("author "):
                current_author = raw_line[7:].strip()
                continue

            diff_file = re.match(r"^\+\+\+ b/(.+)$", raw_line)
            if diff_file:
                current_file = diff_file.group(1)
                continue

            # Only scan added lines in diffs
            if not raw_line.startswith("+") or raw_line.startswith("+++"):
                continue

            line = raw_line[1:]  # strip leading '+'
            if AllowlistManager.check_inline_ignore(line):
                continue

            file_path = Path(current_file)

            for finding in self.regex_detector.detect(line, 0, file_path):
                if finding.confidence >= self.confidence_threshold:
                    key = (current_commit, finding.matched_text)
                    if key not in seen:
                        seen.add(key)
                        finding.commit_hash = current_commit
                        finding.commit_author = current_author
                        results.findings.append(finding)

            for finding in self.entropy_detector.detect(line, 0, file_path):
                if finding.confidence >= self.confidence_threshold:
                    key = (current_commit, finding.matched_text)
                    if key not in seen:
                        seen.add(key)
                        finding.commit_hash = current_commit
                        finding.commit_author = current_author
                        results.findings.append(finding)

        results.total_secrets = len(results.findings)
        results.scan_duration = time.time() - start_time
        return results
