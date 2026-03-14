"""
JSON report generation
"""

import json
from pathlib import Path
from typing import Any, Dict

from secretguard.models import ScanResults
from secretguard.utils.masking import mask_secret, mask_line_content
from secretguard.utils.io import save_report


class JSONReporter:
    """Generate JSON reports from scan results"""

    def generate(self, results: ScanResults, include_remediation: bool = False) -> str:
        """
        Generate JSON report

        Args:
            results: Scan results
            include_remediation: Include remediation suggestions

        Returns:
            JSON string
        """
        report = {
            "summary": {
                "files_scanned": results.files_scanned,
                "total_secrets": results.total_secrets,
                "scan_duration_seconds": round(results.scan_duration, 2),
            },
            "findings": [],
        }

        for finding in results.findings:
            finding_dict = {
                "file": str(finding.file_path),
                "line": finding.line_number,
                "type": finding.secret_type,
                "severity": finding.severity.value,
                "confidence": round(finding.confidence, 2),
                "matched_text": mask_secret(finding.matched_text),
                "line_content": mask_line_content(finding.line_content, finding.matched_text),
            }

            if include_remediation:
                finding_dict["remediation"] = finding.remediation_suggestion

            if finding.commit_hash:
                finding_dict["commit_hash"] = finding.commit_hash
                finding_dict["commit_author"] = finding.commit_author

            report["findings"].append(finding_dict)

        return json.dumps(report, indent=2)

    def save(self, report_data: str, output_path: Path) -> None:
        """Save JSON report to file with secure permissions"""
        save_report(report_data, output_path)
