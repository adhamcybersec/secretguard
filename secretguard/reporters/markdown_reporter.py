"""
Markdown report generation
"""

from pathlib import Path
from secretguard.models import ScanResults


class MarkdownReporter:
    """Generate Markdown reports from scan results"""
    
    def generate(self, results: ScanResults, include_remediation: bool = False) -> str:
        """
        Generate Markdown report
        
        Args:
            results: Scan results
            include_remediation: Include remediation suggestions
            
        Returns:
            Markdown string
        """
        lines = [
            "# SecretGuard Scan Report",
            "",
            "## Summary",
            "",
            f"- **Files Scanned**: {results.files_scanned}",
            f"- **Secrets Found**: {results.total_secrets}",
            f"- **Scan Duration**: {results.scan_duration:.2f}s",
            "",
        ]
        
        if results.findings:
            lines.extend([
                "## Findings",
                "",
                "| File | Line | Type | Confidence |",
                "|------|------|------|------------|",
            ])
            
            for finding in results.findings:
                file_short = str(finding.file_path)[-50:]  # Truncate long paths
                lines.append(
                    f"| {file_short} | {finding.line_number} | {finding.secret_type} | {finding.confidence:.0%} |"
                )
            
            if include_remediation:
                lines.extend(["", "## Remediation Recommendations", ""])
                
                for idx, finding in enumerate(results.findings, 1):
                    lines.extend([
                        f"### {idx}. {finding.file_path}:{finding.line_number}",
                        "",
                        f"**Type**: {finding.secret_type}",
                        "",
                        f"**Matched**: `{finding.matched_text[:100]}`",
                        "",
                        f"**Recommendation**: {finding.remediation_suggestion}",
                        "",
                    ])
        else:
            lines.extend([
                "## ✅ No Secrets Detected",
                "",
                "No potential secrets were found in the scanned files.",
            ])
        
        return "\n".join(lines)
    
    def save(self, report_data: str, output_path: Path) -> None:
        """Save Markdown report to file"""
        output_path.write_text(report_data)
