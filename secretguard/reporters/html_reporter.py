"""HTML report generation with beautiful UI"""

from pathlib import Path
from datetime import datetime
from secretguard.models import ScanResults
from secretguard.utils.masking import mask_secret, mask_line_content
from secretguard.utils.io import save_report

TEMPLATES_DIR = Path(__file__).parent / "templates"


class HTMLReporter:
    """Generate beautiful HTML reports from scan results"""

    def generate(self, results: ScanResults, include_remediation: bool = False) -> str:
        """Generate HTML report.

        Args:
            results: Scan results
            include_remediation: Include remediation suggestions (always included in HTML)

        Returns:
            HTML string
        """
        from jinja2 import FileSystemLoader, Environment

        env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))
        template = env.get_template("report.html")

        findings_data = []
        for finding in results.findings:
            findings_data.append({
                'file_path': str(finding.file_path),
                'line_number': finding.line_number,
                'line_content': mask_line_content(finding.line_content, finding.matched_text),
                'secret_type': finding.secret_type,
                'confidence': finding.confidence,
                'severity': finding.severity.value,
                'remediation_suggestion': finding.remediation_suggestion,
            })

        html = template.render(
            timestamp=datetime.now().strftime("%B %d, %Y at %H:%M:%S"),
            files_scanned=results.files_scanned,
            total_secrets=results.total_secrets,
            scan_duration=round(results.scan_duration, 2),
            findings=findings_data,
        )

        return html

    def save(self, report_data: str, output_path: Path) -> None:
        """Save HTML report to file with secure permissions"""
        save_report(report_data, output_path)
