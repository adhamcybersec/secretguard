"""SARIF report generation for IDE and CI/CD integration"""

import json
from pathlib import Path
from secretguard.models import ScanResults, Severity
from secretguard.utils.masking import mask_line_content
from secretguard.utils.io import save_report
from secretguard import __version__

SEVERITY_TO_SARIF = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


class SARIFReporter:
    """Generate SARIF 2.1.0 reports"""

    TOOL_NAME = "SecretGuard"

    def generate(self, results: ScanResults, **kwargs) -> str:
        rules = {}
        sarif_results = []

        for finding in results.findings:
            rule_id = (
                finding.secret_type.lower().replace(" ", "-").replace("(", "").replace(")", "")
            )

            if rule_id not in rules:
                precision = (
                    "high"
                    if finding.confidence >= 0.9
                    else ("medium" if finding.confidence >= 0.75 else "low")
                )
                rule = {
                    "id": rule_id,
                    "name": finding.secret_type,
                    "shortDescription": {"text": f"Detected: {finding.secret_type}"},
                    "fullDescription": {
                        "text": f"SecretGuard detected a potential {finding.secret_type} in the codebase. "
                        f"This may expose sensitive credentials if committed."
                    },
                    "helpUri": "https://github.com/adhamcybersec/secretguard",
                    "defaultConfiguration": {
                        "level": SEVERITY_TO_SARIF.get(finding.severity, "warning"),
                    },
                    "properties": {
                        "tags": ["security", "secrets", finding.severity.value],
                        "precision": precision,
                    },
                }
                if finding.remediation_suggestion:
                    rule["help"] = {"text": finding.remediation_suggestion}
                rules[rule_id] = rule

            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "level": SEVERITY_TO_SARIF.get(finding.severity, "warning"),
                    "message": {
                        "text": f"{finding.secret_type} detected (confidence: {finding.confidence:.0%})"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": str(finding.file_path)},
                                "region": {
                                    "startLine": finding.line_number,
                                    "snippet": {
                                        "text": mask_line_content(
                                            finding.line_content, finding.matched_text
                                        )
                                    },
                                },
                            }
                        }
                    ],
                }
            )

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.TOOL_NAME,
                            "version": __version__,
                            "informationUri": "https://github.com/adhamcybersec/secretguard",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }

        return json.dumps(sarif, indent=2)

    def save(self, report_data: str, output_path: Path) -> None:
        save_report(report_data, output_path)
