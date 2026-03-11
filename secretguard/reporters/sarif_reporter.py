"""SARIF report generation for IDE and CI/CD integration"""

import json
from pathlib import Path
from secretguard.models import ScanResults, Severity


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
            rule_id = finding.secret_type.lower().replace(" ", "-").replace("(", "").replace(")", "")

            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": finding.secret_type,
                    "shortDescription": {"text": f"Detected: {finding.secret_type}"},
                    "helpUri": "https://github.com/adhamcybersec/secretguard",
                    "defaultConfiguration": {
                        "level": SEVERITY_TO_SARIF.get(finding.severity, "warning"),
                    },
                }
                if finding.remediation_suggestion:
                    rules[rule_id]["help"] = {"text": finding.remediation_suggestion}

            sarif_results.append({
                "ruleId": rule_id,
                "level": SEVERITY_TO_SARIF.get(finding.severity, "warning"),
                "message": {"text": f"{finding.secret_type} detected (confidence: {finding.confidence:.0%})"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(finding.file_path)},
                        "region": {
                            "startLine": finding.line_number,
                            "snippet": {"text": finding.line_content},
                        },
                    }
                }],
            })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": self.TOOL_NAME,
                        "informationUri": "https://github.com/adhamcybersec/secretguard",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }],
        }

        return json.dumps(sarif, indent=2)

    def save(self, report_data: str, output_path: Path) -> None:
        output_path.write_text(report_data)
