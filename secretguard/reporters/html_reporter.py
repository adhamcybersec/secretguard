"""
HTML report generation with beautiful UI
"""

from pathlib import Path
from datetime import datetime
from secretguard.models import ScanResults


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecretGuard Security Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header .emoji {
            font-size: 3em;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }
        
        .stat-card {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .stat-card h3 {
            color: #6c757d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }
        
        .stat-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }
        
        .stat-card.danger .value {
            color: #dc3545;
        }
        
        .stat-card.success .value {
            color: #28a745;
        }
        
        .findings {
            padding: 40px;
        }
        
        .findings h2 {
            margin-bottom: 30px;
            color: #333;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }
        
        .finding-card {
            background: #f8f9fa;
            border-left: 4px solid #dc3545;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        
        .finding-card.high {
            border-left-color: #dc3545;
        }
        
        .finding-card.medium {
            border-left-color: #ffc107;
        }
        
        .finding-card.low {
            border-left-color: #28a745;
        }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .finding-title {
            font-weight: bold;
            color: #333;
            font-size: 1.1em;
        }
        
        .confidence-badge {
            background: #667eea;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
        }
        
        .finding-meta {
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
            color: #6c757d;
            font-size: 0.9em;
        }
        
        .code-block {
            background: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
            margin-bottom: 15px;
        }
        
        .remediation {
            background: #e7f3ff;
            border-left: 3px solid #2196F3;
            padding: 15px;
            border-radius: 4px;
            font-size: 0.95em;
        }
        
        .remediation strong {
            color: #2196F3;
        }
        
        .no-findings {
            text-align: center;
            padding: 60px;
            color: #28a745;
        }
        
        .no-findings .icon {
            font-size: 5em;
            margin-bottom: 20px;
        }
        
        .footer {
            background: #2d3748;
            color: #cbd5e0;
            padding: 30px;
            text-align: center;
        }
        
        .footer a {
            color: #667eea;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="emoji">🔐</div>
            <h1>SecretGuard Security Report</h1>
            <p>Generated on {{ timestamp }}</p>
        </div>
        
        <div class="summary">
            <div class="stat-card">
                <h3>Files Scanned</h3>
                <div class="value">{{ files_scanned }}</div>
            </div>
            
            <div class="stat-card {{ 'danger' if total_secrets > 0 else 'success' }}">
                <h3>Secrets Found</h3>
                <div class="value">{{ total_secrets }}</div>
            </div>
            
            <div class="stat-card">
                <h3>Scan Duration</h3>
                <div class="value">{{ scan_duration }}s</div>
            </div>
        </div>
        
        <div class="findings">
            {% if findings %}
            <h2>🚨 Security Findings</h2>
            
            {% for finding in findings %}
            <div class="finding-card {{ 'high' if finding.severity in ['critical', 'high'] else ('medium' if finding.severity == 'medium' else 'low') }}">
                <div class="finding-header">
                    <div class="finding-title">{{ finding.secret_type }}</div>
                    <div class="confidence-badge">{{ finding.severity|upper }} | {{ (finding.confidence * 100)|int }}% Confidence</div>
                </div>
                
                <div class="finding-meta">
                    <span>📁 {{ finding.file_path }}</span>
                    <span>📍 Line {{ finding.line_number }}</span>
                </div>
                
                <div class="code-block">{{ finding.line_content }}</div>
                
                {% if finding.remediation_suggestion %}
                <div class="remediation">
                    <strong>💡 Recommended Action:</strong> {{ finding.remediation_suggestion }}
                </div>
                {% endif %}
            </div>
            {% endfor %}
            
            {% else %}
            <div class="no-findings">
                <div class="icon">✅</div>
                <h2>No Secrets Detected!</h2>
                <p>Your codebase passed the security scan with flying colors.</p>
            </div>
            {% endif %}
        </div>
        
        <div class="footer">
            <p>Generated by <strong>SecretGuard</strong></p>
            <p>An AI-enhanced secret detection tool</p>
            <p><a href="https://github.com/adhamrashed/secretguard" target="_blank">github.com/adhamrashed/secretguard</a></p>
        </div>
    </div>
</body>
</html>
"""


class HTMLReporter:
    """Generate beautiful HTML reports from scan results"""
    
    def generate(self, results: ScanResults, include_remediation: bool = False) -> str:
        """
        Generate HTML report
        
        Args:
            results: Scan results
            include_remediation: Include remediation suggestions (always included in HTML)
            
        Returns:
            HTML string
        """
        from jinja2 import Template
        
        template = Template(HTML_TEMPLATE)
        
        findings_data = []
        for finding in results.findings:
            findings_data.append({
                'file_path': str(finding.file_path),
                'line_number': finding.line_number,
                'line_content': finding.line_content,
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
        """Save HTML report to file"""
        output_path.write_text(report_data)
