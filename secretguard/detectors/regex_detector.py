"""
Regex-based secret detection
"""

import re
from pathlib import Path
from typing import List

from secretguard.models import SecretFinding, Severity


class RegexDetector:
    """Detects secrets using regex patterns"""
    
    def __init__(self, custom_patterns=None):
        """
        Initialize detector
        
        Args:
            custom_patterns: List of CustomPattern objects from config
        """
        self.custom_patterns = custom_patterns or []
    
    # Pattern definitions: (name, pattern, confidence, severity, remediation)
    PATTERNS = [
        # AWS
        (
            "AWS Access Key ID",
            r"AKIA[0-9A-Z]{16}",
            0.95,
            Severity.HIGH,
            "Move to AWS Secrets Manager or environment variables",
        ),
        (
            "AWS Secret Access Key",
            r"aws_secret_access_key\s*=\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
            0.90,
            Severity.HIGH,
            "Use AWS Secrets Manager or AWS Systems Manager Parameter Store",
        ),

        # GitHub
        (
            "GitHub Personal Access Token",
            r"ghp_[a-zA-Z0-9]{36}",
            0.95,
            Severity.HIGH,
            "Revoke and regenerate token, use GitHub Secrets for CI/CD",
        ),
        (
            "GitHub OAuth Token",
            r"gho_[a-zA-Z0-9]{36}",
            0.95,
            Severity.HIGH,
            "Revoke token immediately and use environment variables",
        ),

        # Google Cloud
        (
            "Google API Key",
            r"AIza[0-9A-Za-z\-_]{35}",
            0.90,
            Severity.MEDIUM,
            "Use Google Cloud Secret Manager",
        ),

        # Stripe
        (
            "Stripe API Key",
            r"sk_live_[0-9a-zA-Z]{24,}",
            0.95,
            Severity.HIGH,
            "Revoke key and use environment variables or secret management",
        ),
        (
            "Stripe Test API Key",
            r"sk_test_[0-9a-zA-Z]{24,}",
            0.85,
            Severity.LOW,
            "Move to environment variables (test keys still shouldn't be committed)",
        ),

        # Generic API Keys
        (
            "Generic API Key",
            r"api[_-]?key\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]",
            0.75,
            Severity.MEDIUM,
            "Use environment variables or a secret management service",
        ),

        # Private Keys
        (
            "RSA Private Key",
            r"-----BEGIN RSA PRIVATE KEY-----",
            0.99,
            Severity.CRITICAL,
            "CRITICAL: Remove immediately. Use key management service or encrypted storage",
        ),
        (
            "SSH Private Key",
            r"-----BEGIN OPENSSH PRIVATE KEY-----",
            0.99,
            Severity.CRITICAL,
            "CRITICAL: Remove immediately. Never commit SSH keys",
        ),
        (
            "PGP Private Key",
            r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
            0.99,
            Severity.CRITICAL,
            "CRITICAL: Remove immediately and regenerate key pair",
        ),

        # Database Connection Strings
        (
            "PostgreSQL Connection String",
            r"postgres://[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@",
            0.90,
            Severity.HIGH,
            "Use environment variables for database credentials",
        ),
        (
            "MySQL Connection String",
            r"mysql://[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@",
            0.90,
            Severity.HIGH,
            "Use environment variables for database credentials",
        ),

        # OAuth & JWT
        (
            "JWT Token",
            r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
            0.85,
            Severity.MEDIUM,
            "Tokens should never be committed. Use secure storage",
        ),

        # Generic Password Patterns
        (
            "Password in Code",
            r"password\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
            0.70,
            Severity.LOW,
            "Remove hardcoded password. Use environment variables or secret management",
        ),
        (
            "Authorization Header",
            r"Authorization:\s*Bearer\s+[a-zA-Z0-9_\-\.]+",
            0.80,
            Severity.MEDIUM,
            "Remove hardcoded authorization token",
        ),

        # Slack
        (
            "Slack Webhook URL",
            r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
            0.95,
            Severity.HIGH,
            "Revoke webhook and regenerate in Slack app settings",
        ),
        (
            "Slack Bot Token",
            r"xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}",
            0.95,
            Severity.HIGH,
            "Revoke token in Slack API dashboard",
        ),

        # Azure
        (
            "Azure Storage Key",
            r"DefaultEndpointProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{20,}==",
            0.95,
            Severity.CRITICAL,
            "Rotate key in Azure Portal and use Azure Key Vault",
        ),

        # Email services
        (
            "SendGrid API Key",
            r"SG\.[a-zA-Z0-9_-]{16,}\.[a-zA-Z0-9_-]{16,}",
            0.95,
            Severity.HIGH,
            "Revoke and regenerate in SendGrid dashboard",
        ),
        (
            "Twilio API Key",
            r"SK[0-9a-fA-F]{32}",
            0.90,
            Severity.HIGH,
            "Rotate key in Twilio Console",
        ),
        (
            "Mailgun API Key",
            r"key-[a-zA-Z0-9]{32}",
            0.85,
            Severity.HIGH,
            "Rotate key in Mailgun dashboard",
        ),

        # Package registries
        (
            "npm Token",
            r"npm_[a-zA-Z0-9]{36}",
            0.95,
            Severity.HIGH,
            "Revoke token with npm token revoke",
        ),
        (
            "PyPI Token",
            r"pypi-[a-zA-Z0-9]{40,}",
            0.95,
            Severity.HIGH,
            "Revoke token in PyPI account settings",
        ),

        # Git platforms
        (
            "GitHub Fine-Grained Token",
            r"github_pat_[a-zA-Z0-9_]{22,}",
            0.95,
            Severity.HIGH,
            "Revoke in GitHub Settings > Developer Settings > Tokens",
        ),
        (
            "GitLab Personal Access Token",
            r"glpat-[a-zA-Z0-9_\-]{20,}",
            0.95,
            Severity.HIGH,
            "Revoke in GitLab User Settings > Access Tokens",
        ),

        # Chat platforms
        (
            "Discord Bot Token",
            r"[MN][a-zA-Z0-9]{23,}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,}",
            0.85,
            Severity.HIGH,
            "Regenerate token in Discord Developer Portal",
        ),
    ]
    
    def detect(self, line: str, line_num: int, file_path: Path) -> List[SecretFinding]:
        """
        Detect secrets in a line using regex patterns
        
        Args:
            line: Line content to scan
            line_num: Line number
            file_path: File being scanned
            
        Returns:
            List of SecretFinding objects
        """
        findings = []
        
        # Check built-in patterns
        for pattern_name, pattern, confidence, severity, remediation in self.PATTERNS:
            matches = re.finditer(pattern, line, re.IGNORECASE)
            
            for match in matches:
                # Skip common false positives
                if self._is_false_positive(match.group(0)):
                    continue
                
                finding = SecretFinding(
                    file_path=file_path,
                    line_number=line_num,
                    line_content=line.strip(),
                    secret_type=pattern_name,
                    confidence=confidence,
                    matched_text=match.group(0),
                    remediation_suggestion=remediation,
                    severity=severity,
                )
                findings.append(finding)
        
        # Check custom patterns
        for custom_pattern in self.custom_patterns:
            try:
                matches = re.finditer(custom_pattern.pattern, line, re.IGNORECASE)
                
                for match in matches:
                    if self._is_false_positive(match.group(0)):
                        continue
                    
                    finding = SecretFinding(
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line.strip(),
                        secret_type=f"{custom_pattern.name} (custom)",
                        confidence=custom_pattern.confidence,
                        matched_text=match.group(0),
                        remediation_suggestion=custom_pattern.remediation,
                    )
                    findings.append(finding)
            except re.error:
                # Invalid regex in custom pattern, skip it
                pass
        
        return findings
    
    def _is_false_positive(self, matched_text: str) -> bool:
        """Check if a match is likely a false positive"""
        false_positive_indicators = [
            "example",
            "sample",
            "test",
            "demo",
            "placeholder",
            "your_",
            "YOUR_",
            "replace",
            "REPLACE",
            "xxxxx",
            "12345",
        ]
        
        matched_lower = matched_text.lower()
        return any(indicator in matched_lower for indicator in false_positive_indicators)
