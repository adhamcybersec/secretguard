"""Structured regex pattern definitions for secret detection, grouped by provider."""

from secretguard.models import Severity

# Each pattern: (name, regex, confidence, severity, remediation)
# Grouped by provider/category for maintainability.

AWS_PATTERNS = [
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
]

GITHUB_PATTERNS = [
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
    (
        "GitHub Fine-Grained Token",
        r"github_pat_[a-zA-Z0-9_]{22,}",
        0.95,
        Severity.HIGH,
        "Revoke in GitHub Settings > Developer Settings > Tokens",
    ),
]

GOOGLE_PATTERNS = [
    (
        "Google API Key",
        r"AIza[0-9A-Za-z\-_]{35}",
        0.90,
        Severity.MEDIUM,
        "Use Google Cloud Secret Manager",
    ),
]

STRIPE_PATTERNS = [
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
]

GENERIC_PATTERNS = [
    (
        "Generic API Key",
        r"api[_-]?key\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]",
        0.75,
        Severity.MEDIUM,
        "Use environment variables or a secret management service",
    ),
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
]

PRIVATE_KEY_PATTERNS = [
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
]

DATABASE_PATTERNS = [
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
]

TOKEN_PATTERNS = [
    (
        "JWT Token",
        r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
        0.85,
        Severity.MEDIUM,
        "Tokens should never be committed. Use secure storage",
    ),
]

SLACK_PATTERNS = [
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
]

CLOUD_PATTERNS = [
    (
        "Azure Storage Key",
        r"DefaultEndpointProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{20,}==",
        0.95,
        Severity.CRITICAL,
        "Rotate key in Azure Portal and use Azure Key Vault",
    ),
]

EMAIL_SERVICE_PATTERNS = [
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
]

PACKAGE_REGISTRY_PATTERNS = [
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
]

GIT_PLATFORM_PATTERNS = [
    (
        "GitLab Personal Access Token",
        r"glpat-[a-zA-Z0-9_\-]{20,}",
        0.95,
        Severity.HIGH,
        "Revoke in GitLab User Settings > Access Tokens",
    ),
]

CHAT_PATTERNS = [
    (
        "Discord Bot Token",
        r"[MN][a-zA-Z0-9]{23,}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,}",
        0.85,
        Severity.HIGH,
        "Regenerate token in Discord Developer Portal",
    ),
]

# Combined list of all patterns
ALL_PATTERNS = (
    AWS_PATTERNS
    + GITHUB_PATTERNS
    + GOOGLE_PATTERNS
    + STRIPE_PATTERNS
    + GENERIC_PATTERNS
    + PRIVATE_KEY_PATTERNS
    + DATABASE_PATTERNS
    + TOKEN_PATTERNS
    + SLACK_PATTERNS
    + CLOUD_PATTERNS
    + EMAIL_SERVICE_PATTERNS
    + PACKAGE_REGISTRY_PATTERNS
    + GIT_PLATFORM_PATTERNS
    + CHAT_PATTERNS
)
