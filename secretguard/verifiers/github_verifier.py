"""GitHub token verification"""

import urllib.request
import urllib.error

from secretguard.verifiers.base import BaseVerifier, VerificationResult


class GitHubVerifier(BaseVerifier):
    """Verify GitHub personal access tokens via the GitHub API."""

    service_name = "GitHub"

    def can_verify(self, secret_type: str, matched_text: str) -> bool:
        return (
            "github" in secret_type.lower()
            or matched_text.startswith(("ghp_", "gho_", "github_pat_"))
        )

    def verify(self, matched_text: str) -> VerificationResult:
        token = matched_text.strip()
        req = urllib.request.Request(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "SecretGuard-Verifier",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    return VerificationResult(
                        is_valid=True,
                        service=self.service_name,
                        detail="Token is ACTIVE and has valid API access",
                    )
        except urllib.error.HTTPError as e:
            if e.code == 401:
                return VerificationResult(
                    is_valid=False,
                    service=self.service_name,
                    detail="Token is invalid or revoked",
                )
            return VerificationResult(
                is_valid=False,
                service=self.service_name,
                error=f"HTTP {e.code}",
            )
        except Exception as e:
            return VerificationResult(
                is_valid=False,
                service=self.service_name,
                error=str(e),
            )

        return VerificationResult(
            is_valid=False,
            service=self.service_name,
            detail="Unexpected response",
        )
