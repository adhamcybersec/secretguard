"""AWS credential verification via STS"""

import subprocess

from secretguard.verifiers.base import BaseVerifier, VerificationResult


class AWSVerifier(BaseVerifier):
    """Verify AWS access keys using ``aws sts get-caller-identity``."""

    service_name = "AWS"

    def can_verify(self, secret_type: str, matched_text: str) -> bool:
        return "aws" in secret_type.lower() or matched_text.startswith("AKIA")

    def verify(self, matched_text: str) -> VerificationResult:
        try:
            result = subprocess.run(
                ["aws", "sts", "get-caller-identity"],
                capture_output=True,
                text=True,
                timeout=15,
                env={"AWS_ACCESS_KEY_ID": matched_text},
            )
            if result.returncode == 0 and "Account" in result.stdout:
                return VerificationResult(
                    is_valid=True,
                    service=self.service_name,
                    detail="Key is ACTIVE — returned valid caller identity",
                )
            return VerificationResult(
                is_valid=False,
                service=self.service_name,
                detail="Key appears invalid or inactive",
            )
        except FileNotFoundError:
            return VerificationResult(
                is_valid=False,
                service=self.service_name,
                error="AWS CLI not installed",
            )
        except Exception as e:
            return VerificationResult(
                is_valid=False,
                service=self.service_name,
                error=str(e),
            )
