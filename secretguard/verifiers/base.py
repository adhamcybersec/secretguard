"""Base verifier interface and result dataclass"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class VerificationResult:
    """Result of a live credential verification attempt."""
    is_valid: bool
    service: str
    detail: str = ""
    error: Optional[str] = None


class BaseVerifier:
    """Base class for credential verifiers."""

    service_name: str = "unknown"

    def can_verify(self, secret_type: str, matched_text: str) -> bool:
        """Return True if this verifier handles the given secret type."""
        raise NotImplementedError

    def verify(self, matched_text: str) -> VerificationResult:
        """Attempt live verification of the credential."""
        raise NotImplementedError
