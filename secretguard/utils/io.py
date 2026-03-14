"""Secure I/O utilities for report file handling"""

import os
from pathlib import Path


def save_report(data: str, path: Path) -> None:
    """Write report data to file with owner-only permissions (0o600)."""
    path.write_text(data)
    os.chmod(path, 0o600)
