"""Secret masking utilities to prevent leaking secrets in reports"""


def mask_secret(text: str, visible: int = 4) -> str:
    """Mask a secret string, keeping first and last `visible` characters.

    Short strings (<=8 chars) are fully masked.
    """
    if len(text) <= visible * 2:
        return "*" * len(text)
    return text[:visible] + "*" * (len(text) - visible * 2) + text[-visible:]


def mask_line_content(line: str, matched_text: str) -> str:
    """Replace matched secret text within a line with its masked version."""
    if not matched_text or matched_text not in line:
        return line
    return line.replace(matched_text, mask_secret(matched_text))
