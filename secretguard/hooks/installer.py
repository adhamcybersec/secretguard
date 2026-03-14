"""
Pre-commit hook installer
"""

import subprocess
from pathlib import Path

PRE_COMMIT_HOOK = """#!/bin/bash
# SecretGuard pre-commit hook
# Prevents committing secrets to git

echo "🔍 SecretGuard: Scanning staged files for secrets..."

# Get list of staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
    echo "✅ No files to scan"
    exit 0
fi

# Create temp directory for staged files
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Copy staged files to temp directory (preserving structure)
for file in $STAGED_FILES; do
    if [ -f "$file" ]; then
        mkdir -p "$TEMP_DIR/$(dirname "$file")"
        cp "$file" "$TEMP_DIR/$file"
    fi
done

# Run SecretGuard on temp directory
if command -v secretguard &> /dev/null; then
    secretguard scan "$TEMP_DIR" --format console 2>&1 | grep -v "Scanning:"
    SCAN_RESULT=$?
else
    echo "⚠️  SecretGuard not found. Install with: pip install secretguard"
    exit 0
fi

# Check result
if [ $SCAN_RESULT -eq 1 ]; then
    echo ""
    echo "❌ COMMIT BLOCKED: Secrets detected in staged files!"
    echo ""
    echo "Options:"
    echo "  1. Remove the secrets and commit again"
    echo "  2. Add to .secretguard.yml allowlist if false positive"
    echo "  3. Bypass this check: git commit --no-verify (NOT RECOMMENDED)"
    echo ""
    exit 1
else
    echo "✅ No secrets detected. Proceeding with commit."
    exit 0
fi
"""


class PreCommitInstaller:
    """Install and manage pre-commit hooks.

    .. deprecated::
        Consider using the `pre-commit` framework instead.
        See .pre-commit-hooks.yaml for integration details.
    """

    @staticmethod
    def install(repo_path: Path = Path.cwd()) -> bool:
        """
        Install SecretGuard pre-commit hook

        Args:
            repo_path: Path to git repository (default: current directory)

        Returns:
            True if successful, False otherwise
        """
        # Check if it's a git repository
        git_dir = repo_path / ".git"
        if not git_dir.exists():
            raise ValueError(f"{repo_path} is not a git repository")

        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(exist_ok=True)

        hook_path = hooks_dir / "pre-commit"

        # Check if hook already exists
        if hook_path.exists():
            existing_content = hook_path.read_text()
            if "SecretGuard" in existing_content:
                return False  # Already installed
            else:
                # Backup existing hook
                backup_path = hook_path.with_suffix(".backup")
                hook_path.rename(backup_path)
                print(f"⚠️  Existing pre-commit hook backed up to {backup_path}")

        # Write new hook
        hook_path.write_text(PRE_COMMIT_HOOK)
        hook_path.chmod(0o755)  # Make executable

        return True

    @staticmethod
    def uninstall(repo_path: Path = Path.cwd()) -> bool:
        """
        Uninstall SecretGuard pre-commit hook

        Args:
            repo_path: Path to git repository

        Returns:
            True if hook was removed, False if not found
        """
        hook_path = repo_path / ".git" / "hooks" / "pre-commit"

        if not hook_path.exists():
            return False

        # Check if it's our hook
        content = hook_path.read_text()
        if "SecretGuard" not in content:
            return False

        # Remove hook
        hook_path.unlink()

        # Restore backup if exists
        backup_path = hook_path.with_suffix(".backup")
        if backup_path.exists():
            backup_path.rename(hook_path)
            print(f"✅ Restored original pre-commit hook from backup")

        return True

    @staticmethod
    def is_installed(repo_path: Path = Path.cwd()) -> bool:
        """Check if SecretGuard pre-commit hook is installed"""
        hook_path = repo_path / ".git" / "hooks" / "pre-commit"

        if not hook_path.exists():
            return False

        content = hook_path.read_text()
        return "SecretGuard" in content
