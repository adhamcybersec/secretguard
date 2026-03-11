"""
Configuration file loader for .secretguard.yml
"""

import yaml
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field


@dataclass
class CustomPattern:
    """User-defined secret pattern"""
    name: str
    pattern: str
    confidence: float = 0.90
    severity: str = "high"
    remediation: str = "Move to environment variables or secret management"


@dataclass
class AllowlistEntry:
    """Entry in the allowlist for ignoring findings"""
    file: Optional[str] = None
    line: Optional[int] = None
    pattern: Optional[str] = None
    reason: str = ""


@dataclass
class SecretGuardConfig:
    """SecretGuard configuration"""
    exclude: List[str] = field(default_factory=list)
    confidence_threshold: float = 0.75
    custom_patterns: List[CustomPattern] = field(default_factory=list)
    allowlist: List[AllowlistEntry] = field(default_factory=list)
    ignore_patterns: List[str] = field(default_factory=list)


class ConfigLoader:
    """Load and parse .secretguard.yml configuration"""
    
    DEFAULT_CONFIG_NAME = ".secretguard.yml"
    
    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> SecretGuardConfig:
        """
        Load configuration from file
        
        Args:
            config_path: Path to config file. If None, searches for .secretguard.yml in current dir
            
        Returns:
            SecretGuardConfig object
        """
        if config_path is None:
            config_path = Path.cwd() / cls.DEFAULT_CONFIG_NAME
        
        if not config_path.exists():
            # Return default config
            return SecretGuardConfig()
        
        try:
            with open(config_path, 'r') as f:
                data = yaml.safe_load(f) or {}
            
            return cls._parse_config(data)
        
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in config file: {e}")
        except Exception as e:
            raise ValueError(f"Error loading config: {e}")
    
    @classmethod
    def _parse_config(cls, data: Dict[str, Any]) -> SecretGuardConfig:
        """Parse config data into SecretGuardConfig object"""
        config = SecretGuardConfig()
        
        # Exclude patterns
        if 'exclude' in data:
            config.exclude = data['exclude']
        
        # Confidence threshold
        if 'confidence_threshold' in data:
            threshold = data['confidence_threshold']
            if not 0.0 <= threshold <= 1.0:
                raise ValueError("confidence_threshold must be between 0.0 and 1.0")
            config.confidence_threshold = threshold
        
        # Custom patterns
        if 'custom_patterns' in data:
            for pattern_data in data['custom_patterns']:
                pattern = CustomPattern(
                    name=pattern_data['name'],
                    pattern=pattern_data['pattern'],
                    confidence=pattern_data.get('confidence', 0.90),
                    severity=pattern_data.get('severity', 'high'),
                    remediation=pattern_data.get('remediation', 'Move to environment variables or secret management'),
                )
                config.custom_patterns.append(pattern)
        
        # Allowlist
        if 'allowlist' in data:
            for entry_data in data['allowlist']:
                entry = AllowlistEntry(
                    file=entry_data.get('file'),
                    line=entry_data.get('line'),
                    pattern=entry_data.get('pattern'),
                    reason=entry_data.get('reason', ''),
                )
                config.allowlist.append(entry)
        
        # Ignore patterns
        if 'ignore_patterns' in data:
            config.ignore_patterns = data['ignore_patterns']
        
        return config
    
    @classmethod
    def create_default_config(cls, path: Path) -> None:
        """Create a default .secretguard.yml file"""
        default_config = """# SecretGuard Configuration

# Paths to exclude from scanning
exclude:
  - "node_modules/**"
  - "vendor/**"
  - ".git/**"
  - "*.test.js"
  - "*.test.py"
  - "*.spec.ts"

# Minimum confidence threshold (0.0-1.0)
confidence_threshold: 0.75

# Custom patterns (regex)
custom_patterns:
  # Example:
  # - name: "Custom API Key"
  #   pattern: "CUSTOM_[A-Z0-9]{32}"
  #   confidence: 0.95
  #   severity: high
  #   remediation: "Move to environment variables"

# Allowlist (ignore specific findings)
allowlist:
  # Example:
  # - file: "tests/fixtures/secrets.py"
  #   line: 10
  #   reason: "Test fixture, not a real secret"

# False positive patterns to ignore
ignore_patterns:
  - "example_api_key_here"
  - "REPLACE_WITH_YOUR_KEY"
  - "your_api_key_here"
  - "INSERT_API_KEY_HERE"
"""
        path.write_text(default_config)
