"""
Tests for ConfigLoader
"""

from pathlib import Path
import pytest
import tempfile

from secretguard.config.loader import ConfigLoader, SecretGuardConfig


def test_default_config():
    """Test loading default config when file doesn't exist"""
    config = ConfigLoader.load(Path("/nonexistent/.secretguard.yml"))
    
    assert isinstance(config, SecretGuardConfig)
    assert config.confidence_threshold == 0.75
    assert config.exclude == []
    assert config.custom_patterns == []


def test_load_valid_config():
    """Test loading a valid config file"""
    config_content = """
exclude:
  - "node_modules/**"
  - "*.test.js"

confidence_threshold: 0.85

custom_patterns:
  - name: "Test Pattern"
    pattern: "TEST_[A-Z0-9]{16}"
    confidence: 0.90

allowlist:
  - file: "test.py"
    line: 10
    reason: "Test fixture"

ignore_patterns:
  - "example_key"
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        f.write(config_content)
        config_path = Path(f.name)
    
    try:
        config = ConfigLoader.load(config_path)
        
        assert len(config.exclude) == 2
        assert "node_modules/**" in config.exclude
        assert config.confidence_threshold == 0.85
        assert len(config.custom_patterns) == 1
        assert config.custom_patterns[0].name == "Test Pattern"
        assert len(config.allowlist) == 1
        assert config.allowlist[0].file == "test.py"
        assert "example_key" in config.ignore_patterns
    finally:
        config_path.unlink()


def test_invalid_confidence_threshold():
    """Test that invalid confidence threshold raises error"""
    config_content = """
confidence_threshold: 1.5
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        f.write(config_content)
        config_path = Path(f.name)
    
    try:
        with pytest.raises(ValueError, match="confidence_threshold must be between"):
            ConfigLoader.load(config_path)
    finally:
        config_path.unlink()


def test_create_default_config():
    """Test creating default config file"""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / ".secretguard.yml"
        ConfigLoader.create_default_config(config_path)
        
        assert config_path.exists()
        content = config_path.read_text()
        assert "exclude:" in content
        assert "confidence_threshold:" in content
        assert "custom_patterns:" in content
