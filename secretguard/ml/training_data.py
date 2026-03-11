"""Built-in training data for the ML classifier"""

# (string, is_secret) pairs
TRAINING_DATA = [
    # Secrets (label=1)
    ("AKIAIOSFODNN7EXAMPLE", 1),
    ("ghp_ABCDEFghijklmnopqrstuvwxyz1234567890", 1),
    ("sk_live_abcdefghijklmnopqrstuvwx", 1),
    ("SG.abcdefghijklmnop.qrstuvwxyz0123456789ABCDE", 1),
    ("xoxb-1234567890-1234567890123-AbCdEfGhIjKl", 1),
    ("glpat-xxxxxxxxxxxxxxxxxxxx", 1),
    ("npm_abcdefghijklmnopqrstuvwxyz1234567890", 1),
    ("pypi-AgEIcHlwaS5vcmcCJGY4NjM1YjEyLTBiZDAtNGI1Zi1h", 1),
    ("dG9rZW4xMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFy", 1),
    ("A3T2abcDEFghiJKLmnoPQRstuVWXyz1234567890abcdef", 1),
    ("7f3a8b2c9d4e5f6a1b0c3d4e5f6a7b8c9d0e1f2a3b4c", 1),
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkw", 1),

    # Non-secrets (label=0)
    ("hello world", 0),
    ("function getData()", 0),
    ("import os", 0),
    ("node_modules", 0),
    ("README.md", 0),
    ("version = 1.0.0", 0),
    ("localhost:8080", 0),
    ("Content-Type: application/json", 0),
    ("550e8400-e29b-41d4-a716-446655440000", 0),
    ("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0", 0),
    ("The quick brown fox jumps over the lazy dog", 0),
    ("background-color: #ffffff", 0),
    ("margin: 0 auto", 0),
    ("2024-01-15T10:30:00Z", 0),
    ("user@example.com", 0),
    ("https://example.com/api/v1/users", 0),
]
