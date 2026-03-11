# SecretGuard v0.2.0 - Product Requirements Document

## Executive Summary

SecretGuard v0.1.0 successfully detects secrets using regex and entropy analysis. Version 0.2.0 will focus on **usability, customization, and CI/CD integration** to make the tool production-ready for real-world use.

---

## Goals

1. **Reduce False Positives** - Give users control over what gets flagged
2. **Improve Workflow Integration** - Make it easy to use in daily development
3. **Better Reporting** - Professional, shareable reports
4. **Customization** - Support team-specific secret patterns

---

## Feature Set

### 1. Configuration File Support (.secretguard.yml)

**Priority:** HIGH  
**Effort:** Medium  
**Impact:** High

**Description:**  
Currently mentioned in README but not implemented. Users need a way to configure SecretGuard per-project.

**Requirements:**
- [ ] Load `.secretguard.yml` from project root
- [ ] Support exclude patterns (paths/files to ignore)
- [ ] Configurable confidence threshold
- [ ] Custom regex patterns
- [ ] Allowlist for known false positives

**Config Schema:**
```yaml
# Paths to exclude from scanning
exclude:
  - "node_modules/**"
  - "*.test.js"
  - "vendor/**"

# Minimum confidence threshold (0.0-1.0)
confidence_threshold: 0.75

# Custom patterns (regex)
custom_patterns:
  - name: "Custom API Key"
    pattern: "CUSTOM_[A-Z0-9]{32}"
    severity: high
    remediation: "Move to environment variables"

# Allowlist (ignore specific findings)
allowlist:
  - file: "tests/fixtures/secrets.py"
    line: 10
    reason: "Test fixture, not a real secret"
  - pattern: "example_api_key_here"
    reason: "Documentation placeholder"
```

**Acceptance Criteria:**
- Config file is auto-detected if present
- CLI flags override config file settings
- Invalid config shows helpful error messages
- `secretguard init` creates a template config

---

### 2. Allowlist / Ignore Functionality

**Priority:** HIGH  
**Effort:** Medium  
**Impact:** High

**Description:**  
Users need to mark false positives as "known safe" to avoid seeing them repeatedly.

**Requirements:**
- [ ] Ignore specific file:line combinations
- [ ] Ignore patterns (regex for false positives)
- [ ] Comment-based ignoring (e.g., `# secretguard:ignore`)
- [ ] Ignore entire files or directories

**Implementation:**
```python
# In code - inline ignore
password = "test_password_123"  # secretguard:ignore

# Or block ignore
# secretguard:ignore-start
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
SECRET = "example_secret"
# secretguard:ignore-end
```

**Acceptance Criteria:**
- Ignored findings don't appear in reports
- Allowlist persists in config file
- Can ignore by file, line, pattern, or comment
- CLI command to add to allowlist: `secretguard ignore <file>:<line>`

---

### 3. HTML Report Generation

**Priority:** MEDIUM  
**Effort:** Medium  
**Impact:** Medium

**Description:**  
Professional HTML reports for sharing with teams, management, or attaching to PRs.

**Requirements:**
- [ ] Beautiful, responsive HTML output
- [ ] Summary dashboard (stats, charts)
- [ ] Filterable/sortable findings table
- [ ] Severity-based color coding
- [ ] Exportable/printable

**Design:**
- Clean, modern UI (Bootstrap or Tailwind CDN)
- File grouping with collapsible sections
- Confidence score visualization (progress bars)
- Click to expand line context
- Dark mode support

**Acceptance Criteria:**
- `secretguard scan . --format html --output report.html`
- Opens in browser correctly
- Self-contained (no external dependencies)
- Mobile-friendly

---

### 4. Pre-commit Hook Integration

**Priority:** HIGH  
**Effort:** Low  
**Impact:** High

**Description:**  
Prevent secrets from being committed in the first place.

**Requirements:**
- [ ] Pre-commit hook script
- [ ] Easy installation (`secretguard install-hook`)
- [ ] Fast scanning (only staged files)
- [ ] Clear error messages when secrets detected
- [ ] Bypass option for emergencies (`--no-verify`)

**Installation Flow:**
```bash
# In project directory
secretguard install-hook

# Creates .git/hooks/pre-commit
# Scans only staged files
# Blocks commit if secrets found
```

**Acceptance Criteria:**
- Hook installs in `.git/hooks/pre-commit`
- Scans only `git diff --cached --name-only` files
- Returns exit code 1 if secrets found
- Shows clear message with instructions
- Doesn't slow down commits (< 2s for typical commit)

---

### 5. Custom Pattern Support (User-Defined)

**Priority:** MEDIUM  
**Effort:** Low  
**Impact:** Medium

**Description:**  
Teams have internal secret formats (e.g., `ACME_TOKEN_xxxxx`). Let them define custom patterns.

**Requirements:**
- [ ] Load patterns from config file
- [ ] Support regex with named groups
- [ ] Set confidence/severity per pattern
- [ ] Custom remediation messages

**Example Config:**
```yaml
custom_patterns:
  - name: "Acme Corp API Key"
    pattern: "ACME_[A-Z0-9]{32}"
    confidence: 0.95
    severity: critical
    remediation: "Contact security@acme.com to rotate"
  
  - name: "Internal Service Token"
    pattern: "SVC_TOKEN_[a-f0-9]{40}"
    confidence: 0.90
    severity: high
    remediation: "Use Kubernetes secrets"
```

**Acceptance Criteria:**
- Patterns load from `.secretguard.yml`
- Patterns validated on load (invalid regex = error)
- Custom patterns appear in scan results
- Can override confidence/remediation per pattern

---

### 6. Interactive Review Mode

**Priority:** LOW  
**Effort:** Medium  
**Impact:** Medium

**Description:**  
Let users review findings interactively and decide which to ignore.

**Requirements:**
- [ ] `secretguard review` command
- [ ] Show findings one-by-one
- [ ] Options: ignore, keep, view context, add to allowlist
- [ ] Save decisions to config

**User Flow:**
```bash
$ secretguard review

Finding 1/6: config.py:12 (Stripe API Key, 95% confidence)
> STRIPE_API_KEY = "sk_live_FAKE_DEMO_KEY_NOT_REAL_123456789"

Options:
  [i] Ignore this finding
  [a] Add to allowlist
  [v] View more context
  [n] Next
  [q] Quit

Your choice: a
Reason: Production key (will rotate)
✅ Added to allowlist in .secretguard.yml
```

**Acceptance Criteria:**
- Interactive TUI with keyboard shortcuts
- Can view file context (5 lines before/after)
- Allowlist updates persist to config
- Can resume interrupted review

---

### 7. Git History Scanning

**Priority:** LOW  
**Effort:** High  
**Impact:** Medium

**Description:**  
Scan entire git history for secrets (even in deleted files).

**Requirements:**
- [ ] `secretguard scan --history` flag
- [ ] Scan all commits (or range)
- [ ] Report secrets even in deleted files
- [ ] Show commit hash where secret was introduced

**Use Case:**  
"We just realized we might have committed AWS keys 6 months ago. Scan the entire history."

**Acceptance Criteria:**
- Scans git log efficiently
- Reports commit hash + file + line
- Works with large repos (1000+ commits)
- Can limit to date range or commit range

---

## Success Metrics

| Metric | Target |
|--------|--------|
| False positive rate | < 5% (from ~15% in v0.1) |
| Scan speed | < 5s for 1000 files |
| User adoption | 100+ GitHub stars in 3 months |
| Pre-commit hook usage | 50+ teams |
| Config file adoption | 80% of users |

---

## Technical Architecture

### New Modules

```
secretguard/
├── config/
│   └── loader.py          # Load .secretguard.yml
├── hooks/
│   ├── pre_commit.py      # Git hook logic
│   └── installer.py       # Hook installation
├── reporters/
│   ├── html_reporter.py   # NEW: HTML reports
│   └── ...
├── allowlist/
│   └── manager.py         # Allowlist checking
└── ...
```

### Dependencies (New)

- `PyYAML` - Config file parsing
- `jinja2` - HTML template rendering
- `gitpython` - Git history scanning (optional)

---

## Implementation Plan

### Phase 1: Core Features (v0.2.0)
**Timeline:** 1-2 hours  
**Features:**
1. Configuration file support ✅
2. Allowlist functionality ✅
3. HTML reports ✅
4. Pre-commit hook ✅

### Phase 2: Advanced Features (v0.3.0)
**Timeline:** Future  
**Features:**
5. Interactive review mode
6. Git history scanning
7. ML-based detection

---

## Testing Requirements

- [ ] Unit tests for config loading
- [ ] Unit tests for allowlist matching
- [ ] Integration test for pre-commit hook
- [ ] Sample HTML report generation test
- [ ] Config validation tests

---

## Documentation Updates

- [ ] Update README with new features
- [ ] Add configuration guide
- [ ] Pre-commit hook setup guide
- [ ] Example configs for common use cases
- [ ] Migration guide from v0.1 to v0.2

---

## Breaking Changes

None. v0.2.0 is fully backward compatible with v0.1.0.

---

## Release Checklist

- [ ] All tests passing
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bump in pyproject.toml
- [ ] Git tag `v0.2.0`
- [ ] GitHub release with notes
- [ ] PyPI publish (if applicable)

---

**Approved:** Pending  
**Author:** Davis  
**Date:** March 11, 2026  
**Version:** 0.2.0  
**Status:** Ready for Implementation
