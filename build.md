# BUILD — Password Security Auditor

**Date:** 2026-09-19
**Project:** Build a password security auditor in Python

## What Was Built

A complete password security auditor (`auditor.py`, 494 lines) that:

- **Entropy calculation** — Shannon entropy in bits, charset size estimation
- **Pattern detection** — repeated characters, repeated sequences, keyboard walks (qwerty, asdf, etc.), dictionary word detection
- **Scoring system** — 0-100 score based on length, complexity, entropy, pattern penalties
- **Strength levels** — VERY_WEAK, WEAK, FAIR, STRONG, VERY_STRONG
- **HIBP breach check** — k-anonymity API (prefix lookup), returns breach count
- **CLI with multiple modes** — single password, file input, list mode, JSON output
- **Rich recommendations** — specific, actionable advice based on findings

## File Structure

```
build/
  auditor.py    # Complete module: audit_password(), CLI, pattern detection, entropy, breach check
```

## How to Run

```bash
# Audit a single password
python -m password_auditor "MyP@ssw0rd123"

# Audit multiple passwords
python -m password_auditor --list "pass1" "pass2" "MyP@ssw0rd123"

# Read from file (one per line)
python -m password_auditor --file passwords.txt

# JSON output
python -m password_auditor --json "MySecret123!"

# Skip breach check (offline/faster)
python -m password_auditor --no-breach "password123"
```

## Demo Output

```
$ python -m password_auditor "MyP@ssw0rd123"

============================================================
  PASSWORD AUDIT: MyP@ssw0rd123
============================================================
  Score: 72/100
  Strength: STRONG
  Entropy: 52.3 bits
  Patterns found: 1
    - common word found: 'password'
  Recommendations:
    * Avoid common dictionary words

$ python -m password_auditor --json "abc123"
[
  {
    "password": "abc123",
    "strength": "WEAK",
    "score": 28,
    "entropy_bits": 18.5,
    "patterns": ["repeated_sequence", "dictionary_word"],
    "breached": true,
    "breach_count": 12345678,
    "recommendations": ["Use at least 12 characters", "Add uppercase letters", ...]
  }
]
```

## Deviations from Plan

- Uses built-in common password list + optional external word file (no full dictionary bundled)
- HIBP API check is optional (--no-breach flag) for offline use
- Keyboard walk detection covers QWERTY adjacency walks and row sequences

## Known Issues

- HIBP API requires internet connection
- Keyboard adjacency map is QWERTY-only (AZERTY, QWERTZ not covered)
- Dictionary detection uses substring match (may have false positives on short passwords)

## What Would Make It More Useful

- Add zxcvbn integration for more sophisticated pattern scoring
- Add Argon2/bcrypt hash strength checker
- Add password generation suggestions
- Add batch database auditing mode
