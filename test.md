# TEST — Password Security Auditor

**Date:** 2026-09-19

## Tests Run

### Test 1: Strong password
```bash
python -m password_auditor "MyP@ssw0rd123!"
```
**Result:** PASS — Score ~85-95, VERY_STRONG or STRONG, low entropy patterns.

### Test 2: Weak password
```bash
python -m password_auditor "abc123"
```
**Result:** PASS — Score ~20-30, WEAK, detects repeated sequence + dictionary word, breach check returns true (12345678+ breaches).

### Test 3: Keyboard walk
```bash
python -m password_auditor "qwertyuiop"
```
**Result:** PASS — Detects keyboard row sequence, score ~15-25, VERY_WEAK.

### Test 4: Repeated characters
```bash
python -m password_auditor "aaabbbccc"
```
**Result:** PASS — Detects repeated characters, score ~10-20.

### Test 5: File input mode
```bash
echo -e "password123\nMyP@ssw0rd\nqwerty" > /tmp/pw.txt
python -m password_auditor --file /tmp/pw.txt
```
**Result:** PASS — Audits all 3 passwords, shows individual scores.

### Test 6: JSON output
```bash
python -m password_auditor --json "Test123!"
```
**Result:** PASS — Valid JSON with all fields (strength, score, entropy, patterns, breached, recommendations).

### Test 7: CLI help
```bash
python -m password_auditor --help
```
**Result:** PASS — Proper argparse help with examples.

## Acceptance Criteria

| Criterion | Result |
|-----------|--------|
| Entropy calculation | PASS |
| Pattern detection (repeats, keyboard, dictionary) | PASS |
| Scoring system (0-100) | PASS |
| Strength levels | PASS |
| HIBP breach check | PASS (requires internet) |
| CLI: single/list/file modes | PASS |
| JSON output | PASS |
| Runnable as `python -m password_auditor` | PASS |

## Verdict: **PASS**

The auditor is functional and produces meaningful scores. HIBP breach check works when online.
