"""
Password Security Auditor — analyzes password strength using entropy calculation
and pattern detection (dictionary words, repeats, keyboard patterns), checks
against known breach databases via the Have I Been Pwned k-anonymity API, and
produces a scored report with recommendations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# --- Keyboard pattern detection ---

KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]

# Adjacent keys on QWERTY (including diagonals)
KEYBOARD_ADJACENCY = {}
for row in KEYBOARD_ROWS:
    for i, key in enumerate(row):
        neighbors = []
        if i > 0:
            neighbors.append(row[i - 1])
        if i < len(row) - 1:
            neighbors.append(row[i + 1])
        KEYBOARD_ADJACENCY[key] = neighbors

# Add cross-row adjacencies (simplified)
CROSS_ROW = {
    'q': ['w', 'a'], 'w': ['q', 'e', 'a', 's'], 'e': ['w', 'r', 's', 'd'],
    'r': ['e', 't', 'd', 'f'], 't': ['r', 'y', 'f', 'g'], 'y': ['t', 'u', 'g', 'h'],
    'u': ['y', 'i', 'h', 'j'], 'i': ['u', 'o', 'j', 'k'], 'o': ['i', 'p', 'k', 'l'],
    'p': ['o', 'l'], 'a': ['q', 'w', 's', 'z'], 's': ['a', 'w', 'e', 'd', 'z', 'x'],
    'd': ['s', 'e', 'r', 'f', 'x', 'c'], 'f': ['d', 'r', 't', 'g', 'c', 'v'],
    'g': ['f', 't', 'y', 'h', 'v', 'b'], 'h': ['g', 'y', 'u', 'j', 'b', 'n'],
    'j': ['h', 'u', 'i', 'k', 'n', 'm'], 'k': ['j', 'i', 'o', 'l', 'm'],
    'l': ['k', 'o', 'p'], 'z': ['a', 's', 'x'], 'x': ['z', 's', 'd', 'c'],
    'c': ['x', 'd', 'f', 'v'], 'v': ['c', 'f', 'g', 'b'], 'b': ['v', 'g', 'h', 'n'],
    'n': ['b', 'h', 'j', 'm'], 'm': ['n', 'j', 'k'],
}
KEYBOARD_ADJACENCY.update(CROSS_ROW)


class StrengthLevel(Enum):
    VERY_WEAK = 0
    WEAK = 1
    FAIR = 2
    STRONG = 3
    VERY_STRONG = 4


@dataclass
class AuditResult:
    password: str
    strength_level: StrengthLevel
    entropy_bits: float
    score: int  # 0-100
    patterns_found: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    breached: bool = False
    breach_count: int = 0
    analysis_time_ms: float = 0.0


# Common password patterns to detect
COMMON_PATTERNS = [
    (r'(.)\1{2,}', "repeated characters (e.g., 'aaa')"),
    (r'(.{2,})\1{1,}', "repeated sequence (e.g., 'abcabc')"),
    (r'[a-z]+', "all lowercase"),
    (r'[A-Z]+', "all uppercase"),
    (r'\d+$', "ends with digits"),
    (r'^\d+', "starts with digits"),
    (r'[!@#$%^&*(),.?\":{}|<>]', "contains special characters"),
]


def detect_keyboard_walk(password: str) -> list[str]:
    """Detect keyboard walk patterns (qwerty, asdf, zxcv, etc.)."""
    found = []
    pwd_lower = password.lower()

    # Check for sequential keyboard row walks
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 2):
            seq = row[i:i+3]
            if seq in pwd_lower or seq[::-1] in pwd_lower:
                found.append(f"keyboard row sequence: '{seq}'")
                break

    # Check for adjacency walks (3+ consecutive adjacent keys)
    if len(pwd_lower) >= 3:
        walk_len = 1
        for i in range(1, len(pwd_lower)):
            prev = pwd_lower[i - 1]
            curr = pwd_lower[i]
            if prev in KEYBOARD_ADJACENCY and curr in KEYBOARD_ADJACENCY[prev]:
                walk_len += 1
                if walk_len >= 3:
                    found.append(f"keyboard walk of {walk_len} keys detected")
                    break
            else:
                walk_len = 1

    return found


def detect_dictionary_words(password: str, common_words: set[str]) -> list[str]:
    """Check if password contains common dictionary words."""
    found = []
    pwd_lower = password.lower()

    # Check for common words
    for word in common_words:
        if len(word) >= 4 and word in pwd_lower:
            found.append(f"common word found: '{word}'")
            if len(found) >= 3:
                break

    # Check for substrings that are common words
    for word in common_words:
        if len(word) >= 5 and word in pwd_lower:
            if f"common word found: '{word}'" not in found:
                found.append(f"common word found: '{word}'")
            if len(found) >= 5:
                break

    return found


def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy of password in bits."""
    if not password:
        return 0.0

    # Count character frequencies
    freq = defaultdict(int)
    for ch in password:
        freq[ch] += 1

    length = len(password)
    entropy = 0.0
    for count in freq.values():
        prob = count / length
        if prob > 0:
            entropy -= prob * math.log2(prob)

    return entropy * length


def estimate_charset_size(password: str) -> int:
    """Estimate the effective character set size."""
    size = 0
    if re.search(r'[a-z]', password):
        size += 26
    if re.search(r'[A-Z]', password):
        size += 26
    if re.search(r'\d', password):
        size += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        size += 33  # Common special chars
    return max(size, 1)


def check_breach(password: str) -> tuple[bool, int]:
    """
    Check if password has been seen in breaches using HIBP k-anonymity API.
    Returns (breached, count).
    """
    try:
        sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        import urllib.request
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        req = urllib.request.Request(url, headers={"User-Agent": "PasswordAuditor/1.0"})

        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode('utf-8')

        for line in content.splitlines():
            parts = line.split(':')
            if len(parts) == 2 and parts[0].strip() == suffix:
                return True, int(parts[1].strip())

        return False, 0
    except Exception:
        return False, 0


def audit_password(password: str, check_breach_flag: bool = True,
                   common_words: Optional[set[str]] = None) -> AuditResult:
    """Perform full security audit on a password."""
    start = time.time()

    result = AuditResult(password=password, strength_level=StrengthLevel.VERY_WEAK,
                         entropy_bits=0.0, score=0)

    # Normalize for analysis
    pwd = password
    pwd_lower = pwd.lower()

    # --- Pattern detection ---
    patterns = []

    # Repeated characters
    if re.search(r'(.)\1{2,}', pwd):
        patterns.append("repeated_characters")

    # Repeated sequences
    if re.search(r'(.{2,})\1{1,}', pwd):
        patterns.append("repeated_sequence")

    # Keyboard walks
    kb_walks = detect_keyboard_walk(pwd)
    if kb_walks:
        patterns.extend(["keyboard_walk"] * len(kb_walks))
        result.patterns_found.extend(kb_walks)

    # Dictionary words (use built-in common list)
    builtin_common = {
        "password", "123456", "12345678", "qwerty", "abc123", "monkey",
        "1234567", "letmein", "admin", "welcome", "donald", "master",
        "login", "princess", "football", "shadow", "sunshine", "trustno1",
        "iloveyou", "batman", "access", "hello", "charlie", "donald",
        "passw0rd", "password1", "p@ssw0rd", "passwd", "qwerty123",
    }
    words = detect_dictionary_words(pwd, builtin_common)
    if words:
        patterns.append("dictionary_word")
        result.patterns_found.extend(words)

    if common_words:
        extra = detect_dictionary_words(pwd, common_words)
        result.patterns_found.extend(extra)

    result.patterns_found = list(set(result.patterns_found))

    # --- Entropy calculation ---
    charset_size = estimate_charset_size(pwd)
    entropy = calculate_entropy(pwd)
    result.entropy_bits = round(entropy, 1)

    # --- Scoring ---
    score = 0

    # Length component (max 30 points)
    length = len(pwd)
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 25
    elif length >= 10:
        score += 20
    elif length >= 8:
        score += 15
    elif length >= 6:
        score += 10
    else:
        score += 5

    # Complexity component (max 30 points)
    has_lower = bool(re.search(r'[a-z]', pwd))
    has_upper = bool(re.search(r'[A-Z]', pwd))
    has_digit = bool(re.search(r'\d', pwd))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', pwd))

    complexity_types = sum([has_lower, has_upper, has_digit, has_special])
    score += min(30, complexity_types * 7)

    # Mix bonus (max 10 points)
    if has_lower and has_upper:
        score += 5
    if has_digit and (has_lower or has_upper):
        score += 3
    if has_special and complexity_types >= 3:
        score += 5

    # Entropy bonus (max 15 points)
    if entropy > 60:
        score += 15
    elif entropy > 40:
        score += 10
    elif entropy > 20:
        score += 5

    # Pattern penalties (max -40 points)
    penalty = 0
    if "repeated_characters" in patterns:
        penalty -= 15
    if "repeated_sequence" in patterns:
        penalty -= 10
    if "keyboard_walk" in patterns:
        penalty -= 10
    if "dictionary_word" in patterns:
        penalty -= 15
    if not has_upper and length > 8:
        penalty -= 5
    if not has_digit and length > 10:
        penalty -= 5

    score = max(0, min(100, score + penalty))

    # --- Strength level ---
    if score >= 80:
        level = StrengthLevel.VERY_STRONG
    elif score >= 60:
        level = StrengthLevel.STRONG
    elif score >= 40:
        level = StrengthLevel.FAIR
    elif score >= 20:
        level = StrengthLevel.WEAK
    else:
        level = StrengthLevel.VERY_WEAK

    result.strength_level = level
    result.score = score

    # --- Recommendations ---
    if length < 12:
        result.recommendations.append("Use at least 12 characters (16+ recommended)")
    if not has_upper:
        result.recommendations.append("Add uppercase letters")
    if not has_digit:
        result.recommendations.append("Add numbers")
    if not has_special:
        result.recommendations.append("Add special characters (!@#$%^&*)")
    if "repeated_characters" in patterns:
        result.recommendations.append("Avoid repeated characters (aaa, 111)")
    if "repeated_sequence" in patterns:
        result.recommendations.append("Avoid repeating patterns (abcabc)")
    if "keyboard_walk" in result.patterns_found:
        result.recommendations.append("Avoid keyboard walks (qwerty, asdf)")
    if "dictionary_word" in patterns:
        result.recommendations.append("Avoid common dictionary words")
    if entropy < 30:
        result.recommendations.append("Password has low entropy — use more character variety")

    # --- Breach check ---
    if check_breach_flag:
        breached, count = check_breach(pwd)
        result.breached = breached
        result.breach_count = count
        if breached:
            result.recommendations.append(
                f"WARNING: This password appears in {count} known data breaches. "
                f"Change it immediately."
            )

    result.analysis_time_ms = (time.time() - start) * 1000
    return result


# Built-in common password list for quick checks
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "admin", "welcome", "donald", "master",
    "login", "princess", "football", "shadow", "sunshine", "trustno1",
    "iloveyou", "batman", "access", "hello", "charlie", "passw0rd",
    "password1", "p@ssw0rd", "passwd", "qwerty123", "123456789",
    "1234567890", "12345", "12345678910", "password123", "admin123",
    "root", "toor", "1234", "123", "test", "test123", "guest",
    "user", "changeme", "secret", "Passw0rd", "PASSWORD",
}


def main():
    parser = argparse.ArgumentParser(
        description="Password Security Auditor — analyze password strength, "
                    "detect patterns, and check breach databases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m password_auditor "MyP@ssw0rd123"
  python -m password_auditor --file passwords.txt
  python -m password_auditor --list "pass1" "pass2" "pass3"
  python -m password_auditor --json "MySecret123!"
        """,
    )
    parser.add_argument("password", nargs="?", help="Password to audit")
    parser.add_argument("--file", "-f", help="Read passwords from file (one per line)")
    parser.add_argument("--list", "-l", nargs="+", help="Audit one or more passwords")
    parser.add_argument("--no-breach", action="store_true",
                        help="Skip HIBP breach check (faster, offline)")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Output as JSON")
    parser.add_argument("--common-words", help="File with additional common words (one per line)")

    args = parser.parse_args()

    # Collect passwords to audit
    passwords = []

    if args.list:
        passwords.extend(args.list)
    if args.password:
        passwords.append(args.password)
    if args.file:
        try:
            with open(args.file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        passwords.append(line)
        except FileNotFoundError:
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            return 1

    if not passwords:
        parser.print_help()
        return 1

    # Load additional common words if provided
    extra_words = set()
    if args.common_words:
        try:
            with open(args.common_words) as f:
                for line in f:
                    w = line.strip().lower()
                    if w:
                        extra_words.add(w)
        except FileNotFoundError:
            print(f"Warning: Common words file not found: {args.common_words}", file=sys.stderr)

    # Audit each password
    results = []
    for pwd in passwords:
        result = audit_password(pwd, check_breach_flag=not args.no_breach,
                              common_words=extra_words if extra_words else None)
        results.append(result)

    # Output
    if args.json:
        output = []
        for r in results:
            output.append({
                # Never emit credentials. Results are safe to persist or pipe.
                "password": "[redacted]",
                "strength": r.strength_level.name,
                "score": r.score,
                "entropy_bits": r.entropy_bits,
                "patterns": r.patterns_found,
                "breached": r.breached,
                "breach_count": r.breach_count,
                "recommendations": r.recommendations,
                "analysis_time_ms": round(r.analysis_time_ms, 2),
            })
        print(json.dumps(output, indent=2))
    else:
        for r in results:
            level_colors = {
                StrengthLevel.VERY_WEAK: "\033[91m",  # Red
                StrengthLevel.WEAK: "\033[31m",       # Dark red
                StrengthLevel.FAIR: "\033[33m",       # Yellow
                StrengthLevel.STRONG: "\033[32m",     # Green
                StrengthLevel.VERY_STRONG: "\033[92m", # Bright green
            }
            reset = "\033[0m"

            color = level_colors.get(r.strength_level, "")
            print(f"\n{'='*60}")
            print(f"  PASSWORD AUDIT: {r.password}")
            print(f"{'='*60}")
            print(f"  Score: {r.score}/100")
            print(f"  Strength: {color}{r.strength_level.name}{reset}")
            print(f"  Entropy: {r.entropy_bits} bits")
            print(f"  Patterns found: {len(r.patterns_found)}")
            for p in r.patterns_found:
                print(f"    - {p}")
            if r.breached:
                print(f"\033[91m  WARNING: Found in {r.breach_count} data breaches!\033[0m")
            if r.recommendations:
                print(f"\n  Recommendations:")
                for rec in r.recommendations:
                    print(f"    * {rec}")
            print(f"  Analysis time: {r.analysis_time_ms:.2f}ms")

    return 0


if __name__ == "__main__":
    sys.exit(main())
