# Password Auditor

Password security auditor in Python. Analyze password strength, detect common patterns, keyboard walks, dictionary words, and estimate entropy.

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)


## Features

- **Strength Assessment** — Evaluate password strength with entropy calculation
- **Pattern Detection** — Detect dictionary words, keyboard walks, and common patterns
- **Common Password Check** — Check against a list of commonly used passwords
- **Entropy Estimation** — Calculate character set size and password entropy
- **Keyboard Walk Detection** — Identify passwords formed by keyboard patterns (qwerty, asdf, etc.)
- **CLI Interface** — Simple command-line interface

## Installation

```bash
git clone https://github.com/aimansam/password-auditor
cd password-auditor
pip install -e .
```

## Quick Start

Audit a password:

```bash
python auditor.py "MyP@ssw0rd!"
```

Audit multiple passwords from a file:

```bash
python auditor.py --file passwords.txt
```

Check against common passwords:

```bash
python auditor.py --check-common "password123"
```

## API Usage

```python
from auditor import audit_password, AuditResult

result: AuditResult = audit_password("MyP@ssw0rd!")
print(f"Strength: {result.strength}")
print(f"Score: {result.score}")
print(f"Issues: {result.issues}")
```

## Requirements

- Python 3.9+
- No external dependencies (stdlib only)

## License

MIT

