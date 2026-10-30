# Password Security Toolkit

A command-line toolkit with two tools: a **password strength checker** and a **secure password generator**. Built with **Python** (standard library only).

## Features
- Strength rating (0-4) based on estimated entropy
- Detects common passwords, keyboard/alphabet/number sequences, repeated characters and digits-only passwords
- Actionable feedback on how to improve a password
- Generator uses Python's `secrets` module (cryptographically secure) and guarantees every character class
- Hidden password prompt (`getpass`) so the password never lands in shell history

## Usage
```bash
python password_toolkit.py check              # prompts securely
python password_toolkit.py check "Summer2024"
python password_toolkit.py generate -l 20 -n 5
python password_toolkit.py generate --no-symbols
```

## How it works
Entropy is estimated as `length x log2(character pool size)`, then adjusted down for known weak patterns. This is a learning tool: real-world strength also depends on breach exposure, so use a password manager and enable multi-factor authentication.

## Run the tests
```bash
python -m unittest -v
```

## Skills demonstrated
Information security fundamentals (password policy, entropy, secure randomness, MFA awareness), regular expressions, Python CLI design, unit testing.

## License
MIT
