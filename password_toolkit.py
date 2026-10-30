#!/usr/bin/env python3
"""Password Security Toolkit: strength checker and secure password generator."""
import argparse
import getpass
import math
import re
import secrets
import string

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123", "password1",
    "111111", "letmein", "admin", "welcome", "iloveyou", "monkey", "dragon",
    "football", "123123", "000000", "qwerty123", "admin123", "passw0rd",
}
SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
RATINGS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]


def pool_size(password):
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool += 33
    return pool


def entropy_bits(password):
    pool = pool_size(password)
    return len(password) * math.log2(pool) if pool else 0.0


def has_sequence(password, length=4):
    lowered = password.lower()
    for seq in SEQUENCES:
        for i in range(len(seq) - length + 1):
            chunk = seq[i:i + length]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def analyze(password):
    """Return entropy, a 0-4 score, a rating and improvement feedback."""
    bits = entropy_bits(password)
    score = 0 if bits < 28 else 1 if bits < 36 else 2 if bits < 60 else 3 if bits < 80 else 4
    feedback = []

    if password.lower() in COMMON_PASSWORDS:
        score = 0
        feedback.append("This is one of the most common passwords.")
    if len(password) < 8:
        score = min(score, 1)
        feedback.append("Use at least 12 characters.")
    elif len(password) < 12:
        feedback.append("Longer is better: aim for 12 or more characters.")
    if has_sequence(password):
        score = max(0, score - 1)
        feedback.append("Avoid sequences such as 'abcd', '1234' or 'qwer'.")
    if re.search(r"(.)\1{2,}", password):
        score = max(0, score - 1)
        feedback.append("Avoid repeating the same character 3+ times.")
    if password.isdigit():
        score = max(0, score - 1)
        feedback.append("Do not use digits only.")
    if not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password):
        feedback.append("Mix upper and lower case letters.")
    if not re.search(r"\d", password):
        feedback.append("Add digits.")
    if not re.search(r"[^A-Za-z0-9]", password):
        feedback.append("Add symbols.")

    return {"entropy_bits": round(bits, 1), "score": score,
            "rating": RATINGS[score], "feedback": feedback}


def generate_password(length=16, use_symbols=True):
    """Cryptographically secure password with at least one of each character class."""
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if use_symbols:
        classes.append(SYMBOLS)
    if length < len(classes) * 2:
        raise ValueError(f"Length must be at least {len(classes) * 2}.")
    alphabet = "".join(classes)
    chars = [secrets.choice(c) for c in classes]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Password Security Toolkit")
    sub = ap.add_subparsers(dest="command", required=True)

    c = sub.add_parser("check", help="rate the strength of a password")
    c.add_argument("password", nargs="?",
                   help="omit to type it hidden (keeps it out of shell history)")

    g = sub.add_parser("generate", help="generate secure random passwords")
    g.add_argument("-l", "--length", type=int, default=16)
    g.add_argument("-n", "--count", type=int, default=1)
    g.add_argument("--no-symbols", action="store_true")

    args = ap.parse_args(argv)
    if args.command == "check":
        pw = args.password if args.password is not None else getpass.getpass("Password: ")
        result = analyze(pw)
        print(f"Rating : {result['rating']} ({result['score']}/4)")
        print(f"Entropy: {result['entropy_bits']} bits")
        for tip in result["feedback"]:
            print(f"  - {tip}")
    else:
        try:
            for _ in range(args.count):
                print(generate_password(args.length, not args.no_symbols))
        except ValueError as exc:
            raise SystemExit(f"Error: {exc}")


if __name__ == "__main__":
    main()
