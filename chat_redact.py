"""
chat-redact: remove private details from WhatsApp chat exports before you share them.

Catches Indian and common personal data: phone numbers, emails, UPI IDs, Aadhaar,
PAN, GSTIN, IFSC, bank account numbers, card numbers, passwords/PINs/OTPs and IP
addresses. Keeps the chat readable: timestamps and structure stay as they are.

Pure Python standard library. No data leaves your computer.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from dataclasses import dataclass, field

__version__ = "0.1.0"

# --------------------------------------------------------------------------
# Checksums (used to cut false positives)
# --------------------------------------------------------------------------

_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_ok(digits: str) -> bool:
    """True if the digit string passes the Verhoeff checksum (used by Aadhaar)."""
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def luhn_ok(digits: str) -> bool:
    """True if the digit string passes the Luhn checksum (used by payment cards)."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


# --------------------------------------------------------------------------
# Detectors. Order matters: more specific patterns run first.
# Each rule: (label, compiled regex, optional validator on the match text,
#             group to replace or 0 for whole match)
# --------------------------------------------------------------------------

RULES = [
    # One-time codes, card CVVs and PINs: keyword followed by 3-8 digits
    ("OTP",
     re.compile(r"(?i)\b(?:otp|verification\s+code|one[\s\-]time\s+(?:password|code))\b\s*(?:is|:|=|-)?\s*(?P<code>\d{4,8})\b"),
     None, "code"),
    ("CVV",
     re.compile(r"(?i)\b(?:cvv|cvc)\b\s*(?:is|:|=|-)?\s*(?P<code>\d{3,4})\b"),
     None, "code"),
    ("PIN",
     re.compile(r"(?i)\b(?:m?pin|upi\s*pin|atm\s*pin)\b\s*(?:is|:|=|-)?\s*(?P<code>\d{4,6})\b"),
     None, "code"),
    # Passwords after a keyword: "password is Shop@123", "pwd: tiger#99"
    # Needs 4+ characters and a digit or symbol, so "pass 2 boxes" is left alone.
    ("PASSWORD",
     re.compile(r"(?i)\b(?:password|passwd|passcode|pass|pwd)\b\s*(?:is|:|=|-)?\s*(?P<secret>(?=\S*[\d@#$%^&*!?_])\S{4,})"),
     None, "secret"),
    ("EMAIL",
     re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b"),
     None, 0),
    # UPI ID: handle@provider with no dot in provider (e.g. ramesh@okhdfcbank, 9820012345@ybl)
    ("UPI_ID",
     re.compile(r"\b[A-Za-z0-9._\-]{2,}@[A-Za-z]{2,}\b(?!\.)"),
     None, 0),
    ("GSTIN",
     re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b"),
     None, 0),
    ("PAN",
     re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
     None, 0),
    ("IFSC",
     re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
     None, 0),
    ("IP_ADDRESS",
     re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
     None, 0),
    # Card numbers: 13-19 digits, optional spaces/dashes, must pass Luhn
    ("CARD_NUMBER",
     re.compile(r"(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)"),
     lambda m: luhn_ok(_digits(m)) and 13 <= len(_digits(m)) <= 19, 0),
    # Aadhaar: 12 digits, first digit 2-9, often grouped 4-4-4, must pass Verhoeff
    ("AADHAAR",
     re.compile(r"(?<!\d)[2-9]\d{3}[ \-]?\d{4}[ \-]?\d{4}(?!\d)"),
     lambda m: verhoeff_ok(_digits(m)), 0),
    # Indian mobile: optional +91 / 91 / 0, then 10 digits starting 6-9
    ("PHONE",
     re.compile(r"(?<![\d+])(?:(?:\+|00)?91[ \-]?|0)?[6-9]\d{4}[ \-]?\d{5}(?!\d)"),
     None, 0),
    # International numbers written with a + country code
    ("PHONE",
     re.compile(r"(?<![\w+])\+\d{1,3}[ \-]?\(?\d{2,4}\)?(?:[ \-]?\d{2,4}){2,4}(?!\d)"),
     lambda m: 8 <= len(_digits(m)) <= 15, 0),
    # Bank account: 9-18 digits right after an account keyword
    ("BANK_ACCOUNT",
     re.compile(r"(?i)\b(?:a/?c|acc(?:oun)?t|acct|account\s*(?:no|number)|a/c\s*no)\b\.?\s*(?:no\.?|number|#)?\s*[:\-]?\s*(?P<acct>\d[\d ]{7,20}\d)"),
     lambda m: 9 <= len(_digits(m)) <= 18, "acct"),
]

# In --strict mode, any leftover run of 9+ digits is masked too.
STRICT_RULE = ("NUMBER", re.compile(r"(?<!\d)\d{9,}(?!\d)"), None, 0)

# WhatsApp export headers (Android and iOS styles).
_HEADER = re.compile(
    r"^(?P<head>\[?\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4},?\s+\d{1,2}:\d{2}(?::\d{2})?\s*(?:[AaPp]\.?\s?[Mm]\.?)?\]?\s*(?:-\s*)?)"
    r"(?P<sender>[^:]{1,60}?):\s(?P<body>.*)$"
)


@dataclass
class Result:
    text: str
    counts: Counter = field(default_factory=Counter)


def _label(name: str, style: str) -> str:
    return f"[{name.replace('_', ' ')}]" if style == "brackets" else "█" * 6


def redact_text(text: str, strict: bool = False, style: str = "brackets", counts: Counter | None = None) -> str:
    """Redact private details from a single piece of text (no header parsing)."""
    counts = counts if counts is not None else Counter()
    rules = RULES + ([STRICT_RULE] if strict else [])
    for name, rx, check, group in rules:
        def sub(m: re.Match) -> str:
            target = m.group(group) if group else m.group(0)
            if check and not check(target):
                return m.group(0)
            if "█" in target or (target.startswith("[") and target.endswith("]")):
                return m.group(0)
            counts[name] += 1
            if group:
                s, e = m.span(group)
                base = m.start(0)
                full = m.group(0)
                return full[: s - base] + _label(name, style) + full[e - base:]
            return _label(name, style)
        text = rx.sub(sub, text)
    return text


def redact_chat(chat: str, strict: bool = False, hide_names: bool = False, style: str = "brackets") -> Result:
    """Redact a full WhatsApp export. Timestamps stay; message bodies are cleaned.

    hide_names replaces each sender with "Person 1", "Person 2"... everywhere they appear.
    """
    counts: Counter = Counter()
    names: dict[str, str] = {}
    lines = chat.splitlines(keepends=True)

    if hide_names:
        for line in lines:
            m = _HEADER.match(line.rstrip("\r\n"))
            if m:
                sender = m.group("sender").strip()
                if sender not in names and not sender.startswith("+"):
                    names[sender] = f"Person {len(names) + 1}"
                elif sender not in names:
                    names[sender] = f"Person {len(names) + 1}"

    out = []
    for line in lines:
        ending = line[len(line.rstrip("\r\n")):]
        raw = line.rstrip("\r\n")
        m = _HEADER.match(raw)
        if m:
            head, sender, body = m.group("head"), m.group("sender"), m.group("body")
            body = redact_text(body, strict, style, counts)
            if hide_names:
                body = _swap_names(body, names, counts)
                sender = names.get(sender.strip(), sender)
            else:
                sender = redact_text(sender, strict, style, counts)
            out.append(f"{head}{sender}: {body}{ending}")
        else:
            body = redact_text(raw, strict, style, counts)
            if hide_names:
                body = _swap_names(body, names, counts)
            out.append(body + ending)
    return Result("".join(out), counts)


def _swap_names(text: str, names: dict[str, str], counts: Counter) -> str:
    for real in sorted(names, key=len, reverse=True):
        for variant in {real, real.split()[0]} if " " in real else {real}:
            if len(variant) < 3:
                continue
            pattern = re.compile(r"(?<!\w)@?" + re.escape(variant) + r"(?!\w)")
            text, n = pattern.subn(names[real], text)
            if n:
                counts["NAME"] += n
    return text


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="chat-redact",
        description="Remove private details (phones, emails, UPI, Aadhaar, PAN, bank, cards, passwords) from a WhatsApp chat export.",
    )
    p.add_argument("input", help="chat export .txt file, or - for stdin")
    p.add_argument("-o", "--output", help="write the clean chat here (default: print to screen)")
    p.add_argument("--hide-names", action="store_true", help="replace sender names with Person 1, Person 2, ...")
    p.add_argument("--strict", action="store_true", help="also mask any other long number (9+ digits)")
    p.add_argument("--blocks", action="store_true", help="use ███ blocks instead of [LABELS]")
    p.add_argument("-q", "--quiet", action="store_true", help="don't print the summary")
    p.add_argument("--version", action="version", version=f"chat-redact {__version__}")
    a = p.parse_args(argv)

    data = sys.stdin.read() if a.input == "-" else open(a.input, encoding="utf-8", errors="replace").read()
    res = redact_chat(data, strict=a.strict, hide_names=a.hide_names, style="blocks" if a.blocks else "brackets")

    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(res.text)
    else:
        sys.stdout.write(res.text)

    if not a.quiet:
        total = sum(res.counts.values())
        summary = ", ".join(f"{k.replace('_', ' ').lower()}: {v}" for k, v in res.counts.most_common()) or "nothing found"
        print(f"\nchat-redact: removed {total} item(s) ({summary})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
