"""Checksums used to tell real card, Aadhaar and IBAN numbers from look-alikes (port of ``checksums.ts``)."""

from __future__ import annotations

import re

_LUHN_DIGITS = re.compile(r"[0-9]{13,19}")
_VERHOEFF_DIGITS = re.compile(r"[0-9]{2,}")
_IBAN_SHAPE = re.compile(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}")

_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def luhn_valid(value: str) -> bool:
    """Luhn checksum of a card-like digit string (spaces and dashes ignored)."""
    digits = value.replace(" ", "").replace("-", "")
    if not _LUHN_DIGITS.fullmatch(digits):
        return False
    total = 0
    double = False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if double:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        double = not double
    return total % 10 == 0


def verhoeff_valid(value: str) -> bool:
    """Verhoeff checksum (Indian Aadhaar numbers); spaces and dashes are ignored."""
    digits = value.replace(" ", "").replace("-", "")
    if not _VERHOEFF_DIGITS.fullmatch(digits):
        return False
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][ord(ch) - 48]]
    return c == 0


def iban_valid(value: str) -> bool:
    """IBAN mod-97 check (ISO 13616); spaces are ignored."""
    iban = value.replace(" ", "").upper()
    if not _IBAN_SHAPE.fullmatch(iban):
        return False
    rearranged = iban[4:] + iban[:4]
    remainder = 0
    for ch in rearranged:
        number = str(ord(ch) - 55) if ch >= "A" else ch
        for digit in number:
            remainder = (remainder * 10 + ord(digit) - 48) % 97
    return remainder == 1
