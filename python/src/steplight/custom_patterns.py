"""Validation of user-supplied redaction patterns (port of ``customPatterns.ts``).

A pattern is rejected before it is ever used on page data when it is invalid, over 200 characters, matches
the empty string, has a classically catastrophic shape (nested or ambiguous repetition), or is slow on
adversarial input of growing size. This is a safety net, not a proof.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

MAX_PATTERN_LENGTH = 200
# The same escalation as the TypeScript engine, with limits ~4x looser because CPython's regex engine is
# slower than V8's irregexp: a linear pattern must not be rejected just because the interpreter is slow.
SLOW_MS = 120.0
GROWING_MS = 20.0
SIZES = (8, 12, 16, 20, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512)
MAX_PATTERNS = 50

_BOUNDED_REPEAT = re.compile(r"\{\d+,\d*\}")
_NAMED_GROUP = re.compile(r"\(\?<([A-Za-z_])")
_PLAIN_FIRST = re.compile(r"[A-Za-z0-9_-]")
_BROAD = re.compile(r"\\[wds]", re.IGNORECASE)


@dataclass(frozen=True)
class PatternCheck:
    """Result of :func:`validate_pattern`."""

    ok: bool
    regex: re.Pattern[str] | None = None
    reason: str = ""


def _is_repeat(ch: str) -> bool:
    return ch in ("+", "*")


def has_catastrophic_shape(source: str) -> bool:
    """Structural check for nested or ambiguous repetition such as ``(a+)+``, ``(a|aa)*`` or ``.*.*``."""
    stack: list[dict[str, object]] = []
    in_class = False
    previous_atom = ""
    last_was_repeat = False

    def repeat_after(i: int) -> bool:
        if i >= len(source):
            return False
        return _is_repeat(source[i]) or (source[i] == "{" and _BOUNDED_REPEAT.match(source, i) is not None)

    i = 0
    while i < len(source):
        ch = source[i]
        atom = ""
        if ch == "\\":
            atom = source[i : i + 2]
            i += 1
        elif in_class:
            if ch == "]":
                in_class = False
            i += 1
            continue
        elif ch == "[":
            close = source.find("]", i + 2)
            atom = "[" if close < 0 else source[i : close + 1]
            in_class = False
            if close >= 0:
                i = close
        elif ch == "(":
            stack.append({"repeats": False, "alts": [], "current": ""})
            if i + 1 < len(source) and source[i + 1] == "?":
                i += 1
                while i + 1 < len(source) and source[i + 1] in ":=!<":
                    i += 1
            last_was_repeat = False
            i += 1
            continue
        elif ch == "|":
            if stack:
                g = stack[-1]
                alts = g["alts"]
                assert isinstance(alts, list)
                alts.append(g["current"])
                g["current"] = ""
            last_was_repeat = False
            i += 1
            continue
        elif ch == ")":
            g_closed = stack.pop() if stack else None
            repeated = repeat_after(i + 1)
            if g_closed is not None:
                alts = g_closed["alts"]
                assert isinstance(alts, list)
                alts.append(g_closed["current"])
                if g_closed["repeats"] and repeated:
                    return True
                if repeated and len(alts) > 1:
                    firsts = [str(a)[:1] for a in alts]
                    plain = all(f != "" and _PLAIN_FIRST.match(f) for f in firsts)
                    if not plain or len(set(firsts)) != len(firsts):
                        return True
                if g_closed["repeats"] and stack:
                    stack[-1]["repeats"] = True
            last_was_repeat = repeated
            i += 1
            continue
        elif _is_repeat(ch) or ch == "?" or (ch == "{" and _BOUNDED_REPEAT.match(source, i) is not None):
            if ch != "?" and stack:
                stack[-1]["repeats"] = True
            i += 1
            continue
        elif ch in ("^", "$"):
            i += 1
            continue
        else:
            atom = ch
        if stack:
            stack[-1]["current"] = str(stack[-1]["current"]) + atom
        repeated = repeat_after(i + 1)
        if repeated:
            broad = atom == "." or _BROAD.match(atom) is not None or atom.startswith("[")
            prev_broad = (
                previous_atom == "." or _BROAD.match(previous_atom) is not None or previous_atom.startswith("[")
            )
            if last_was_repeat and (atom == previous_atom or (broad and prev_broad)):
                return True
            previous_atom = atom
        last_was_repeat = repeated
        i += 1
    return False


def _probes(n: int) -> list[str]:
    return [
        "a" * n + "!",
        "1" * n + "x",
        "ab" * -(-n // 2) + "c",
        " " * n + "x",
        "a@" * -(-n // 2) + "!",
        "x" * (n * 2),
        "-" * n + "\n",
        "a1 " * -(-n // 3) + "!",
    ]


def _compile(source: str) -> re.Pattern[str]:
    # JavaScript named groups (?<name>...) are written (?P<name>...) in Python.
    return re.compile(_NAMED_GROUP.sub(r"(?P<\1", source), re.IGNORECASE | re.ASCII)


def _time(regex: re.Pattern[str], probe: str) -> float:
    start = time.perf_counter()
    regex.search(probe)
    return (time.perf_counter() - start) * 1000.0


def validate_pattern(source: object) -> PatternCheck:
    """Validate a user-supplied redaction pattern (case-insensitive, global) before use on page data."""
    if not isinstance(source, str) or source == "":
        return PatternCheck(False, reason="Pattern is empty.")
    if len(source) > MAX_PATTERN_LENGTH:
        return PatternCheck(False, reason=f"Pattern is longer than {MAX_PATTERN_LENGTH} characters.")
    try:
        regex = _compile(source)
    except (re.error, RecursionError, OverflowError) as err:
        return PatternCheck(False, reason=f"Not a valid regular expression ({err}).")
    if regex.search(""):
        return PatternCheck(False, reason="Pattern matches empty text, which would redact everything.")
    if has_catastrophic_shape(source):
        return PatternCheck(
            False,
            reason="Nested or ambiguous repetition such as (a+)+ or (a|aa)* can hang the program. Simplify the pattern.",
        )
    for n in SIZES:
        slowest = 0.0
        for probe in _probes(n):
            best = min(_time(regex, probe), _time(regex, probe))
            slowest = max(slowest, best)
            if slowest > SLOW_MS:
                return PatternCheck(
                    False, reason="Pattern is too slow on adversarial input (possible catastrophic backtracking)."
                )
        if slowest > GROWING_MS:
            return PatternCheck(
                False, reason="Pattern gets slower very quickly as input grows (possible catastrophic backtracking)."
            )
    return PatternCheck(True, regex=regex)


def compile_custom_patterns(sources: list[str] | tuple[str, ...]) -> list[re.Pattern[str]]:
    """Compile the valid patterns of a list; invalid ones are skipped silently."""
    out: list[re.Pattern[str]] = []
    for source in list(sources)[:MAX_PATTERNS]:
        check = validate_pattern(source)
        if check.ok and check.regex is not None:
            out.append(check.regex)
    return out
