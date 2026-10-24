"""Secret and personal-data redaction (port of ``packages/core/src/redact.ts``).

Every pattern is a scanner that returns character ranges; overlapping ranges are merged (earliest start,
then the more specific kind) and replaced in one pass, so patterns cannot interfere with each other.
Linear time: email and card detection avoid backtracking regexes, every regex scanner is guarded by a
literal pre-check, and inputs are truncated before they are scanned.

The port must give exactly the output of the TypeScript engine on every case of
``spec/redaction-vectors.json``. Two JavaScript-isms are reproduced on purpose: lengths and cut points are in
UTF-16 code units (``String.length``), and ``\\s`` is JavaScript's whitespace set, not Python's.
"""

from __future__ import annotations

import base64
import binascii
import re
from bisect import bisect_left, bisect_right
from collections.abc import Callable
from dataclasses import dataclass
from itertools import accumulate
from typing import NamedTuple

from .checksums import iban_valid, verhoeff_valid
from .custom_patterns import compile_custom_patterns

MAX_BODY_PREVIEW = 2 * 1024
"""Maximum stored size of a request body preview, in UTF-16 code units."""
MAX_SNAPSHOT_TEXT = 200 * 1024
"""Maximum stored size of a snapshot, in UTF-16 code units."""

# JavaScript's \s: [\t\n\v\f\r    -     　﻿] (Python's differs at U+FEFF and others).
_WS = "\\t\\n\\v\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"
_A = re.ASCII
_AI = re.ASCII | re.IGNORECASE

# --------------------------------------------------------------------------- UTF-16 helpers

_ASTRAL = re.compile("[\U00010000-\U0010ffff]")


def utf16_length(text: str) -> int:
    """``String.length`` of the JavaScript string: astral characters count twice."""
    return len(text) + len(_ASTRAL.findall(text))


def _prefix_utf16(text: str, units: int) -> str:
    """The longest prefix that is at most ``units`` UTF-16 code units long (never splits a character)."""
    if units >= len(text) * 2 or not _ASTRAL.search(text):
        return text[:units]
    used = 0
    for index, ch in enumerate(text):
        used += 2 if ord(ch) > 0xFFFF else 1
        if used > units:
            return text[:index]
    return text


def truncate(text: str, max_units: int) -> str:
    """Cut to ``max_units`` UTF-16 code units, appending ``…[truncated]`` when something was cut."""
    if utf16_length(text) <= max_units:
        return text
    return f"{_prefix_utf16(text, max_units)}…[truncated]"


# --------------------------------------------------------------------------- decoding

_EMAIL_DOMAIN = re.compile(r"[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,5}\.[A-Za-z]{2,24}")
_PERCENT_RUN = re.compile(r"(?:%[0-9A-Fa-f]{2})+")
_JSON_U = re.compile(r"\\u([0-9a-fA-F]{4})")
_ENTITY = re.compile(r"&#([0-9]{2,5});|&#x([0-9a-fA-F]{2,4});")


def decode_percent(text: str) -> str:
    """Decode percent-escapes so form-encoded values (``a%40b.co``) are visible; invalid runs stay as they are."""
    if "%" not in text:
        return text

    def one(match: re.Match[str]) -> str:
        try:
            return bytes.fromhex(match.group(0).replace("%", "")).decode("utf-8")
        except UnicodeDecodeError:
            return match.group(0)

    return _PERCENT_RUN.sub(one, text)


def _join_surrogates(text: str) -> str:
    """Combine ``\\ud83d\\ude00``-style pairs the way a JavaScript string would; a lone half becomes U+FFFD."""
    if not any(0xD800 <= ord(c) <= 0xDFFF for c in text):
        return text
    return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace")


def _decode_all(text: str) -> str:
    """Percent-decode until nothing changes (defeats ``%2540``), then JSON ``\\uXXXX`` and HTML ``&#64;`` escapes."""
    for _ in range(3):
        nxt = decode_percent(text)
        if nxt == text:
            break
        text = nxt
    if "\\" in text:
        text = _JSON_U.sub(lambda m: chr(int(m.group(1), 16)), text).replace("\\/", "/")
        text = _join_surrogates(text)
    if "&#" in text:

        def entity(m: re.Match[str]) -> str:
            code = int(m.group(1)) if m.group(1) is not None else int(m.group(2), 16)
            return chr(code) if 0 < code < 0xD800 else m.group(0)

        text = _ENTITY.sub(entity, text)
    return text


# --------------------------------------------------------------------------- matchers


class _Range(NamedTuple):
    start: int
    end: int
    kind: str
    prio: int  # lower wins when ranges overlap


Push = Callable[[int, int, str, int], None]
Scanner = Callable[[str, Push], None]


def _is_local_char(code: int) -> bool:
    return (
        48 <= code <= 57 or 65 <= code <= 90 or 97 <= code <= 122 or code in (46, 95, 37, 43, 45)  # . _ % + -
    )


def find_emails(text: str) -> list[tuple[str, int]]:
    """Email addresses as ``(value, index)``. Anchored on ``@`` so cost is linear plus <= 64 characters of lookback per ``@``."""
    out: list[tuple[str, int]] = []
    pos = 0
    while True:
        at = text.find("@", pos)
        if at < 0:
            break
        pos = at + 1
        start = at
        while start > 0 and at - start < 64 and _is_local_char(ord(text[start - 1])):
            start -= 1
        if start == at:
            continue
        m = _EMAIL_DOMAIN.match(text, at + 1)
        if m is None:
            continue
        end = at + 1 + len(m.group(0))
        out.append((text[start:end], start))
        pos = end
    return out


def _has_any(text: str, needles: tuple[str, ...]) -> bool:
    return any(n in text for n in needles)


def _regex_scanner(
    pattern: re.Pattern[str],
    kind: str,
    prio: int,
    accept: Callable[[str, str, int], bool] | None = None,
    needles: tuple[str, ...] | None = None,
) -> Scanner:
    def scan(text: str, push: Push) -> None:
        if needles is not None and not _has_any(text, needles):
            return
        for m in pattern.finditer(text):
            if accept is not None and not accept(m.group(0), text, m.start()):
                continue
            push(m.start(), m.end(), kind, prio)

    return scan


def _private_keys(text: str, push: Push) -> None:
    """PEM private key blocks. An unterminated block redacts to the end of the text (fail closed)."""
    pos = 0
    while True:
        begin = text.find("-----BEGIN ", pos)
        if begin < 0:
            return
        header_end = text.find("-----", begin + 11)
        if header_end < 0 or "PRIVATE KEY" not in text[begin : header_end + 5]:
            pos = begin + 11
            continue
        end_marker = text.find("-----END ", header_end)
        if end_marker < 0:
            push(begin, len(text), "private_key", 0)
            return
        end_close = text.find("-----", end_marker + 9)
        end = len(text) if end_close < 0 else end_close + 5
        push(begin, end, "private_key", 0)
        pos = end


_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", _A)
_API_KEYS: tuple[tuple[re.Pattern[str], tuple[str, ...]], ...] = (
    (re.compile(r"\bsk-(?:proj-|ant-(?:api[0-9]{2}-)?)?[A-Za-z0-9_-]{16,200}\b", _A), ("sk-",)),
    (
        re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}", _A),
        ("AKIA", "ASIA", "AGPA", "AIDA", "AROA", "ANPA", "ANVA", "AIPA"),
    ),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,100}\b", _A), ("ghp_", "gho_", "ghu_", "ghs_", "ghr_")),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,120}\b", _A), ("github_pat_",)),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}", _A), ("xox",)),
    (re.compile(r"\bxapp-[0-9]-[A-Za-z0-9-]{10,}", _A), ("xapp-",)),
    (re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,100}\b", _A), ("k_live_", "k_test_")),
    (re.compile(r"\bwhsec_[A-Za-z0-9]{16,100}\b", _A), ("whsec_",)),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}", _A), ("AIza",)),
    (re.compile(r"\bnpm_[A-Za-z0-9]{36}", _A), ("npm_",)),
)
_BEARER = re.compile(rf"\b(?:bearer|basic)[{_WS}]+[A-Za-z0-9._~+/=-]{{16,}}", _AI)

_PASSWORD_PAIR = re.compile(
    r"(?<![A-Za-z0-9])(?:pass(?:word|wd|phrase)?|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token"
    r"|refresh[_-]?token|client[_-]?secret|private[_-]?key|credentials?)s?"
    rf"([\"']?[ \t]{{0,3}}[:=][ \t]{{0,3}}[\"']?)([^{_WS}\"'&;,<>\\]{{3,200}})",
    _AI,
)
_MARKER_VALUE = re.compile(r"\[REDACTED:[a-z_]+\][;,.)\]}]*\Z")


def _is_marker(value: str) -> bool:
    """A value that is one redaction marker (plus trailing punctuation) was redacted already: leave it."""
    return _MARKER_VALUE.match(value) is not None


def _password_pairs(text: str, push: Push) -> None:
    if ":" not in text and "=" not in text:
        return
    for m in _PASSWORD_PAIR.finditer(text):
        if _is_marker(m.group(2)):
            continue
        push(m.end() - len(m.group(2)), m.end(), "password", 4)


_URL_PARAM = re.compile(
    rf"(?:^|(?<=[?&;#{_WS}]))"
    r"(?:[a-z0-9_.-]*(?:token|secret|password|passwd|pwd|signature|credential|apikey|api[_-]key)"
    r"|key|code|session(?:id)?|sid|auth(?:orization)?|sig|otp|jwt)="
    rf"([^&{_WS}#\"'<>]{{1,500}})",
    _AI,
)


def _url_params(text: str, push: Push) -> None:
    if "=" not in text:
        return
    for m in _URL_PARAM.finditer(text):
        if _is_marker(m.group(1)):
            continue
        push(m.end() - len(m.group(1)), m.end(), "url_param", 5)


def _emails(text: str, push: Push) -> None:
    for value, index in find_emails(text):
        push(index, index + len(value), "email", 6)


_IBAN = re.compile(r"(?<![A-Z0-9])[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?(?![A-Z0-9])", _A)
_SSN = re.compile(r"(?<![0-9])(?!000|666|9[0-9][0-9])[0-9]{3}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}(?![0-9])", _A)
_DIGIT_RUN = re.compile(r"[0-9]+")


def _cards(text: str, push: Push) -> None:
    """Card numbers: digit groups joined by a single space or dash.

    Every run of 13-19 digits that starts and ends on a group boundary is Luhn-checked, so a card next to
    another number ("order 12345 4242 4242 4242 4242") is still found. Each window is checked in O(1) with
    prefix sums, so the scan stays linear even for a megabyte of "1 1 1 1 ...".
    """
    starts: list[int] = []
    ends: list[int] = []

    def flush() -> None:
        g = len(starts)
        if g and sum(ends[k] - starts[k] for k in range(g)) >= 13:
            _card_chain(text, starts, ends, push)
        starts.clear()
        ends.clear()

    for m in _DIGIT_RUN.finditer(text):
        i, j = m.start(), m.end()
        if ends and not (i - ends[-1] == 1 and text[ends[-1]] in (" ", "-")):
            flush()
        starts.append(i)
        ends.append(j)
    flush()


def _card_chain(text: str, starts: list[int], ends: list[int], push: Push) -> None:
    g = len(starts)
    digits = "".join(text[starts[k] : ends[k]] for k in range(g))
    offset = [0] * (g + 1)
    for k in range(g):
        offset[k + 1] = offset[k] + (ends[k] - starts[k])
    n = offset[g]
    vals = [c - 48 for c in digits.encode("ascii")]
    # t[c][i]: Luhn sum of digits [0, i) when the digits at index parity c are the undoubled ones.
    t: list[list[int]] = []
    for c in (0, 1):
        contrib = [v if idx % 2 == c else (v * 2 if v < 5 else v * 2 - 9) for idx, v in enumerate(vals)]
        t.append([0, *accumulate(contrib)])
    s = 0
    while s < g:
        frm = offset[s]
        if frm + 13 > n:
            break
        best = -1
        for e in range(bisect_left(offset, frm + 13, s + 1), bisect_right(offset, frm + 19, s + 1)):
            to = offset[e]
            tc = t[(to - 1) & 1]
            if (tc[to] - tc[frm]) % 10 == 0:
                best = e - 1  # group e - 1 ends at offset[e]
        if best >= 0:
            push(starts[s], ends[best], "card", 9)
            s = best  # continue after this card
        s += 1


_AADHAAR_GROUPED = re.compile(r"(?<![0-9])[2-9][0-9]{3}[ -][0-9]{4}[ -][0-9]{4}(?![0-9])", _A)
_AADHAAR_PLAIN = re.compile(r"(?<![0-9])[2-9][0-9]{11}(?![0-9])", _A)
_PAN = re.compile(r"(?<![A-Z0-9])[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z](?![A-Z0-9])", _A)
_AADHAAR_WORD = re.compile(r"aadh?a{1,2}r|uidai|\buid\b", _AI)


def _aadhaar_context(text: str, index: int) -> bool:
    return _AADHAAR_WORD.search(text[max(0, index - 40) : index]) is not None


_PHONE_CANDIDATE = re.compile(r"(?<![0-9@.])\+?\(?[0-9][0-9 ()\-.]{6,20}[0-9](?![0-9@])", _A)
_NANP = re.compile(r"\(?[2-9][0-9]{2}\)?[ .-][0-9]{3}[ .-][0-9]{4}", _A)
_INDIAN_MOBILE = re.compile(r"[6-9][0-9]{9}", _A)
_PHONE_TOKEN = re.compile(r"[+(]?[0-9][0-9)]*(?:[.-][0-9]+)*", _A)


_DROP_PUNCTUATION = str.maketrans("", "", "+() -.")


def _is_phone(candidate: str) -> bool:
    digits = candidate.translate(_DROP_PUNCTUATION)  # candidates hold only digits and "+() -."
    n = len(digits)
    if candidate.startswith("+"):
        return 8 <= n <= 15
    if n not in (10, 11, 12):  # Indian mobiles and North-American numbers have 10 digits (plus 0 / 91)
        return False
    if n == 12 and digits.startswith("91"):
        rest = digits[2:]
    elif n == 11 and digits.startswith("0"):
        rest = digits[1:]
    elif n == 10:
        rest = digits
    else:
        return False
    return _INDIAN_MOBILE.fullmatch(rest) is not None or _NANP.fullmatch(candidate) is not None


def _phones(text: str, push: Push) -> None:
    for m in _PHONE_CANDIDATE.finditer(text):
        base = m.start()
        candidate = m.group(0)
        if _is_phone(candidate):
            push(base, base + len(candidate), "phone", 14)
            continue
        tokens = [(t.start(), t.end()) for t in _PHONE_TOKEN.finditer(candidate)]
        if len(tokens) < 2 or len(tokens) > 8:
            continue
        found = False
        for frm in range(len(tokens)):
            if found:
                break
            for to in range(len(tokens) - 1, frm - 1, -1):
                if frm == 0 and to == len(tokens) - 1:
                    continue
                if _is_phone(candidate[tokens[frm][0] : tokens[to][1]]):
                    push(base + tokens[frm][0], base + tokens[to][1], "phone", 14)
                    found = True
                    break


_MARKER = re.compile(
    r"\[REDACTED:(email|card|api_key|jwt|private_key|bearer|iban|ssn|aadhaar|pan|encoded|password|url_param)\]"
)


def _markers(credentials: bool) -> Scanner:
    def scan(text: str, push: Push) -> None:
        for m in _MARKER.finditer(text):
            kind = m.group(1)
            if not credentials and kind in ("password", "url_param"):
                continue
            push(m.start(), m.end(), kind, 1)

    return scan


_BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/_=-])", _A)
_ALPHA_ONLY = re.compile(r"[A-Za-z]+")
MAX_ENCODED_TOKENS = 300
MAX_ENCODED_CHARS = 4096


def _decode_base64_text(token: str) -> str | None:
    """Decode a base64 / base64url token to text, or None when it is not mostly printable."""
    b64 = token[:MAX_ENCODED_CHARS].rstrip("=").replace("-", "+").replace("_", "/")
    if len(b64) % 4 == 1:
        b64 = b64[:-1]
    b64 += "=" * ((4 - len(b64) % 4) % 4)
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    printable = sum(1 for c in raw if 32 <= c < 127 or c in (9, 10, 13))
    if len(raw) > 0 and printable / len(raw) >= 0.9:
        return raw.decode("latin-1")
    return None


def _encoded_segments(inner: Callable[[str], bool]) -> Scanner:
    def scan(text: str, push: Push) -> None:
        count = 0
        for m in _BASE64_TOKEN.finditer(text):
            count += 1
            if count > MAX_ENCODED_TOKENS:
                return
            token = m.group(0)
            if _ALPHA_ONLY.fullmatch(token) and len(token) < 40:
                continue  # an ordinary long word
            decoded = _decode_base64_text(token)
            if decoded is not None and inner(decoded):
                push(m.start(), m.end(), "encoded", 2)

    return scan


# --------------------------------------------------------------------------- custom patterns

_custom_regexes: list[re.Pattern[str]] = []


def configure_redaction(custom_patterns: list[str] | tuple[str, ...] | None = None) -> None:
    """Set the user's extra redaction patterns (validated; a bad one is skipped). An empty list clears them."""
    global _custom_regexes
    _custom_regexes = compile_custom_patterns(list(custom_patterns or []))


def _custom_scanner(text: str, push: Push) -> None:
    for regex in _custom_regexes:
        for m in regex.finditer(text):
            if m.end() > m.start():
                push(m.start(), m.end(), "custom", 15)


# --------------------------------------------------------------------------- scanning


@dataclass(frozen=True)
class _ScanOptions:
    credentials: bool
    extended: bool
    markers: bool


def _base_scanners(o: _ScanOptions) -> list[Scanner]:
    scanners: list[Scanner] = [
        _private_keys,
        _regex_scanner(_JWT, "jwt", 3, None, ("eyJ",)),
        *(_regex_scanner(pattern, "api_key", 3, None, needles) for pattern, needles in _API_KEYS),
        _regex_scanner(_BEARER, "bearer", 3, None, ("earer", "EARER", "asic", "ASIC")),
        _emails,
        _regex_scanner(_IBAN, "iban", 7, lambda v, _t, _i: iban_valid(v)),
        _regex_scanner(_SSN, "ssn", 8, None, ("-",)),
        _cards,
        _regex_scanner(_AADHAAR_GROUPED, "aadhaar", 10, lambda v, _t, _i: verhoeff_valid(v), (" ", "-")),
        _regex_scanner(_AADHAAR_PLAIN, "aadhaar", 10, lambda v, t, i: verhoeff_valid(v) and _aadhaar_context(t, i)),
        _regex_scanner(_PAN, "pan", 11),
    ]
    if o.credentials:
        scanners += [_password_pairs, _url_params]
    if o.extended:
        scanners.append(_phones)
    return scanners


def _collect(text: str, o: _ScanOptions, nested: bool = False) -> list[_Range]:
    found: list[_Range] = []

    def push(start: int, end: int, kind: str, prio: int) -> None:
        if end > start:
            found.append(_Range(start, end, kind, prio))

    for scanner in _base_scanners(o):
        scanner(text, push)
    if o.markers:
        _markers(o.credentials)(text, push)
    if o.extended:
        _custom_scanner(text, push)
    if not nested and len(text) >= 24:
        # Obfuscated copies: base64 that decodes to something sensitive.
        inner_options = _ScanOptions(o.credentials, o.extended, False)
        _encoded_segments(lambda decoded: len(_collect(decoded, inner_options, True)) > 0)(text, push)
    # Overlaps: earlier start wins, then the more specific (lower prio) kind, then the longer range.
    found.sort(key=lambda r: (r.start, r.prio, -r.end))
    out: list[_Range] = []
    last_end = 0
    for r in found:
        if r.start < last_end:
            continue
        out.append(r)
        last_end = r.end
    return out


@dataclass(frozen=True)
class SensitiveMatch:
    """A sensitive value found in text (do not persist ``value`` unredacted)."""

    kind: str
    value: str
    index: int


def find_sensitive(text: str, *, credentials: bool = False) -> list[SensitiveMatch]:
    """What detectors react to: emails, Luhn-valid cards, API keys, JWTs, private keys, bearer credentials, IBANs, SSNs, Aadhaar, PAN, encoded copies and markers."""
    decoded = _decode_all(text)
    return [
        SensitiveMatch(r.kind, decoded[r.start : r.end], r.start)
        for r in _collect(decoded, _ScanOptions(credentials, False, True))
    ]


def redact_text(text: str) -> str:
    """Replace every sensitive value with ``[REDACTED:<kind>]``.

    Text without findings is returned unchanged; otherwise escapes are decoded in the result. Applying it
    twice gives the same result. Fails closed: if redaction itself breaks, ``[REDACTED:error]`` is returned
    and the data is dropped rather than kept raw.
    """
    try:
        decoded = _decode_all(text)
        ranges = _collect(decoded, _ScanOptions(True, True, False))
        if not ranges:
            return text
        out: list[str] = []
        pos = 0
        for r in ranges:
            out.append(decoded[pos : r.start])
            out.append(f"[REDACTED:{r.kind}]")
            pos = r.end
        out.append(decoded[pos:])
        return "".join(out)
    except Exception:  # fail closed, whatever went wrong
        return "[REDACTED:error]"


def sanitize_body(body: str) -> str:
    """Truncate then redact a request body preview to :data:`MAX_BODY_PREVIEW`."""
    return redact_text(truncate(body, MAX_BODY_PREVIEW))


def sanitize_snapshot(text: str) -> str:
    """Truncate then redact snapshot text to :data:`MAX_SNAPSHOT_TEXT` (truncating first bounds the regex work)."""
    return redact_text(truncate(text, MAX_SNAPSHOT_TEXT))
