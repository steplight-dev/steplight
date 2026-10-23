"""Fields whose contents Steplight never reads (the rules in ``spec/never-capture.json``).

The shared page script applies these rules inside the browser, before anything leaves the page; this module
is the same rule for Python code that needs to ask the question about a field it knows only by description.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from urllib.parse import urlsplit


def _js_regex(source: str, flags: str) -> re.Pattern[str]:
    """Compile a JavaScript regular expression of the simple kind used by the rules."""
    py_flags = re.ASCII | (re.IGNORECASE if "i" in flags else 0)
    # JavaScript `$` is the end of the input; Python's also matches before a trailing newline.
    return re.compile(source.replace("|$)", r"|\Z)"), py_flags)


@dataclass(frozen=True)
class _Rules:
    input_types: tuple[str, ...]
    autocomplete: re.Pattern[str]
    name: re.Pattern[str]
    camel_case: re.Pattern[str]
    editable_tags: tuple[str, ...]
    payment_hosts: tuple[str, ...]


@lru_cache(maxsize=1)
def _rules() -> _Rules:
    data = json.loads(resources.files("steplight").joinpath("_data/never-capture.json").read_text(encoding="utf-8"))
    return _Rules(
        input_types=tuple(data["inputTypes"]),
        autocomplete=_js_regex(data["autocompletePattern"]["source"], data["autocompletePattern"]["flags"]),
        name=_js_regex(data["namePattern"]["source"], data["namePattern"]["flags"]),
        camel_case=_js_regex(data["splitCamelCase"]["source"], ""),
        editable_tags=tuple(data["editableTags"]),
        payment_hosts=tuple(data["paymentFrameHosts"]),
    )


def is_never_capture_field(
    *,
    tag: str | None = None,
    type: str | None = None,
    name: str | None = None,
    id: str | None = None,
    autocomplete: str | None = None,
    aria_label: str | None = None,
    placeholder: str | None = None,
    label: str | None = None,
    content_editable: bool = False,
    in_payment_frame: bool = False,
) -> bool:
    """True when the field must never be read.

    Password inputs, payment / one-time-code ``autocomplete`` values, names that look like card / CVV / OTP /
    PIN / SSN / Aadhaar / PAN / password / token fields, and anything editable inside a payment frame.
    """
    rules = _rules()
    if in_payment_frame and (content_editable or (tag or "") in rules.editable_tags):
        return True
    if (type or "").lower() in rules.input_types:
        return True
    if autocomplete and rules.autocomplete.search(autocomplete):
        return True
    words = " ".join(rules.camel_case.sub(r"\1_\2", str(v)) for v in (name, id, aria_label, placeholder, label) if v)
    return bool(words) and rules.name.search(words) is not None


def is_payment_frame_url(url: str | None) -> bool:
    """Is this URL served by a known payment provider?"""
    if not url:
        return False
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return False
    return bool(host) and any(host == h or host.endswith(f".{h}") for h in _rules().payment_hosts)
