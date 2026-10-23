"""Registrable domain ("site") of a URL (port of ``domain.ts``)."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

_MULTI_PART_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "org.in", "co.jp", "co.nz",
        "com.au", "net.au", "org.au", "com.br", "com.cn", "com.mx", "com.sg", "co.za", "com.tr",
    }
)  # fmt: skip
_IPV4 = re.compile(r"[0-9]{1,3}(\.[0-9]{1,3}){3}")
_DEFAULT_PORTS = {"http": 80, "https": 443}


def host_and_port(url: str) -> tuple[str, str, str] | None:
    """``(scheme, hostname, port)`` of a URL as a browser's ``URL`` reports them (default ports are empty), or None."""
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if not scheme:
            return None
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return None
    shown = "" if port is None or _DEFAULT_PORTS.get(scheme) == port else str(port)
    return scheme, host, shown


def registrable_domain(url: str | None) -> str | None:
    """``https://a.b.example.com/x`` -> ``example.com``. Local hosts and IPs keep their port; non-http(s) gives None."""
    if not url:
        return None
    hp = host_and_port(url)
    if hp is None or hp[0] not in ("http", "https"):
        return None
    _, host, port = hp
    if host == "localhost" or _IPV4.fullmatch(host) or ":" in host:
        return f"{host}:{port}" if port else host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    return ".".join(labels[-3:]) if last_two in _MULTI_PART_SUFFIXES else last_two


def site_of(url: str | None) -> str | None:
    """Like :func:`registrable_domain`, treating ``ws://`` and ``wss://`` as ``http://`` and ``https://``."""
    if url is None:
        return None
    return registrable_domain(re.sub(r"^ws(s?):", r"http\1:", url, flags=re.IGNORECASE))


def is_cross_site(from_url: str | None, to_url: str | None) -> bool:
    """True when both URLs resolve to known, different registrable domains."""
    a = registrable_domain(from_url)
    b = registrable_domain(to_url)
    return a is not None and b is not None and a != b


def strip_query(url: str) -> str:
    """URL without query string and fragment (the ``minimal`` capture level)."""
    hp = host_and_port(url)
    if hp is None:
        return re.split(r"[?#]", url, maxsplit=1)[0]
    try:
        path = urlsplit(url).path
    except ValueError:
        return re.split(r"[?#]", url, maxsplit=1)[0]
    scheme, host, port = hp
    shown_host = f"[{host}]" if ":" in host else host
    return f"{scheme}://{shown_host}{':' + port if port else ''}{path}"
