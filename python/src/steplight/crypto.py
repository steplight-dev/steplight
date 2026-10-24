"""Encryption at rest for run files, byte-compatible with the TypeScript SDK (``storage/fileCrypto.ts``).

AES-256-GCM per file: ``run.json`` and snapshots as one envelope each, ``steps.jsonl`` and
``analysis-input.jsonl`` as one envelope per line (so they stay append-only). Every envelope has its own random
12-byte IV, and the file's identity (``<runId>/<file>``) is bound in as additional authenticated data, so a file
moved to another run or renamed fails to decrypt. An envelope is the one-line compact JSON
``{"steplight":"enc-v1","iv":...,"tag":...,"ct":...}`` (base64), exactly as the Node CLI writes and reads it.

Keys: a 32-byte ``key`` (64 hex characters or base64), or a ``passphrase`` stretched with scrypt (N=32768, r=8,
p=1, 16-byte random salt kept in ``<runs>/.steplight-enc.json`` next to an encrypted check value, so a wrong
passphrase is reported clearly). ``$STEPLIGHT_ENCRYPTION_KEY`` / ``$STEPLIGHT_PASSPHRASE`` are used when nothing
is given. AES-GCM needs the ``cryptography`` package (``pip install steplight[crypto]``).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ENC_MARKER = '{"steplight":"enc-v1"'
SALT_FILE = ".steplight-enc.json"
_SCRYPT = {"N": 32768, "r": 8, "p": 1}
_HEX64 = re.compile(r"[0-9a-fA-F]{64}")


class EncryptedRunError(Exception):
    """A run is encrypted and no (or the wrong) key is available, or the data was changed."""

    def __init__(
        self, message: str = "This run is encrypted. Set STEPLIGHT_ENCRYPTION_KEY (or STEPLIGHT_PASSPHRASE) to read it."
    ) -> None:
        super().__init__(message)


@dataclass(frozen=True)
class EncryptionOptions:
    """Where the key comes from: an explicit ``key`` (bytes, hex or base64) or a ``passphrase``."""

    key: bytes | str | None = None
    passphrase: str | None = None


def is_encrypted_text(text: str) -> bool:
    """True when the text is one of our encrypted envelopes."""
    return text.startswith(ENC_MARKER)


def parse_key(value: bytes | str) -> bytes:
    """A 32-byte key from bytes, 64 hex characters or base64."""
    if isinstance(value, bytes):
        key = value
    else:
        text = value.strip()
        key = bytes.fromhex(text) if _HEX64.fullmatch(text) else base64.b64decode(text, validate=True)
    if len(key) != 32:
        raise ValueError("The encryption key must be 32 bytes (64 hex characters or base64).")
    return key


def effective_encryption(
    options: EncryptionOptions | None = None, env: Mapping[str, str | None] | None = None
) -> EncryptionOptions | None:
    """Explicit options, else the environment; None when no key source is set."""
    if options is not None and (options.key is not None or options.passphrase is not None):
        return options
    environ: Mapping[str, str | None] = env if env is not None else os.environ
    if environ.get("STEPLIGHT_ENCRYPTION_KEY"):
        return EncryptionOptions(key=environ["STEPLIGHT_ENCRYPTION_KEY"])
    if environ.get("STEPLIGHT_PASSPHRASE"):
        return EncryptionOptions(passphrase=environ["STEPLIGHT_PASSPHRASE"])
    return None


def _aesgcm(key: bytes) -> Any:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as err:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(
            "Encryption at rest needs the 'cryptography' package: pip install 'steplight[crypto]'"
        ) from err
    return AESGCM(key)


def encrypt_file(plain: str, key: bytes, aad: str) -> str:
    """Encrypt text into a one-line JSON envelope."""
    iv = secrets.token_bytes(12)
    sealed = _aesgcm(key).encrypt(iv, plain.encode("utf-8"), aad.encode("utf-8"))
    ct, tag = sealed[:-16], sealed[-16:]
    envelope = {
        "steplight": "enc-v1",
        "iv": base64.b64encode(iv).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }
    return json.dumps(envelope, separators=(",", ":"))


def decrypt_file(text: str, key: bytes | None, aad: str) -> str:
    """Decrypt an envelope. Plain (unencrypted) text is returned as it is."""
    if not is_encrypted_text(text):
        return text
    if key is None:
        raise EncryptedRunError()
    try:
        env = json.loads(text)
        iv = base64.b64decode(env["iv"], validate=True)
        sealed = base64.b64decode(env["ct"], validate=True) + base64.b64decode(env["tag"], validate=True)
        plain: str = _aesgcm(key).decrypt(iv, sealed, aad.encode("utf-8")).decode("utf-8")
        return plain
    except RuntimeError:
        raise
    except Exception as err:
        raise EncryptedRunError("Could not decrypt: wrong key, or the file was modified.") from err


_derived: dict[tuple[str, str], bytes] = {}


def _scrypt(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=128 * 1024 * 1024, dklen=32)


def resolve_key(
    root: str | os.PathLike[str], options: EncryptionOptions | None = None, create: bool = False
) -> bytes | None:
    """The 32-byte key for a runs folder, or None when no key source is set.

    A passphrase creates the salt file on first use when ``create`` is true.
    """
    eff = effective_encryption(options)
    if eff is None:
        return None
    if eff.key is not None:
        return parse_key(eff.key)
    passphrase = eff.passphrase or ""
    cache_key = (str(Path(root).resolve()), passphrase)
    hit = _derived.get(cache_key)
    if hit is not None:
        return hit
    file = Path(root) / SALT_FILE
    meta: dict[str, Any] | None
    try:
        meta = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        meta = None
    if meta is None:
        if not create:
            raise EncryptedRunError(
                "No passphrase salt found for this folder, so nothing here was encrypted with a passphrase."
            )
        salt = secrets.token_bytes(16)
        key = _scrypt(passphrase, salt, **{k.lower(): v for k, v in _SCRYPT.items()})
        meta = {
            "v": 1,
            "kdf": "scrypt",
            **_SCRYPT,
            "salt": base64.b64encode(salt).decode("ascii"),
            "check": encrypt_file("steplight-ok", key, "check"),
        }
        file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_private(file, json.dumps(meta, separators=(",", ":")))
        _derived[cache_key] = key
        return key
    key = _scrypt(passphrase, base64.b64decode(meta["salt"]), int(meta["N"]), int(meta["r"]), int(meta["p"]))
    try:
        if decrypt_file(meta["check"], key, "check") != "steplight-ok":
            raise ValueError("mismatch")
    except Exception as err:
        raise EncryptedRunError("Wrong passphrase for this folder.") from err
    _derived[cache_key] = key
    return key


def write_private(file: str | os.PathLike[str], data: str) -> None:
    """Write a file readable only by its owner: mode 0600 on POSIX. On Windows the mode bits have no effect and the file inherits the folder's ACL."""
    path = os.fspath(file)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
        handle.write(data)
    if os.name != "nt":
        os.chmod(path, 0o600)
