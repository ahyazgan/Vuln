"""Application-layer encryption for data at rest (CLAUDE.md §7.4 — LOCKED).

§7.4 requires scan *results* and sensitive scan metadata to be encrypted at
rest. The free-text content of a finding — its title, description, proof of
concept, recommendation, and references — is what reveals the vulnerability and
how to exploit it, so those columns are stored as ciphertext. Structural
classification fields (``severity``, ``cvss_score``, ``is_chained``,
``chain_parent_ids``) stay in plaintext because the API sorts/aggregates on them
(e.g. ``ORDER BY severity``); they carry no exploit detail.

Encryption is transparent: SQLAlchemy :class:`TypeDecorator` columns encrypt on
write and decrypt on read, so models, queries, and API schemas are unchanged.

Keys live in the environment and are never persisted (§7.3). ``VULNSCAN_ENCRYPTION_KEY``
holds one or more comma-separated Fernet keys; the **first** encrypts, and all of
them can decrypt — so a key can be rotated by prepending a new one and keeping the
old until rows are re-encrypted. A clearly-insecure dev fallback is used only when
the variable is unset (it MUST be overridden in production).
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Any

from cryptography.fernet import Fernet, MultiFernet
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator

# Dev-only fallback (a valid Fernet key). NEVER use this in production — set
# VULNSCAN_ENCRYPTION_KEY to one or more real keys (Fernet.generate_key()).
_DEV_FALLBACK_KEY = "ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg="


class Encryptor:
    """Symmetric encrypt/decrypt over a key ring (MultiFernet)."""

    def __init__(self, keys: list[str]) -> None:
        if not keys:
            raise ValueError("at least one encryption key is required")
        # First key encrypts; every key can decrypt (supports rotation).
        self._fernet = MultiFernet([Fernet(k.encode()) for k in keys])

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str:
        return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")


def _load_keys() -> list[str]:
    raw = os.getenv("VULNSCAN_ENCRYPTION_KEY", "").strip()
    if not raw:
        return [_DEV_FALLBACK_KEY]
    return [k.strip() for k in raw.split(",") if k.strip()]


@lru_cache(maxsize=1)
def get_encryptor() -> Encryptor:
    """Process-wide encryptor, built lazily from the environment (cached)."""
    return Encryptor(_load_keys())


class EncryptedString(TypeDecorator):
    """A ``str`` column encrypted at rest; stored as ciphertext ``Text``."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect: Any) -> str | None:
        if value is None:
            return None
        return get_encryptor().encrypt(value)

    def process_result_value(self, value: str | None, dialect: Any) -> str | None:
        if value is None:
            return None
        return get_encryptor().decrypt(value)


class EncryptedJSON(TypeDecorator):
    """A JSON-serializable column encrypted at rest; stored as ciphertext ``Text``."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Any) -> str | None:
        if value is None:
            return None
        return get_encryptor().encrypt(json.dumps(value, default=str))

    def process_result_value(self, value: str | None, dialect: Any) -> Any:
        if value is None:
            return None
        return json.loads(get_encryptor().decrypt(value))


__all__ = [
    "Encryptor",
    "get_encryptor",
    "EncryptedString",
    "EncryptedJSON",
]
