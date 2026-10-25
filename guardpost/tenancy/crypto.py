"""Hashing and key derivation for tenancy.

- API keys are stored as SHA-256 of the full key string and compared in
  constant time. The secret part has 256 bits of entropy, so an unsalted hash
  is enough (nothing to brute-force).
- Per-tenant pseudonymous identifiers are HMACs under a tenant key derived
  from the instance secret: ``tk = HKDF-SHA256(GUARDPOST_SECRET, tenant)``.
  The same IP therefore hashes differently in every tenant, and nothing on
  disk links a tenant to a plaintext address.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

INSTANCE_SECRET_META_KEY = "instance_secret"
SECRET_ENV = "GUARDPOST_SECRET"


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def generate_secret(nbytes: int = 32) -> str:
    """A URL-safe random secret (``nbytes`` of entropy)."""
    return secrets.token_urlsafe(nbytes)


def hkdf_sha256(ikm: bytes, *, salt: bytes = b"", info: bytes = b"", length: int = 32) -> bytes:
    """HKDF (RFC 5869) with SHA-256."""
    if length > 255 * 32:
        raise ValueError("HKDF length too large")
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def tenant_key(instance_secret: str | bytes, tenant_id: str, key_version: int = 1) -> bytes:
    """The tenant's HMAC key. ``key_version`` lets a tenant's keys be rotated."""
    ikm = instance_secret.encode("utf-8") if isinstance(instance_secret, str) else instance_secret
    info = f"guardpost/tenant/{tenant_id}/v{key_version}".encode()
    return hkdf_sha256(ikm, salt=b"guardpost-tenant-key", info=info)


def keyed_hash(key: bytes, value: str, *, purpose: str) -> str:
    """HMAC-SHA256 of ``value`` under ``key``, domain-separated by ``purpose``."""
    return hmac.new(key, f"{purpose}\x00{value}".encode(), hashlib.sha256).hexdigest()
