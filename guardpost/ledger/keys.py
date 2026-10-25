"""Per-tenant keyed hashes and the sealed IP of a pending check.

Every value the ledger stores about a person is ``HMAC(tk, purpose, value)``
with ``tk = HKDF(GUARDPOST_SECRET, tenant)`` (:func:`guardpost.tenancy.crypto.tenant_key`).
The email's inner value is Factory v2's ``normalized_email_hash``
(sha256 of the alias-normalized address), so an app can send either the
address or that hash and land on the same key.
"""

from __future__ import annotations

import hashlib
import hmac

from guardpost.email.validator import normalize_email
from guardpost.tenancy.crypto import keyed_hash, tenant_key

_TAG_BYTES = 16


def normalized_email_sha256(email: str) -> str:
    """Factory v2 ``normalizedEmailHash``: sha256 hex of the normalized address."""
    return hashlib.sha256(normalize_email(email).encode("utf-8")).hexdigest()


def secret_fingerprint(secret: str) -> str:
    """Identifies the secret keyed data was written with (stored in gp_meta), revealing nothing."""
    return keyed_hash(hashlib.sha256(secret.encode("utf-8")).digest(), "guardpost", purpose="fingerprint")[:32]


class TenantHasher:
    """Keyed hashes under one tenant's key."""

    def __init__(self, secret: str, tenant_id: str, key_version: int = 1) -> None:
        self._key = tenant_key(secret, tenant_id, key_version)
        self._enc = hmac.new(self._key, b"seal-enc", hashlib.sha256).digest()
        self._mac = hmac.new(self._key, b"seal-tag", hashlib.sha256).digest()

    def _h(self, value: str, purpose: str) -> str:
        return keyed_hash(self._key, value, purpose=purpose)

    def email(self, normalized_sha256: str) -> str:
        return self._h(normalized_sha256.lower(), "email")

    def fingerprint(self, fingerprint: str) -> str:
        return self._h(fingerprint.lower(), "fp")

    def ip(self, canonical_ip: str) -> str:
        return self._h(canonical_ip, "ip")

    def net(self, network_key: str) -> str:
        return self._h(network_key, "net")

    def name(self, name_key: str) -> str:
        return self._h(name_key, "name")

    def override(self, kind: str, target: str) -> str:
        return self._h(target, f"override-{kind}")

    def request(self, canonical: str) -> str:
        return self._h(canonical, "request")

    # -- sealing (HMAC-SHA256 in counter mode + an HMAC tag; nonce = check id) --

    def _stream(self, nonce: str, length: int) -> bytes:
        out = b""
        counter = 0
        while len(out) < length:
            out += hmac.new(self._enc, f"{nonce}\x00{counter}".encode(), hashlib.sha256).digest()
            counter += 1
        return out[:length]

    def seal(self, nonce: str, plaintext: str) -> str:
        data = plaintext.encode("utf-8")
        ct = bytes(a ^ b for a, b in zip(data, self._stream(nonce, len(data)), strict=True))
        tag = hmac.new(self._mac, nonce.encode() + b"\x00" + ct, hashlib.sha256).digest()[:_TAG_BYTES]
        return (ct + tag).hex()

    def unseal(self, nonce: str, sealed: str) -> str | None:
        raw = bytes.fromhex(sealed)
        ct, tag = raw[:-_TAG_BYTES], raw[-_TAG_BYTES:]
        expected = hmac.new(self._mac, nonce.encode() + b"\x00" + ct, hashlib.sha256).digest()[:_TAG_BYTES]
        if not hmac.compare_digest(tag, expected):
            return None
        return bytes(a ^ b for a, b in zip(ct, self._stream(nonce, len(ct)), strict=True)).decode("utf-8")
