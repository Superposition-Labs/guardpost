"""Permanently banned email addresses.

Stores normalized email hashes (SHA-256) to prevent banned users
from re-registering with the same email.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guardpost.storage.base import StorageBackend

from guardpost.email.validator import normalize_email

logger = logging.getLogger(__name__)


@dataclass
class BannedEmailRecord:
    """A permanently banned email (stored as normalized hash — no plaintext PII)."""

    normalized_email_hash: str
    banned_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    banned_by: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict:
        return {
            "normalized_email_hash": self.normalized_email_hash,
            "banned_at": self.banned_at.isoformat(),
            "banned_by": self.banned_by,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: dict) -> BannedEmailRecord:
        val = data.get("banned_at")
        if isinstance(val, str):
            data["banned_at"] = datetime.fromisoformat(val)
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


Keyer = Callable[[str], str]


def _hash_email(email: str) -> str:
    """Normalize and SHA-256 hash an email."""
    normalized = normalize_email(email)
    return hashlib.sha256(normalized.encode()).hexdigest()


class BannedEmailEngine:
    """Manage permanently banned emails with pluggable storage.

    ``tenant_id`` scopes a ban to one tenant on backends that support tenancy
    (SQLite, memory); None means the backend's legacy tenant. It is not passed
    at all when None, so pre-tenancy backends keep working.

    ``keyer`` turns the sha256 of the normalized address into the stored key:
    the tenant's HMAC once the instance has a real GUARDPOST_SECRET (see
    guardpost/ledger/rekey.py), else None and the sha256 is stored as is.
    """

    def __init__(self, storage: StorageBackend) -> None:
        self.storage = storage

    @staticmethod
    def _scope(tenant_id: str | None) -> dict:
        return {"tenant_id": tenant_id} if tenant_id is not None else {}

    @staticmethod
    def _key(email: str, keyer: Keyer | None) -> str:
        digest = _hash_email(email)
        return keyer(digest) if keyer else digest

    async def is_banned(self, email: str, *, tenant_id: str | None = None, keyer: Keyer | None = None) -> bool:
        """Check if an email is permanently banned."""
        return await self.storage.is_email_banned(self._key(email, keyer), **self._scope(tenant_id))

    async def ban(
        self,
        email: str,
        banned_by: str | None = None,
        reason: str | None = None,
        *,
        tenant_id: str | None = None,
        keyer: Keyer | None = None,
    ) -> BannedEmailRecord:
        """Add an email to the permanent ban list."""
        email_hash = self._key(email, keyer)
        scope = self._scope(tenant_id)

        existing = await self.storage.get_banned_email(email_hash, **scope)
        if existing is not None:
            return existing

        record = BannedEmailRecord(
            normalized_email_hash=email_hash,
            banned_by=banned_by,
            reason=reason,
        )
        await self.storage.save_banned_email(record, **scope)
        return record

    async def unban(self, email: str, *, tenant_id: str | None = None, keyer: Keyer | None = None) -> bool:
        """Remove an email from the ban list. Returns True if it was banned."""
        return await self.storage.delete_banned_email(self._key(email, keyer), **self._scope(tenant_id))
