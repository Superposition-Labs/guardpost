"""Permanently banned email addresses.

Stores normalized email hashes (SHA-256) to prevent banned users
from re-registering with the same email.
"""

from __future__ import annotations

import hashlib
import logging
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


def _hash_email(email: str) -> str:
    """Normalize and SHA-256 hash an email."""
    normalized = normalize_email(email)
    return hashlib.sha256(normalized.encode()).hexdigest()


class BannedEmailEngine:
    """Manage permanently banned emails with pluggable storage."""

    def __init__(self, storage: StorageBackend) -> None:
        self.storage = storage

    async def is_banned(self, email: str) -> bool:
        """Check if an email is permanently banned."""
        email_hash = _hash_email(email)
        return await self.storage.is_email_banned(email_hash)

    async def ban(self, email: str, banned_by: str | None = None, reason: str | None = None) -> BannedEmailRecord:
        """Add an email to the permanent ban list."""
        email_hash = _hash_email(email)

        existing = await self.storage.get_banned_email(email_hash)
        if existing is not None:
            return existing

        record = BannedEmailRecord(
            normalized_email_hash=email_hash,
            banned_by=banned_by,
            reason=reason,
        )
        await self.storage.save_banned_email(record)
        return record

    async def unban(self, email: str) -> bool:
        """Remove an email from the ban list. Returns True if it was banned."""
        email_hash = _hash_email(email)
        return await self.storage.delete_banned_email(email_hash)
