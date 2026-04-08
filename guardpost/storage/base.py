"""Abstract storage backend protocol.

All storage implementations (SQLite, MongoDB, PostgreSQL) must implement
this interface. The default is SQLiteStorage (zero external dependencies).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from guardpost.email.banned import BannedEmailRecord
from guardpost.fraud.patterns import Registration
from guardpost.ip.reputation import IPReputationRecord


@runtime_checkable
class StorageBackend(Protocol):
    """Protocol that all storage backends must implement."""

    # ------------------------------------------------------------------
    # IP Reputation
    # ------------------------------------------------------------------

    async def get_ip_reputation(self, ip_address: str) -> IPReputationRecord | None:
        """Fetch an IP reputation record, or None if not found."""
        ...

    async def save_ip_reputation(self, record: IPReputationRecord) -> None:
        """Upsert an IP reputation record."""
        ...

    # ------------------------------------------------------------------
    # Banned Emails
    # ------------------------------------------------------------------

    async def is_email_banned(self, email_hash: str) -> bool:
        """Check if an email hash is in the ban list."""
        ...

    async def get_banned_email(self, email_hash: str) -> BannedEmailRecord | None:
        """Fetch a banned email record by hash."""
        ...

    async def save_banned_email(self, record: BannedEmailRecord) -> None:
        """Insert a banned email record."""
        ...

    async def delete_banned_email(self, email_hash: str) -> bool:
        """Delete a banned email by hash. Returns True if it existed."""
        ...

    # ------------------------------------------------------------------
    # Registrations (pattern detection persistence)
    # ------------------------------------------------------------------

    async def save_registration(self, registration: Registration) -> None:
        """Persist a registration event for pattern analysis."""
        ...

    async def get_recent_registrations(self, since: float) -> list[Registration]:
        """Fetch registration events with timestamp >= since."""
        ...

    async def purge_old_registrations(self, before: float) -> int:
        """Delete registration events with timestamp < before. Returns count deleted."""
        ...

    async def get_registration_timeline(
        self, since: float, bucket_seconds: int = 3600
    ) -> list[dict]:
        """Return registration counts grouped by time bucket.

        Returns list of dicts: {"t": bucket_start_timestamp, "count": int}
        Buckets are aligned to `bucket_seconds` (default: 1 hour).
        """
        ...

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    async def get_stats(self) -> dict:
        """Return aggregate statistics for the /stats endpoint.

        Returns a dict with keys:
            total_ips, graylisted_ips, blacklisted_ips, whitelisted_ips,
            total_banned_emails, total_registrations, total_suspicious_registrations
        """
        ...

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """Create tables / indexes if needed. Called once at startup."""
        ...

    async def close(self) -> None:
        """Release resources (connection pools, file handles)."""
        ...
