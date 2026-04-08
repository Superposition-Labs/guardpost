"""IP reputation tracking for registration abuse prevention.

Tracks registration patterns per IP address and enforces graylist/blacklist
thresholds to prevent multi-accounting and credit farming.

Thresholds are set high to account for corporate networks, university
campuses, co-working spaces, and mobile carrier CGNATs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guardpost.storage.base import StorageBackend

logger = logging.getLogger(__name__)


@dataclass
class IPReputationRecord:
    """Reputation state for a single IP address."""

    ip_address: str
    total_registrations: int = 0
    suspicious_registrations: int = 0
    first_registration_at: datetime | None = None
    last_registration_at: datetime | None = None
    status: str = "clean"  # clean | graylisted | blacklisted
    status_reason: str | None = None
    status_changed_at: datetime | None = None
    manually_whitelisted: bool = False
    whitelisted_by: str | None = None
    whitelist_reason: str | None = None

    def to_dict(self) -> dict:
        """Serialize to a plain dict for storage."""
        return {
            "ip_address": self.ip_address,
            "total_registrations": self.total_registrations,
            "suspicious_registrations": self.suspicious_registrations,
            "first_registration_at": self.first_registration_at.isoformat() if self.first_registration_at else None,
            "last_registration_at": self.last_registration_at.isoformat() if self.last_registration_at else None,
            "status": self.status,
            "status_reason": self.status_reason,
            "status_changed_at": self.status_changed_at.isoformat() if self.status_changed_at else None,
            "manually_whitelisted": self.manually_whitelisted,
            "whitelisted_by": self.whitelisted_by,
            "whitelist_reason": self.whitelist_reason,
        }

    @classmethod
    def from_dict(cls, data: dict) -> IPReputationRecord:
        """Deserialize from a plain dict."""
        for key in ("first_registration_at", "last_registration_at", "status_changed_at"):
            val = data.get(key)
            if isinstance(val, str):
                data[key] = datetime.fromisoformat(val)
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# Default thresholds — configurable via IPReputationEngine.__init__
DEFAULT_GRAYLIST_SUSPICIOUS_THRESHOLD = 5
DEFAULT_GRAYLIST_TOTAL_7D_THRESHOLD = 15
DEFAULT_BLACKLIST_SUSPICIOUS_THRESHOLD = 8
DEFAULT_BLACKLIST_TOTAL_30D_THRESHOLD = 30


class IPReputationEngine:
    """Evaluate and track IP reputation with pluggable storage."""

    def __init__(
        self,
        storage: StorageBackend,
        *,
        graylist_suspicious: int = DEFAULT_GRAYLIST_SUSPICIOUS_THRESHOLD,
        graylist_total_7d: int = DEFAULT_GRAYLIST_TOTAL_7D_THRESHOLD,
        blacklist_suspicious: int = DEFAULT_BLACKLIST_SUSPICIOUS_THRESHOLD,
        blacklist_total_30d: int = DEFAULT_BLACKLIST_TOTAL_30D_THRESHOLD,
    ) -> None:
        self.storage = storage
        self.graylist_suspicious = graylist_suspicious
        self.graylist_total_7d = graylist_total_7d
        self.blacklist_suspicious = blacklist_suspicious
        self.blacklist_total_30d = blacklist_total_30d

    async def record_registration(self, ip_address: str, is_suspicious: bool) -> IPReputationRecord:
        """Record a registration from an IP and re-evaluate status."""
        now = datetime.now(UTC)
        record = await self.storage.get_ip_reputation(ip_address)

        if record is None:
            record = IPReputationRecord(
                ip_address=ip_address,
                first_registration_at=now,
            )

        record.total_registrations += 1
        if is_suspicious:
            record.suspicious_registrations += 1
        record.last_registration_at = now

        if not record.manually_whitelisted:
            self._evaluate_status(record, now)

        await self.storage.save_ip_reputation(record)
        return record

    async def check_ip(self, ip_address: str) -> tuple[str, str | None]:
        """Check the current reputation of an IP.

        Returns:
            (status, reason) — status is 'clean', 'graylisted', or 'blacklisted'.
        """
        record = await self.storage.get_ip_reputation(ip_address)
        if record is None:
            return "clean", None
        if record.manually_whitelisted:
            return "clean", None
        return record.status, record.status_reason

    async def whitelist_ip(self, ip_address: str, whitelisted_by: str, reason: str) -> IPReputationRecord:
        """Manually whitelist an IP (admin override)."""
        now = datetime.now(UTC)
        record = await self.storage.get_ip_reputation(ip_address)
        if record is None:
            record = IPReputationRecord(ip_address=ip_address, first_registration_at=now)

        record.manually_whitelisted = True
        record.whitelisted_by = whitelisted_by
        record.whitelist_reason = reason
        record.status = "clean"
        record.status_reason = None
        record.status_changed_at = now

        await self.storage.save_ip_reputation(record)
        return record

    # ------------------------------------------------------------------
    # Internal evaluation
    # ------------------------------------------------------------------

    def _evaluate_status(self, record: IPReputationRecord, now: datetime) -> None:
        """Re-evaluate graylist/blacklist thresholds."""
        old_status = record.status

        # Blacklist thresholds (higher priority)
        if record.suspicious_registrations >= self.blacklist_suspicious:
            record.status = "blacklisted"
            record.status_reason = f"{record.suspicious_registrations} suspicious registrations"
        elif record.status != "blacklisted" and self._check_volume_blacklist(record, now):
            record.status = "blacklisted"
            record.status_reason = f"{record.total_registrations} total registrations (high volume)"
        elif record.suspicious_registrations >= self.graylist_suspicious:
            record.status = "graylisted"
            record.status_reason = f"{record.suspicious_registrations} suspicious registrations"
        elif self._check_volume_graylist(record, now):
            record.status = "graylisted"
            record.status_reason = f"{record.total_registrations} total registrations (elevated volume)"

        if record.status != old_status:
            record.status_changed_at = now
            logger.warning(
                "IP reputation changed: %s → %s for %s (%s)",
                old_status,
                record.status,
                record.ip_address,
                record.status_reason,
            )

    def _check_volume_blacklist(self, record: IPReputationRecord, now: datetime) -> bool:
        if not record.first_registration_at:
            return False
        first = record.first_registration_at.replace(tzinfo=now.tzinfo)
        days = (now - first).days or 1
        return days <= 30 and record.total_registrations >= self.blacklist_total_30d

    def _check_volume_graylist(self, record: IPReputationRecord, now: datetime) -> bool:
        if not record.first_registration_at:
            return False
        first = record.first_registration_at.replace(tzinfo=now.tzinfo)
        days = (now - first).days or 1
        return days <= 7 and record.total_registrations >= self.graylist_total_7d
