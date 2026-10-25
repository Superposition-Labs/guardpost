"""IP reputation tracking for registration abuse prevention.

Tracks registration patterns per IP address and enforces graylist/blacklist
thresholds to prevent multi-accounting and credit farming.

Thresholds are set high to account for corporate networks, university
campuses, co-working spaces, and mobile carrier CGNATs.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, NamedTuple

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

# Subnet thresholds — deliberately higher than the per-IP ones, because a /24 is
# shared by strangers: CGNAT pools, campus networks and small ISPs all live
# inside one block, so the innocent-neighbour cost of a wrong verdict is real.
#
# The layer exists because per-IP reputation is blind to a rotating proxy pool.
# In factory_ru (Aug 2026) six /24 blocks produced 45 registrations from 45
# distinct IPs — one registration each, so no IP counter ever moved. Only 2 of
# the 45 were flagged, and none of them ever paid.
DEFAULT_SUBNET_GRAYLIST_SUSPICIOUS_THRESHOLD = 8
DEFAULT_SUBNET_GRAYLIST_TOTAL_7D_THRESHOLD = 25
DEFAULT_SUBNET_BLACKLIST_SUSPICIOUS_THRESHOLD = 15
DEFAULT_SUBNET_BLACKLIST_TOTAL_30D_THRESHOLD = 50


class _Thresholds(NamedTuple):
    """One tier's four limits, so per-IP and per-subnet share the same logic."""

    graylist_suspicious: int
    graylist_total_7d: int
    blacklist_suspicious: int
    blacklist_total_30d: int


def subnet_key(ip_address: str) -> str | None:
    """Return the /24 an IPv4 address belongs to, e.g. "185.193.158.0/24".

    Returns None for IPv6 and for anything unparseable. IPv6 is excluded on
    purpose: a single household commonly holds a whole /64, so the prefix sizes
    that would be comparable to a /24 do not carry the same meaning.
    """
    try:
        parsed = ipaddress.ip_address(ip_address)
    except ValueError:
        return None
    if parsed.version != 4:
        return None
    return str(ipaddress.ip_network(f"{ip_address}/24", strict=False))


class IPReputationEngine:
    """Evaluate and track IP reputation with pluggable storage.

    Tracks two tiers against the same storage: the individual address, and the
    /24 it sits in. Subnet records reuse IPReputationRecord with the CIDR string
    in `ip_address`, so no storage or schema change is needed.
    """

    def __init__(
        self,
        storage: StorageBackend,
        *,
        graylist_suspicious: int = DEFAULT_GRAYLIST_SUSPICIOUS_THRESHOLD,
        graylist_total_7d: int = DEFAULT_GRAYLIST_TOTAL_7D_THRESHOLD,
        blacklist_suspicious: int = DEFAULT_BLACKLIST_SUSPICIOUS_THRESHOLD,
        blacklist_total_30d: int = DEFAULT_BLACKLIST_TOTAL_30D_THRESHOLD,
        track_subnets: bool = True,
        subnet_graylist_suspicious: int = DEFAULT_SUBNET_GRAYLIST_SUSPICIOUS_THRESHOLD,
        subnet_graylist_total_7d: int = DEFAULT_SUBNET_GRAYLIST_TOTAL_7D_THRESHOLD,
        subnet_blacklist_suspicious: int = DEFAULT_SUBNET_BLACKLIST_SUSPICIOUS_THRESHOLD,
        subnet_blacklist_total_30d: int = DEFAULT_SUBNET_BLACKLIST_TOTAL_30D_THRESHOLD,
    ) -> None:
        self.storage = storage
        self.graylist_suspicious = graylist_suspicious
        self.graylist_total_7d = graylist_total_7d
        self.blacklist_suspicious = blacklist_suspicious
        self.blacklist_total_30d = blacklist_total_30d
        self.track_subnets = track_subnets
        self._ip_thresholds = _Thresholds(
            graylist_suspicious,
            graylist_total_7d,
            blacklist_suspicious,
            blacklist_total_30d,
        )
        self._subnet_thresholds = _Thresholds(
            subnet_graylist_suspicious,
            subnet_graylist_total_7d,
            subnet_blacklist_suspicious,
            subnet_blacklist_total_30d,
        )

    async def record_registration(self, ip_address: str, is_suspicious: bool) -> IPReputationRecord:
        """Record a registration from an IP and re-evaluate status.

        Also updates the enclosing /24 when subnet tracking is on. Returns the
        per-IP record, which is what every existing caller expects.
        """
        now = datetime.now(UTC)
        record = await self._bump(ip_address, is_suspicious, now, self._ip_thresholds)

        if self.track_subnets:
            cidr = subnet_key(ip_address)
            if cidr:
                await self._bump(cidr, is_suspicious, now, self._subnet_thresholds)

        return record

    async def _bump(
        self,
        key: str,
        is_suspicious: bool,
        now: datetime,
        thresholds: _Thresholds,
    ) -> IPReputationRecord:
        """Increment one reputation record and re-evaluate it."""

        def mutate(record: IPReputationRecord | None) -> IPReputationRecord:
            if record is None:
                record = IPReputationRecord(ip_address=key, first_registration_at=now)
            record.total_registrations += 1
            if is_suspicious:
                record.suspicious_registrations += 1
            record.last_registration_at = now
            if not record.manually_whitelisted:
                self._evaluate_status(record, now, thresholds)
            return record

        return await self._update(key, mutate)

    async def _update(
        self,
        key: str,
        mutate: Callable[[IPReputationRecord | None], IPReputationRecord],
    ) -> IPReputationRecord:
        """Read-modify-write one record, atomically when the backend can.

        Backends with ``update_ip_reputation`` (SQLite, memory) run ``mutate``
        inside their write lock, so concurrent registrations from one IP never
        lose an increment. Others fall back to get-then-save, which can.
        """
        update = getattr(self.storage, "update_ip_reputation", None)
        if update is not None:
            return await update(key, mutate)
        record = mutate(await self.storage.get_ip_reputation(key))
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

    async def check_subnet(self, ip_address: str) -> tuple[str, str | None]:
        """Check the reputation of the /24 enclosing an address.

        A whitelisted individual IP is exempt: an admin who vouched for the
        address should not see it condemned by its neighbours.
        """
        if not self.track_subnets:
            return "clean", None

        cidr = subnet_key(ip_address)
        if not cidr:
            return "clean", None

        ip_record = await self.storage.get_ip_reputation(ip_address)
        if ip_record is not None and ip_record.manually_whitelisted:
            return "clean", None

        record = await self.storage.get_ip_reputation(cidr)
        if record is None or record.manually_whitelisted:
            return "clean", None
        return record.status, record.status_reason

    async def whitelist_ip(self, ip_address: str, whitelisted_by: str, reason: str) -> IPReputationRecord:
        """Manually whitelist an IP or a /24 CIDR (admin override, shared by all tenants)."""
        now = datetime.now(UTC)

        def mutate(record: IPReputationRecord | None) -> IPReputationRecord:
            if record is None:
                record = IPReputationRecord(ip_address=ip_address, first_registration_at=now)
            record.manually_whitelisted = True
            record.whitelisted_by = whitelisted_by
            record.whitelist_reason = reason
            record.status = "clean"
            record.status_reason = None
            record.status_changed_at = now
            return record

        return await self._update(ip_address, mutate)

    # ------------------------------------------------------------------
    # Internal evaluation
    # ------------------------------------------------------------------

    def _evaluate_status(
        self,
        record: IPReputationRecord,
        now: datetime,
        thresholds: _Thresholds | None = None,
    ) -> None:
        """Re-evaluate graylist/blacklist thresholds.

        `thresholds` defaults to the per-IP tier so existing callers and tests
        keep their behaviour.
        """
        limits = thresholds or self._ip_thresholds
        old_status = record.status

        # Blacklist thresholds (higher priority)
        if record.suspicious_registrations >= limits.blacklist_suspicious:
            record.status = "blacklisted"
            record.status_reason = f"{record.suspicious_registrations} suspicious registrations"
        elif record.status != "blacklisted" and self._check_volume_blacklist(record, now, limits):
            record.status = "blacklisted"
            record.status_reason = f"{record.total_registrations} total registrations (high volume)"
        elif record.suspicious_registrations >= limits.graylist_suspicious:
            record.status = "graylisted"
            record.status_reason = f"{record.suspicious_registrations} suspicious registrations"
        elif self._check_volume_graylist(record, now, limits):
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

    def _check_volume_blacklist(
        self, record: IPReputationRecord, now: datetime, limits: _Thresholds | None = None
    ) -> bool:
        limits = limits or self._ip_thresholds
        if not record.first_registration_at:
            return False
        first = record.first_registration_at.replace(tzinfo=now.tzinfo)
        days = (now - first).days or 1
        return days <= 30 and record.total_registrations >= limits.blacklist_total_30d

    def _check_volume_graylist(
        self, record: IPReputationRecord, now: datetime, limits: _Thresholds | None = None
    ) -> bool:
        limits = limits or self._ip_thresholds
        if not record.first_registration_at:
            return False
        first = record.first_registration_at.replace(tzinfo=now.tzinfo)
        days = (now - first).days or 1
        return days <= 7 and record.total_registrations >= limits.graylist_total_7d
