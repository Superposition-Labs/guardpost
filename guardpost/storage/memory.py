"""In-memory storage backend — for testing and ephemeral use.

Mirrors SQLiteStorage, tenancy included: bans, events and counters are per
tenant, IP reputation is shared.
"""

from __future__ import annotations

import dataclasses
from collections import Counter

from guardpost.email.banned import BannedEmailRecord
from guardpost.fraud.patterns import Registration
from guardpost.ip.reputation import IPReputationRecord
from guardpost.tenancy.models import ApiKey, Tenant

DEFAULT_LEGACY_TENANT = "default"


def tenant_stats(events: list[dict], banned: int, total: int, suspicious: int) -> dict:
    """Per-tenant stats, computed only from that tenant's own data.

    The IP fields count the distinct addresses (by keyed hash) seen in the
    tenant's retained events, each with the status recorded at its latest
    event — never the instance-wide reputation table, which other tenants feed.
    """
    latest: dict[str, tuple[float, str | None]] = {}
    for e in events:
        if e["ip_key"] is None:
            continue
        prev = latest.get(e["ip_key"])
        if prev is None or e["ts"] >= prev[0]:
            latest[e["ip_key"]] = (e["ts"], e["ip_status"])
    statuses = [status for _, status in latest.values()]
    return {
        "total_ips": len(statuses),
        "graylisted_ips": statuses.count("graylisted"),
        "blacklisted_ips": statuses.count("blacklisted"),
        "whitelisted_ips": statuses.count("whitelisted"),
        "total_banned_emails": banned,
        "total_registrations": total,
        "total_suspicious_registrations": suspicious,
    }


class MemoryStorage:
    """In-memory storage backend. Data is lost on process exit."""

    supports_tenancy = True

    def __init__(self, *, legacy_tenant: str = DEFAULT_LEGACY_TENANT) -> None:
        self.legacy_tenant = legacy_tenant
        self._ip_reputation: dict[str, IPReputationRecord] = {}
        self._bans: dict[tuple[str, str], BannedEmailRecord] = {}
        self._events: list[dict] = []
        self._counters: dict[str, list[int]] = {}
        self._tenants: dict[str, Tenant] = {}
        self._api_keys: dict[str, ApiKey] = {}
        self._meta: dict[str, str] = {}

    async def initialize(self) -> None:
        await self.ensure_tenant(self.legacy_tenant)

    async def close(self) -> None:
        self._ip_reputation.clear()
        self._bans.clear()
        self._events.clear()
        self._counters.clear()

    # IP Reputation (shared)
    async def get_ip_reputation(self, ip_address: str) -> IPReputationRecord | None:
        return self._ip_reputation.get(ip_address)

    async def save_ip_reputation(self, record: IPReputationRecord) -> None:
        self._ip_reputation[record.ip_address] = record

    async def update_ip_reputation(self, key, mutate) -> IPReputationRecord:
        # No await between the read and the write, so this is atomic on the
        # event loop.
        record = mutate(self._ip_reputation.get(key))
        self._ip_reputation[key] = record
        return record

    # Meta
    async def get_meta(self, key: str) -> str | None:
        return self._meta.get(key)

    async def ensure_meta(self, key: str, value: str) -> str:
        return self._meta.setdefault(key, value)

    # Tenants and keys (copies, so callers cannot mutate stored state)
    async def get_tenant(self, tenant_id: str) -> Tenant | None:
        t = self._tenants.get(tenant_id)
        return dataclasses.replace(t) if t else None

    async def list_tenants(self) -> list[Tenant]:
        return [dataclasses.replace(self._tenants[k]) for k in sorted(self._tenants)]

    async def create_tenant(self, tenant: Tenant) -> None:
        if tenant.id in self._tenants:
            raise ValueError(f"tenant {tenant.id!r} already exists")
        self._tenants[tenant.id] = dataclasses.replace(tenant)

    async def save_tenant(self, tenant: Tenant) -> None:
        if tenant.id not in self._tenants:
            raise LookupError(f"no such tenant: {tenant.id}")
        self._tenants[tenant.id] = dataclasses.replace(tenant)

    async def ensure_tenant(self, tenant_id: str, name: str | None = None) -> Tenant:
        if tenant_id not in self._tenants:
            self._tenants[tenant_id] = Tenant(id=tenant_id, name=name or tenant_id)
        return dataclasses.replace(self._tenants[tenant_id])

    async def get_api_key(self, key_id: str) -> ApiKey | None:
        k = self._api_keys.get(key_id)
        return dataclasses.replace(k) if k else None

    async def list_api_keys(self, tenant_id: str | None = None) -> list[ApiKey]:
        keys = sorted(self._api_keys.values(), key=lambda k: (k.tenant_id, k.created_at))
        return [dataclasses.replace(k) for k in keys if tenant_id is None or k.tenant_id == tenant_id]

    async def save_api_key(self, key: ApiKey) -> None:
        self._api_keys[key.id] = dataclasses.replace(key)

    async def touch_api_key(self, key_id: str, when) -> None:
        if key_id in self._api_keys:
            self._api_keys[key_id].last_used_at = when

    # Banned Emails (per tenant)
    def _tenant(self, tenant_id: str | None) -> str:
        return tenant_id or self.legacy_tenant

    async def is_email_banned(self, email_hash: str, tenant_id: str | None = None) -> bool:
        return (self._tenant(tenant_id), email_hash) in self._bans

    async def get_banned_email(self, email_hash: str, tenant_id: str | None = None) -> BannedEmailRecord | None:
        return self._bans.get((self._tenant(tenant_id), email_hash))

    async def save_banned_email(self, record: BannedEmailRecord, tenant_id: str | None = None) -> None:
        self._bans[(self._tenant(tenant_id), record.normalized_email_hash)] = record

    async def delete_banned_email(self, email_hash: str, tenant_id: str | None = None) -> bool:
        return self._bans.pop((self._tenant(tenant_id), email_hash), None) is not None

    # Registration events (per tenant)
    async def record_registration_event(
        self, tenant_id: str, *, ts: float, suspicious: bool,
        ip_key: str | None = None, ip_status: str | None = None,
    ) -> None:
        self._events.append({"tenant_id": tenant_id, "ts": ts, "suspicious": bool(suspicious),
                             "ip_key": ip_key, "ip_status": ip_status})
        counter = self._counters.setdefault(tenant_id, [0, 0])
        counter[0] += 1
        counter[1] += int(bool(suspicious))

    async def get_registration_timeline(
        self, since: float, bucket_seconds: int = 3600, tenant_id: str | None = None,
    ) -> list[dict]:
        tenant = self._tenant(tenant_id)
        buckets: Counter[int] = Counter()
        for e in self._events:
            if e["tenant_id"] == tenant and e["ts"] >= since:
                buckets[int(e["ts"] / bucket_seconds) * bucket_seconds] += 1
        return [{"t": t, "count": c} for t, c in sorted(buckets.items())]

    async def purge_registration_events(self, tenant_id: str, before: float) -> int:
        keep = [e for e in self._events if not (e["tenant_id"] == tenant_id and e["ts"] < before)]
        purged = len(self._events) - len(keep)
        self._events = keep
        return purged

    async def get_tenant_stats(self, tenant_id: str | None = None) -> dict:
        tenant = self._tenant(tenant_id)
        total, suspicious = self._counters.get(tenant, [0, 0])
        return tenant_stats(
            [e for e in self._events if e["tenant_id"] == tenant],
            sum(1 for t, _ in self._bans if t == tenant), total, suspicious,
        )

    # 0.2 registration API (pre-tenancy callers; the legacy tenant)
    async def save_registration(self, registration: Registration) -> None:
        await self.record_registration_event(self.legacy_tenant, ts=registration.timestamp, suspicious=False)

    async def get_recent_registrations(self, since: float) -> list[Registration]:
        return []

    async def purge_old_registrations(self, before: float) -> int:
        return await self.purge_registration_events(self.legacy_tenant, before)

    # Stats
    async def get_stats(self) -> dict:
        return await self.get_tenant_stats(self.legacy_tenant)
