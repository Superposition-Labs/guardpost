"""In-memory storage backend — for testing and ephemeral use."""

from __future__ import annotations

from guardpost.email.banned import BannedEmailRecord
from guardpost.fraud.patterns import Registration
from guardpost.ip.reputation import IPReputationRecord


class MemoryStorage:
    """In-memory storage backend. Data is lost on process exit."""

    def __init__(self) -> None:
        self._ip_reputation: dict[str, IPReputationRecord] = {}
        self._banned_emails: dict[str, BannedEmailRecord] = {}
        self._registrations: list[Registration] = []

    async def initialize(self) -> None:
        pass

    async def close(self) -> None:
        self._ip_reputation.clear()
        self._banned_emails.clear()
        self._registrations.clear()

    # IP Reputation
    async def get_ip_reputation(self, ip_address: str) -> IPReputationRecord | None:
        return self._ip_reputation.get(ip_address)

    async def save_ip_reputation(self, record: IPReputationRecord) -> None:
        self._ip_reputation[record.ip_address] = record

    # Banned Emails
    async def is_email_banned(self, email_hash: str) -> bool:
        return email_hash in self._banned_emails

    async def get_banned_email(self, email_hash: str) -> BannedEmailRecord | None:
        return self._banned_emails.get(email_hash)

    async def save_banned_email(self, record: BannedEmailRecord) -> None:
        self._banned_emails[record.normalized_email_hash] = record

    async def delete_banned_email(self, email_hash: str) -> bool:
        if email_hash in self._banned_emails:
            del self._banned_emails[email_hash]
            return True
        return False

    # Registrations
    async def save_registration(self, registration: Registration) -> None:
        self._registrations.append(registration)

    async def get_recent_registrations(self, since: float) -> list[Registration]:
        return [r for r in self._registrations if r.timestamp >= since]

    async def purge_old_registrations(self, before: float) -> int:
        old = [r for r in self._registrations if r.timestamp < before]
        self._registrations = [
            r for r in self._registrations if r.timestamp >= before]
        return len(old)

    async def get_registration_timeline(
        self, since: float, bucket_seconds: int = 3600
    ) -> list[dict]:
        from collections import Counter
        buckets: Counter[float] = Counter()
        for r in self._registrations:
            if r.timestamp >= since:
                bucket = int(r.timestamp / bucket_seconds) * bucket_seconds
                buckets[bucket] += 1
        return [
            {"t": t, "count": c}
            for t, c in sorted(buckets.items())
        ]

    # Stats
    async def get_stats(self) -> dict:
        records = self._ip_reputation.values()
        return {
            "total_ips": len(self._ip_reputation),
            "graylisted_ips": sum(1 for r in records if r.status == "graylisted"),
            "blacklisted_ips": sum(1 for r in records if r.status == "blacklisted"),
            "whitelisted_ips": sum(1 for r in records if r.manually_whitelisted),
            "total_banned_emails": len(self._banned_emails),
            "total_registrations": sum(r.total_registrations for r in records),
            "total_suspicious_registrations": sum(r.suspicious_registrations for r in records),
        }
