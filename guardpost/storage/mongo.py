"""MongoDB storage backend — for high-throughput deployments.

Requires the ``motor`` async driver::

    pip install guardpost[mongo]

Usage::

    from guardpost.storage.mongo import MongoStorage

    storage = MongoStorage("mongodb://localhost:27017", database="guardpost")
    await storage.initialize()
"""

from __future__ import annotations

from guardpost.email.banned import BannedEmailRecord
from guardpost.fraud.patterns import Registration
from guardpost.ip.reputation import IPReputationRecord


class MongoStorage:
    """Async MongoDB storage backend using motor."""

    def __init__(
        self,
        uri: str = "mongodb://localhost:27017",
        database: str = "guardpost",
    ) -> None:
        try:
            import motor.motor_asyncio  # noqa: F401
        except ImportError as exc:
            raise ImportError(
                "motor is required for MongoDB storage. Install it with: pip install guardpost[mongo]"
            ) from exc

        self._client = motor.motor_asyncio.AsyncIOMotorClient(uri)
        self._db = self._client[database]
        self._ip_col = self._db["ip_reputation"]
        self._ban_col = self._db["banned_emails"]
        self._reg_col = self._db["registrations"]

    async def initialize(self) -> None:
        await self._ip_col.create_index("ip_address", unique=True)
        await self._ban_col.create_index("normalized_email_hash", unique=True)
        await self._reg_col.create_index("timestamp")

    async def close(self) -> None:
        self._client.close()

    # ------------------------------------------------------------------
    # IP Reputation
    # ------------------------------------------------------------------

    async def get_ip_reputation(self, ip_address: str) -> IPReputationRecord | None:
        doc = await self._ip_col.find_one({"ip_address": ip_address})
        if doc is None:
            return None
        doc.pop("_id", None)
        return IPReputationRecord.from_dict(doc)

    async def save_ip_reputation(self, record: IPReputationRecord) -> None:
        data = record.to_dict()
        await self._ip_col.replace_one({"ip_address": record.ip_address}, data, upsert=True)

    # ------------------------------------------------------------------
    # Banned Emails
    # ------------------------------------------------------------------

    async def is_email_banned(self, email_hash: str) -> bool:
        return await self._ban_col.count_documents({"normalized_email_hash": email_hash}, limit=1) > 0

    async def get_banned_email(self, email_hash: str) -> BannedEmailRecord | None:
        doc = await self._ban_col.find_one({"normalized_email_hash": email_hash})
        if doc is None:
            return None
        doc.pop("_id", None)
        return BannedEmailRecord.from_dict(doc)

    async def save_banned_email(self, record: BannedEmailRecord) -> None:
        data = record.to_dict()
        await self._ban_col.replace_one(
            {"normalized_email_hash": record.normalized_email_hash},
            data,
            upsert=True,
        )

    async def delete_banned_email(self, email_hash: str) -> bool:
        result = await self._ban_col.delete_one({"normalized_email_hash": email_hash})
        return result.deleted_count > 0

    # ------------------------------------------------------------------
    # Registrations
    # ------------------------------------------------------------------

    async def save_registration(self, registration: Registration) -> None:
        await self._reg_col.insert_one(registration.to_dict())

    async def get_recent_registrations(self, since: float) -> list[Registration]:
        cursor = self._reg_col.find({"timestamp": {"$gte": since}}).sort("timestamp", 1)
        return [Registration.from_dict(doc) async for doc in cursor]

    async def purge_old_registrations(self, before: float) -> int:
        result = await self._reg_col.delete_many({"timestamp": {"$lt": before}})
        return result.deleted_count

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    async def get_stats(self) -> dict:
        total_ips = await self._ip_col.count_documents({})
        graylisted = await self._ip_col.count_documents({"status": "graylisted"})
        blacklisted = await self._ip_col.count_documents({"status": "blacklisted"})
        whitelisted = await self._ip_col.count_documents({"manually_whitelisted": True})
        total_banned = await self._ban_col.count_documents({})

        pipeline = [
            {
                "$group": {
                    "_id": None,
                    "total_registrations": {"$sum": "$total_registrations"},
                    "total_suspicious_registrations": {"$sum": "$suspicious_registrations"},
                }
            },
        ]
        agg = await self._ip_col.aggregate(pipeline).to_list(1)
        totals = agg[0] if agg else {}

        return {
            "total_ips": total_ips,
            "graylisted_ips": graylisted,
            "blacklisted_ips": blacklisted,
            "whitelisted_ips": whitelisted,
            "total_banned_emails": total_banned,
            "total_registrations": totals.get("total_registrations", 0),
            "total_suspicious_registrations": totals.get("total_suspicious_registrations", 0),
        }
