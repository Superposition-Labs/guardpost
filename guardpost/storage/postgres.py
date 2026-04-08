"""PostgreSQL storage backend — for production deployments.

Requires the ``asyncpg`` async driver::

    pip install guardpost[postgres]

Usage::

    from guardpost.storage.postgres import PostgresStorage

    storage = PostgresStorage("postgresql://user:pass@localhost/guardpost")
    await storage.initialize()
"""

from __future__ import annotations

import json

from guardpost.email.banned import BannedEmailRecord
from guardpost.fraud.patterns import Registration
from guardpost.ip.reputation import IPReputationRecord


class PostgresStorage:
    """Async PostgreSQL storage backend using asyncpg."""

    def __init__(self, dsn: str = "postgresql://localhost/guardpost") -> None:
        try:
            import asyncpg  # noqa: F401
        except ImportError as exc:
            raise ImportError(
                "asyncpg is required for PostgreSQL storage. Install it with: pip install guardpost[postgres]"
            ) from exc

        self._dsn = dsn
        self._pool = None

    async def initialize(self) -> None:
        import asyncpg

        self._pool = await asyncpg.create_pool(self._dsn, min_size=1, max_size=10)
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ip_reputation (
                    ip_address TEXT PRIMARY KEY,
                    data JSONB NOT NULL
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS banned_emails (
                    normalized_email_hash TEXT PRIMARY KEY,
                    data JSONB NOT NULL
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS registrations (
                    id SERIAL PRIMARY KEY,
                    email TEXT NOT NULL,
                    username TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    ip_address TEXT,
                    timestamp DOUBLE PRECISION NOT NULL
                )
                """
            )
            await conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_registrations_timestamp
                    ON registrations (timestamp)
                """
            )

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()
            self._pool = None

    # ------------------------------------------------------------------
    # IP Reputation
    # ------------------------------------------------------------------

    async def get_ip_reputation(self, ip_address: str) -> IPReputationRecord | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT data FROM ip_reputation WHERE ip_address = $1",
                ip_address,
            )
        if row is None:
            return None
        return IPReputationRecord.from_dict(json.loads(row["data"]))

    async def save_ip_reputation(self, record: IPReputationRecord) -> None:
        data = json.dumps(record.to_dict())
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO ip_reputation (ip_address, data) VALUES ($1, $2)
                ON CONFLICT (ip_address) DO UPDATE SET data = EXCLUDED.data
                """,
                record.ip_address,
                data,
            )

    # ------------------------------------------------------------------
    # Banned Emails
    # ------------------------------------------------------------------

    async def is_email_banned(self, email_hash: str) -> bool:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT 1 FROM banned_emails WHERE normalized_email_hash = $1",
                email_hash,
            )
        return row is not None

    async def get_banned_email(self, email_hash: str) -> BannedEmailRecord | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT data FROM banned_emails WHERE normalized_email_hash = $1",
                email_hash,
            )
        if row is None:
            return None
        return BannedEmailRecord.from_dict(json.loads(row["data"]))

    async def save_banned_email(self, record: BannedEmailRecord) -> None:
        data = json.dumps(record.to_dict())
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO banned_emails (normalized_email_hash, data) VALUES ($1, $2)
                ON CONFLICT (normalized_email_hash) DO UPDATE SET data = EXCLUDED.data
                """,
                record.normalized_email_hash,
                data,
            )

    async def delete_banned_email(self, email_hash: str) -> bool:
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM banned_emails WHERE normalized_email_hash = $1",
                email_hash,
            )
        return result == "DELETE 1"

    # ------------------------------------------------------------------
    # Registrations
    # ------------------------------------------------------------------

    async def save_registration(self, registration: Registration) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO registrations (email, username, domain, ip_address, timestamp) "
                "VALUES ($1, $2, $3, $4, $5)",
                registration.email,
                registration.username,
                registration.domain,
                registration.ip_address,
                registration.timestamp,
            )

    async def get_recent_registrations(self, since: float) -> list[Registration]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT email, username, domain, ip_address, timestamp "
                "FROM registrations WHERE timestamp >= $1 ORDER BY timestamp",
                since,
            )
        return [
            Registration(
                email=row["email"],
                username=row["username"],
                domain=row["domain"],
                ip_address=row["ip_address"],
                timestamp=row["timestamp"],
            )
            for row in rows
        ]

    async def purge_old_registrations(self, before: float) -> int:
        async with self._pool.acquire() as conn:
            result = await conn.execute("DELETE FROM registrations WHERE timestamp < $1", before)
        # asyncpg returns 'DELETE N'
        return int(result.split()[-1])

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    async def get_stats(self) -> dict:
        async with self._pool.acquire() as conn:
            total_ips = await conn.fetchval("SELECT COUNT(*) FROM ip_reputation")
            total_banned = await conn.fetchval("SELECT COUNT(*) FROM banned_emails")
            graylisted = await conn.fetchval("SELECT COUNT(*) FROM ip_reputation WHERE data->>'status' = 'graylisted'")
            blacklisted = await conn.fetchval(
                "SELECT COUNT(*) FROM ip_reputation WHERE data->>'status' = 'blacklisted'"
            )
            whitelisted = await conn.fetchval(
                "SELECT COUNT(*) FROM ip_reputation WHERE (data->>'manually_whitelisted')::boolean = true"
            )
            row = await conn.fetchrow(
                """
                SELECT
                    COALESCE(SUM((data->>'total_registrations')::int), 0) AS total_regs,
                    COALESCE(SUM((data->>'suspicious_registrations')::int), 0) AS total_suspicious
                FROM ip_reputation
                """
            )

        return {
            "total_ips": total_ips,
            "graylisted_ips": graylisted,
            "blacklisted_ips": blacklisted,
            "whitelisted_ips": whitelisted,
            "total_banned_emails": total_banned,
            "total_registrations": row["total_regs"],
            "total_suspicious_registrations": row["total_suspicious"],
        }
