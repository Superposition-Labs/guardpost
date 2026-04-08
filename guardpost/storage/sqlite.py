"""SQLite storage backend — zero-config default.

Uses aiosqlite for async SQLite access. The database file is created
automatically on first run. No external database server required.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
from pathlib import Path

from guardpost.email.banned import BannedEmailRecord
from guardpost.fraud.patterns import Registration
from guardpost.ip.reputation import IPReputationRecord

# Default database path: ~/.guardpost/guardpost.db
_DEFAULT_DB_PATH = Path.home() / ".guardpost" / "guardpost.db"


class SQLiteStorage:
    """Async-compatible SQLite storage backend.

    Uses synchronous sqlite3 under the hood (SQLite is fast enough
    for the expected load, and avoids the aiosqlite dependency).
    For high-throughput scenarios, use MongoDB or PostgreSQL backends.
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(
                str(self.db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def _initialize_sync(self) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.executescript(
                """
            CREATE TABLE IF NOT EXISTS ip_reputation (
                ip_address TEXT PRIMARY KEY,
                data TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS banned_emails (
                normalized_email_hash TEXT PRIMARY KEY,
                data TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS registrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                username TEXT NOT NULL,
                domain TEXT NOT NULL,
                ip_address TEXT,
                timestamp REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_registrations_timestamp
                ON registrations (timestamp);
            """
            )
            conn.commit()

    async def initialize(self) -> None:
        """Create tables if they don't exist."""
        await asyncio.to_thread(self._initialize_sync)

    async def close(self) -> None:
        if self._conn:
            conn = self._conn
            self._conn = None
            await asyncio.to_thread(conn.close)

    # ------------------------------------------------------------------
    # IP Reputation
    # ------------------------------------------------------------------

    async def get_ip_reputation(self, ip_address: str) -> IPReputationRecord | None:
        def _query():
            with self._lock:
                conn = self._get_conn()
                row = conn.execute(
                    "SELECT data FROM ip_reputation WHERE ip_address = ?", (ip_address,)).fetchone()
                if row is None:
                    return None
                return IPReputationRecord.from_dict(json.loads(row["data"]))

        return await asyncio.to_thread(_query)

    async def save_ip_reputation(self, record: IPReputationRecord) -> None:
        def _write():
            with self._lock:
                conn = self._get_conn()
                conn.execute(
                    "INSERT OR REPLACE INTO ip_reputation (ip_address, data) VALUES (?, ?)",
                    (record.ip_address, json.dumps(record.to_dict())),
                )
                conn.commit()

        await asyncio.to_thread(_write)

    # ------------------------------------------------------------------
    # Banned Emails
    # ------------------------------------------------------------------

    async def is_email_banned(self, email_hash: str) -> bool:
        def _query():
            with self._lock:
                conn = self._get_conn()
                row = conn.execute(
                    "SELECT 1 FROM banned_emails WHERE normalized_email_hash = ?", (email_hash,)).fetchone()
                return row is not None

        return await asyncio.to_thread(_query)

    async def get_banned_email(self, email_hash: str) -> BannedEmailRecord | None:
        def _query():
            with self._lock:
                conn = self._get_conn()
                row = conn.execute(
                    "SELECT data FROM banned_emails WHERE normalized_email_hash = ?", (
                        email_hash,)
                ).fetchone()
                if row is None:
                    return None
                return BannedEmailRecord.from_dict(json.loads(row["data"]))

        return await asyncio.to_thread(_query)

    async def save_banned_email(self, record: BannedEmailRecord) -> None:
        def _write():
            with self._lock:
                conn = self._get_conn()
                conn.execute(
                    "INSERT OR REPLACE INTO banned_emails (normalized_email_hash, data) VALUES (?, ?)",
                    (record.normalized_email_hash, json.dumps(record.to_dict())),
                )
                conn.commit()

        await asyncio.to_thread(_write)

    async def delete_banned_email(self, email_hash: str) -> bool:
        def _delete():
            with self._lock:
                conn = self._get_conn()
                cursor = conn.execute(
                    "DELETE FROM banned_emails WHERE normalized_email_hash = ?", (email_hash,))
                conn.commit()
                return cursor.rowcount > 0

        return await asyncio.to_thread(_delete)

    # ------------------------------------------------------------------
    # Registrations
    # ------------------------------------------------------------------

    async def save_registration(self, registration: Registration) -> None:
        def _write():
            with self._lock:
                conn = self._get_conn()
                conn.execute(
                    "INSERT INTO registrations (email, username, domain, ip_address, timestamp) VALUES (?, ?, ?, ?, ?)",
                    (
                        registration.email,
                        registration.username,
                        registration.domain,
                        registration.ip_address,
                        registration.timestamp,
                    ),
                )
                conn.commit()

        await asyncio.to_thread(_write)

    async def get_recent_registrations(self, since: float) -> list[Registration]:
        def _query():
            with self._lock:
                conn = self._get_conn()
                rows = conn.execute(
                    "SELECT email, username, domain, ip_address, timestamp "
                    "FROM registrations WHERE timestamp >= ? ORDER BY timestamp",
                    (since,),
                ).fetchall()
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

        return await asyncio.to_thread(_query)

    async def purge_old_registrations(self, before: float) -> int:
        def _delete():
            with self._lock:
                conn = self._get_conn()
                cursor = conn.execute(
                    "DELETE FROM registrations WHERE timestamp < ?", (before,))
                conn.commit()
                return cursor.rowcount

        return await asyncio.to_thread(_delete)

    async def get_registration_timeline(
        self, since: float, bucket_seconds: int = 3600
    ) -> list[dict]:
        def _query():
            with self._lock:
                conn = self._get_conn()
                rows = conn.execute(
                    "SELECT (CAST(timestamp / ? AS INTEGER) * ?) AS t, COUNT(*) AS count "
                    "FROM registrations WHERE timestamp >= ? "
                    "GROUP BY t ORDER BY t",
                    (bucket_seconds, bucket_seconds, since),
                ).fetchall()
                return [{"t": row[0], "count": row[1]} for row in rows]
        return await asyncio.to_thread(_query)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    async def get_stats(self) -> dict:
        def _query():
            conn = self._get_conn()
            total_ips = conn.execute(
                "SELECT COUNT(*) FROM ip_reputation").fetchone()[0]
            total_banned = conn.execute(
                "SELECT COUNT(*) FROM banned_emails").fetchone()[0]

            # Aggregate from JSON data
            graylisted = 0
            blacklisted = 0
            whitelisted = 0
            total_regs = 0
            total_suspicious = 0
            for row in conn.execute("SELECT data FROM ip_reputation"):
                data = json.loads(row[0])
                status = data.get("status", "clean")
                if status == "graylisted":
                    graylisted += 1
                elif status == "blacklisted":
                    blacklisted += 1
                if data.get("manually_whitelisted"):
                    whitelisted += 1
                total_regs += data.get("total_registrations", 0)
                total_suspicious += data.get("suspicious_registrations", 0)

            return {
                "total_ips": total_ips,
                "graylisted_ips": graylisted,
                "blacklisted_ips": blacklisted,
                "whitelisted_ips": whitelisted,
                "total_banned_emails": total_banned,
                "total_registrations": total_regs,
                "total_suspicious_registrations": total_suspicious,
            }

        return await asyncio.to_thread(_query)
