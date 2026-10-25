"""SQLite storage backend — zero-config default.

Synchronous sqlite3 under ``asyncio.to_thread``: SQLite is fast enough for the
expected load and this avoids the aiosqlite dependency. The database file is
created on first run and its schema is managed by the migration runner
(``guardpost/storage/migrations/sqlite``).

Concurrency: one connection per storage object, guarded by a lock, in
autocommit mode. Every write runs inside :meth:`SQLiteStorage.transaction`
(``BEGIN IMMEDIATE``), which takes SQLite's write lock up front, so a
read-modify-write such as an IP counter bump is atomic against other
coroutines, threads and processes sharing the file.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import TypeVar

from guardpost.email.banned import BannedEmailRecord
from guardpost.fraud.patterns import Registration
from guardpost.ip.reputation import IPReputationRecord
from guardpost.storage.migrations import apply_sqlite_migrations

# Default database path: ~/.guardpost/guardpost.db
_DEFAULT_DB_PATH = Path.home() / ".guardpost" / "guardpost.db"

T = TypeVar("T")


class SQLiteStorage:
    """Async-compatible SQLite storage backend."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        self._conn: sqlite3.Connection | None = None
        # Re-entrant so a write helper can run inside an outer transaction().
        self._lock = threading.RLock()
        self._tx_depth = 0

    # ------------------------------------------------------------------
    # Connection, transactions, migrations
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(
                str(self.db_path), check_same_thread=False, isolation_level=None, timeout=30.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=30000")
            self._conn = conn
        return self._conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run a block in one ``BEGIN IMMEDIATE`` transaction (sync, blocking).

        Commits on success and rolls back on any exception. Nested use joins
        the outermost transaction. Call it from a worker thread
        (:meth:`_write` does) — it blocks while another writer holds the lock.
        """
        with self._lock:
            conn = self._get_conn()
            if self._tx_depth:
                self._tx_depth += 1
                try:
                    yield conn
                finally:
                    self._tx_depth -= 1
                return
            conn.execute("BEGIN IMMEDIATE")
            self._tx_depth = 1
            try:
                yield conn
            except BaseException:
                self._tx_depth = 0
                conn.execute("ROLLBACK")
                raise
            self._tx_depth = 0
            conn.execute("COMMIT")

    async def _read(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        def run() -> T:
            with self._lock:
                return fn(self._get_conn())

        return await asyncio.to_thread(run)

    async def _write(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        def run() -> T:
            with self.transaction() as conn:
                return fn(conn)

        return await asyncio.to_thread(run)

    def migration_params(self) -> Mapping[str, str]:
        """Values recorded in gp_meta before migrations run."""
        return {}

    def migrate(self) -> list[int]:
        """Apply pending schema migrations (sync). Returns the versions applied."""
        with self._lock:
            applied = apply_sqlite_migrations(self._get_conn(), self.migration_params())
        return [m.version for m in applied]

    async def initialize(self) -> None:
        """Create or upgrade the schema."""
        await asyncio.to_thread(self.migrate)

    async def close(self) -> None:
        if self._conn:
            conn = self._conn
            self._conn = None
            await asyncio.to_thread(conn.close)

    # ------------------------------------------------------------------
    # IP Reputation (shared across tenants)
    # ------------------------------------------------------------------

    @staticmethod
    def _load_ip(conn: sqlite3.Connection, key: str) -> IPReputationRecord | None:
        row = conn.execute("SELECT data FROM ip_reputation WHERE ip_address = ?", (key,)).fetchone()
        return IPReputationRecord.from_dict(json.loads(row["data"])) if row else None

    @staticmethod
    def _store_ip(conn: sqlite3.Connection, record: IPReputationRecord) -> None:
        conn.execute(
            "INSERT OR REPLACE INTO ip_reputation (ip_address, data) VALUES (?, ?)",
            (record.ip_address, json.dumps(record.to_dict())),
        )

    async def get_ip_reputation(self, ip_address: str) -> IPReputationRecord | None:
        return await self._read(lambda conn: self._load_ip(conn, ip_address))

    async def save_ip_reputation(self, record: IPReputationRecord) -> None:
        await self._write(lambda conn: self._store_ip(conn, record))

    async def update_ip_reputation(
        self,
        key: str,
        mutate: Callable[[IPReputationRecord | None], IPReputationRecord],
    ) -> IPReputationRecord:
        """Atomically read, mutate and write one reputation record.

        ``mutate`` receives the stored record (or None) and returns the record
        to save. It runs inside the write transaction, so no other writer can
        interleave between the read and the write — no lost increments.
        """
        def run(conn: sqlite3.Connection) -> IPReputationRecord:
            record = mutate(self._load_ip(conn, key))
            self._store_ip(conn, record)
            return record

        return await self._write(run)

    # ------------------------------------------------------------------
    # Banned Emails
    # ------------------------------------------------------------------

    async def is_email_banned(self, email_hash: str) -> bool:
        return await self._read(lambda conn: conn.execute(
            "SELECT 1 FROM banned_emails WHERE normalized_email_hash = ?", (email_hash,)
        ).fetchone() is not None)

    async def get_banned_email(self, email_hash: str) -> BannedEmailRecord | None:
        def run(conn):
            row = conn.execute(
                "SELECT data FROM banned_emails WHERE normalized_email_hash = ?", (email_hash,)).fetchone()
            return BannedEmailRecord.from_dict(json.loads(row["data"])) if row else None

        return await self._read(run)

    async def save_banned_email(self, record: BannedEmailRecord) -> None:
        await self._write(lambda conn: conn.execute(
            "INSERT OR REPLACE INTO banned_emails (normalized_email_hash, data) VALUES (?, ?)",
            (record.normalized_email_hash, json.dumps(record.to_dict())),
        ))

    async def delete_banned_email(self, email_hash: str) -> bool:
        return await self._write(lambda conn: conn.execute(
            "DELETE FROM banned_emails WHERE normalized_email_hash = ?", (email_hash,)
        ).rowcount > 0)

    # ------------------------------------------------------------------
    # Registrations
    # ------------------------------------------------------------------

    async def save_registration(self, registration: Registration) -> None:
        await self._write(lambda conn: conn.execute(
            "INSERT INTO registrations (email, username, domain, ip_address, timestamp) VALUES (?, ?, ?, ?, ?)",
            (registration.email, registration.username, registration.domain,
             registration.ip_address, registration.timestamp),
        ))

    async def get_recent_registrations(self, since: float) -> list[Registration]:
        def run(conn):
            rows = conn.execute(
                "SELECT email, username, domain, ip_address, timestamp "
                "FROM registrations WHERE timestamp >= ? ORDER BY timestamp",
                (since,),
            ).fetchall()
            return [Registration(email=r["email"], username=r["username"], domain=r["domain"],
                                 ip_address=r["ip_address"], timestamp=r["timestamp"]) for r in rows]

        return await self._read(run)

    async def purge_old_registrations(self, before: float) -> int:
        return await self._write(lambda conn: conn.execute(
            "DELETE FROM registrations WHERE timestamp < ?", (before,)).rowcount)

    async def get_registration_timeline(
        self, since: float, bucket_seconds: int = 3600
    ) -> list[dict]:
        def run(conn):
            rows = conn.execute(
                "SELECT (CAST(timestamp / ? AS INTEGER) * ?) AS t, COUNT(*) AS count "
                "FROM registrations WHERE timestamp >= ? GROUP BY t ORDER BY t",
                (bucket_seconds, bucket_seconds, since),
            ).fetchall()
            return [{"t": row[0], "count": row[1]} for row in rows]

        return await self._read(run)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    async def get_stats(self) -> dict:
        def run(conn):
            total_ips = conn.execute("SELECT COUNT(*) FROM ip_reputation").fetchone()[0]
            total_banned = conn.execute("SELECT COUNT(*) FROM banned_emails").fetchone()[0]
            graylisted = blacklisted = whitelisted = total_regs = total_suspicious = 0
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

        return await self._read(run)
