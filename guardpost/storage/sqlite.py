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
import logging
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
from guardpost.tenancy.config import TenantConfig
from guardpost.tenancy.models import ApiKey, Tenant, format_ts, parse_ts, utcnow

logger = logging.getLogger(__name__)

DEFAULT_LEGACY_TENANT = "default"

# Default database path: ~/.guardpost/guardpost.db
_DEFAULT_DB_PATH = Path.home() / ".guardpost" / "guardpost.db"

T = TypeVar("T")


class SQLiteStorage:
    """Async-compatible SQLite storage backend."""

    # Bans, stats and registration events are per tenant; IP reputation is shared.
    supports_tenancy = True

    def __init__(self, db_path: str | Path | None = None, *, legacy_tenant: str = DEFAULT_LEGACY_TENANT) -> None:
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        # The tenant that callers which pass no tenant act as (0.2 semantics).
        self.legacy_tenant = legacy_tenant
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
        """Values recorded in gp_meta before migrations run (first value wins)."""
        return {"legacy_tenant": self.legacy_tenant}

    def migrate(self) -> list[int]:
        """Apply pending schema migrations (sync). Returns the versions applied."""
        with self._lock:
            applied = apply_sqlite_migrations(self._get_conn(), self.migration_params())
        return [m.version for m in applied]

    async def initialize(self) -> None:
        """Create or upgrade the schema; make sure the legacy tenant exists."""
        await asyncio.to_thread(self.migrate)
        await self.ensure_tenant(self.legacy_tenant)
        migrated_to = await self.get_meta("legacy_tenant")
        if migrated_to and migrated_to != self.legacy_tenant:
            logger.warning(
                "Pre-0.3 bans and counters were migrated to tenant %r, but the legacy tenant is now %r "
                "(GUARDPOST_LEGACY_TENANT)", migrated_to, self.legacy_tenant)

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
    # Meta
    # ------------------------------------------------------------------

    async def get_meta(self, key: str) -> str | None:
        def run(conn):
            row = conn.execute("SELECT value FROM gp_meta WHERE key = ?", (key,)).fetchone()
            return row[0] if row else None

        return await self._read(run)

    async def ensure_meta(self, key: str, value: str) -> str:
        """Store ``value`` unless the key exists; return the stored value."""
        def run(conn):
            conn.execute("INSERT OR IGNORE INTO gp_meta (key, value) VALUES (?, ?)", (key, value))
            return conn.execute("SELECT value FROM gp_meta WHERE key = ?", (key,)).fetchone()[0]

        return await self._write(run)

    # ------------------------------------------------------------------
    # Tenants and API keys
    # ------------------------------------------------------------------

    @staticmethod
    def _tenant_from_row(row) -> Tenant:
        return Tenant(
            id=row["id"], name=row["name"], status=row["status"],
            config=TenantConfig.from_json(row["config_json"]), key_version=row["key_version"],
            created_at=parse_ts(row["created_at"]), updated_at=parse_ts(row["updated_at"]),
        )

    @staticmethod
    def _key_from_row(row) -> ApiKey:
        return ApiKey(
            id=row["id"], tenant_id=row["tenant_id"], key_sha256=row["key_sha256"],
            scopes=frozenset(s for s in row["scopes"].split(",") if s), label=row["label"],
            created_at=parse_ts(row["created_at"]), last_used_at=parse_ts(row["last_used_at"]),
            expires_at=parse_ts(row["expires_at"]), revoked_at=parse_ts(row["revoked_at"]),
        )

    async def get_tenant(self, tenant_id: str) -> Tenant | None:
        def run(conn):
            row = conn.execute("SELECT * FROM tenants WHERE id = ?", (tenant_id,)).fetchone()
            return self._tenant_from_row(row) if row else None

        return await self._read(run)

    async def list_tenants(self) -> list[Tenant]:
        return await self._read(lambda conn: [
            self._tenant_from_row(r) for r in conn.execute("SELECT * FROM tenants ORDER BY id")])

    async def create_tenant(self, tenant: Tenant) -> None:
        def run(conn):
            try:
                conn.execute(
                    "INSERT INTO tenants (id, name, status, config_json, key_version, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (tenant.id, tenant.name, tenant.status, tenant.config.to_json(), tenant.key_version,
                     format_ts(tenant.created_at), format_ts(tenant.updated_at)),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError(f"tenant {tenant.id!r} already exists") from exc

        await self._write(run)

    async def save_tenant(self, tenant: Tenant) -> None:
        def run(conn):
            cur = conn.execute(
                "UPDATE tenants SET name = ?, status = ?, config_json = ?, key_version = ?, updated_at = ? "
                "WHERE id = ?",
                (tenant.name, tenant.status, tenant.config.to_json(), tenant.key_version,
                 format_ts(tenant.updated_at), tenant.id),
            )
            if cur.rowcount == 0:
                raise LookupError(f"no such tenant: {tenant.id}")

        await self._write(run)

    async def ensure_tenant(self, tenant_id: str, name: str | None = None) -> Tenant:
        def run(conn):
            now = format_ts(utcnow())
            conn.execute(
                "INSERT OR IGNORE INTO tenants (id, name, status, config_json, key_version, created_at, updated_at) "
                "VALUES (?, ?, 'active', '{}', 1, ?, ?)",
                (tenant_id, name or tenant_id, now, now),
            )
            return self._tenant_from_row(
                conn.execute("SELECT * FROM tenants WHERE id = ?", (tenant_id,)).fetchone())

        return await self._write(run)

    async def get_api_key(self, key_id: str) -> ApiKey | None:
        def run(conn):
            row = conn.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,)).fetchone()
            return self._key_from_row(row) if row else None

        return await self._read(run)

    async def list_api_keys(self, tenant_id: str | None = None) -> list[ApiKey]:
        def run(conn):
            if tenant_id is None:
                rows = conn.execute("SELECT * FROM api_keys ORDER BY tenant_id, created_at")
            else:
                rows = conn.execute(
                    "SELECT * FROM api_keys WHERE tenant_id = ? ORDER BY created_at", (tenant_id,))
            return [self._key_from_row(r) for r in rows]

        return await self._read(run)

    async def save_api_key(self, key: ApiKey) -> None:
        await self._write(lambda conn: conn.execute(
            "INSERT INTO api_keys (id, tenant_id, key_sha256, scopes, label, created_at, last_used_at, "
            "expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (id) DO UPDATE SET tenant_id = excluded.tenant_id, key_sha256 = excluded.key_sha256, "
            "scopes = excluded.scopes, label = excluded.label, created_at = excluded.created_at, "
            "last_used_at = excluded.last_used_at, expires_at = excluded.expires_at, "
            "revoked_at = excluded.revoked_at",
            (key.id, key.tenant_id, key.key_sha256, ",".join(sorted(key.scopes)), key.label,
             format_ts(key.created_at), format_ts(key.last_used_at), format_ts(key.expires_at),
             format_ts(key.revoked_at)),
        ))

    async def touch_api_key(self, key_id: str, when) -> None:
        await self._write(lambda conn: conn.execute(
            "UPDATE api_keys SET last_used_at = ? WHERE id = ?", (format_ts(when), key_id)))

    # ------------------------------------------------------------------
    # Banned emails (per tenant)
    # ------------------------------------------------------------------

    def _tenant(self, tenant_id: str | None) -> str:
        return tenant_id or self.legacy_tenant

    async def is_email_banned(self, email_hash: str, tenant_id: str | None = None) -> bool:
        tenant = self._tenant(tenant_id)
        return await self._read(lambda conn: conn.execute(
            "SELECT 1 FROM bans WHERE tenant_id = ? AND email_hash = ?", (tenant, email_hash)
        ).fetchone() is not None)

    async def get_banned_email(self, email_hash: str, tenant_id: str | None = None) -> BannedEmailRecord | None:
        tenant = self._tenant(tenant_id)

        def run(conn):
            row = conn.execute(
                "SELECT email_hash, banned_at, banned_by, reason FROM bans WHERE tenant_id = ? AND email_hash = ?",
                (tenant, email_hash)).fetchone()
            if row is None:
                return None
            return BannedEmailRecord(normalized_email_hash=row["email_hash"], banned_at=parse_ts(row["banned_at"]),
                                     banned_by=row["banned_by"], reason=row["reason"])

        return await self._read(run)

    async def save_banned_email(self, record: BannedEmailRecord, tenant_id: str | None = None) -> None:
        tenant = self._tenant(tenant_id)
        await self._write(lambda conn: conn.execute(
            "INSERT OR REPLACE INTO bans (tenant_id, email_hash, banned_at, banned_by, reason) VALUES (?, ?, ?, ?, ?)",
            (tenant, record.normalized_email_hash, format_ts(record.banned_at), record.banned_by, record.reason),
        ))

    async def delete_banned_email(self, email_hash: str, tenant_id: str | None = None) -> bool:
        tenant = self._tenant(tenant_id)
        return await self._write(lambda conn: conn.execute(
            "DELETE FROM bans WHERE tenant_id = ? AND email_hash = ?", (tenant, email_hash)
        ).rowcount > 0)

    # ------------------------------------------------------------------
    # Registration events (per tenant; no email, keyed-hash IP)
    # ------------------------------------------------------------------

    async def record_registration_event(
        self,
        tenant_id: str,
        *,
        ts: float,
        suspicious: bool,
        ip_key: str | None = None,
        ip_status: str | None = None,
    ) -> None:
        def run(conn):
            conn.execute(
                "INSERT INTO registration_events (tenant_id, ts, suspicious, ip_key, ip_status) VALUES (?, ?, ?, ?, ?)",
                (tenant_id, ts, int(suspicious), ip_key, ip_status),
            )
            conn.execute(
                "INSERT INTO tenant_counters (tenant_id, total_registrations, suspicious_registrations) "
                "VALUES (?, 1, ?) ON CONFLICT (tenant_id) DO UPDATE SET "
                "total_registrations = total_registrations + 1, "
                "suspicious_registrations = suspicious_registrations + excluded.suspicious_registrations",
                (tenant_id, int(suspicious)),
            )

        await self._write(run)

    async def get_registration_timeline(
        self, since: float, bucket_seconds: int = 3600, tenant_id: str | None = None,
    ) -> list[dict]:
        tenant = self._tenant(tenant_id)

        def run(conn):
            rows = conn.execute(
                "SELECT (CAST(ts / ? AS INTEGER) * ?) AS t, COUNT(*) AS count FROM registration_events "
                "WHERE tenant_id = ? AND ts >= ? GROUP BY t ORDER BY t",
                (bucket_seconds, bucket_seconds, tenant, since),
            ).fetchall()
            return [{"t": row[0], "count": row[1]} for row in rows]

        return await self._read(run)

    async def purge_registration_events(self, tenant_id: str, before: float) -> int:
        return await self._write(lambda conn: conn.execute(
            "DELETE FROM registration_events WHERE tenant_id = ? AND ts < ?", (tenant_id, before)).rowcount)

    async def get_tenant_stats(self, tenant_id: str | None = None) -> dict:
        """The tenant's own numbers only (see :func:`guardpost.storage.memory.tenant_stats`)."""
        tenant = self._tenant(tenant_id)

        def run(conn):
            banned = conn.execute("SELECT COUNT(*) FROM bans WHERE tenant_id = ?", (tenant,)).fetchone()[0]
            counters = conn.execute(
                "SELECT total_registrations, suspicious_registrations FROM tenant_counters WHERE tenant_id = ?",
                (tenant,)).fetchone()
            # SQLite returns the bare ip_status from the row holding MAX(ts).
            latest = [row[0] for row in conn.execute(
                "SELECT ip_status, MAX(ts) FROM registration_events WHERE tenant_id = ? AND ip_key IS NOT NULL "
                "GROUP BY ip_key", (tenant,))]
            return {
                "total_ips": len(latest),
                "graylisted_ips": latest.count("graylisted"),
                "blacklisted_ips": latest.count("blacklisted"),
                "whitelisted_ips": latest.count("whitelisted"),
                "total_banned_emails": banned,
                "total_registrations": counters[0] if counters else 0,
                "total_suspicious_registrations": counters[1] if counters else 0,
            }

        return await self._read(run)

    # ------------------------------------------------------------------
    # 0.2 registration API (pre-tenancy callers; the legacy tenant)
    # ------------------------------------------------------------------

    async def save_registration(self, registration: Registration) -> None:
        """Counted as a legacy-tenant event. The email itself is not stored (0.3)."""
        await self.record_registration_event(self.legacy_tenant, ts=registration.timestamp, suspicious=False)

    async def get_recent_registrations(self, since: float) -> list[Registration]:
        """Always empty since 0.3: plaintext registrations are no longer persisted."""
        return []

    async def purge_old_registrations(self, before: float) -> int:
        return await self.purge_registration_events(self.legacy_tenant, before)

    async def get_stats(self) -> dict:
        return await self.get_tenant_stats(self.legacy_tenant)
