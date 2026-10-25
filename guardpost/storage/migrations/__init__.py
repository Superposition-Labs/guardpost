"""Schema migrations.

SQLite migrations live in ``sqlite/NNNN_<name>.sql`` and are applied in version
order, each in its own ``BEGIN IMMEDIATE`` transaction, and recorded in
``schema_migrations``. A migration that fails is rolled back whole and stops
the run, so the database is always at some exact version.

Parameters that a migration needs from the deployment (for example which
tenant pre-tenancy data belongs to) are written to ``gp_meta`` before any
migration runs, with INSERT OR IGNORE: the first value recorded wins, so a
later change of environment cannot re-target data that was already migrated.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import resources

_FILENAME_RE = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")


class MigrationError(RuntimeError):
    """A migration failed; the database is left at the previous version."""


# A migration whose SQL holds this line drops personal data: the runner VACUUMs
# afterwards, because DROP/DELETE only move pages to the freelist and SQLite
# keeps their old bytes (plaintext emails, for 0002) in the file until reused.
VACUUM_MARKER = "-- guardpost:vacuum-after"


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str

    @property
    def vacuum_after(self) -> bool:
        return any(line.strip() == VACUUM_MARKER for line in self.sql.splitlines())


def sqlite_migrations() -> list[Migration]:
    """All bundled SQLite migrations, in version order."""
    out = []
    for entry in resources.files(__name__).joinpath("sqlite").iterdir():
        match = _FILENAME_RE.match(entry.name)
        if not match:
            continue
        out.append(Migration(int(match.group(1)), match.group(2), entry.read_text(encoding="utf-8")))
    out.sort(key=lambda m: m.version)
    versions = [m.version for m in out]
    if len(set(versions)) != len(versions):
        raise MigrationError(f"duplicate migration versions: {versions}")
    return out


def split_statements(script: str) -> list[str]:
    """Split a SQL script into single statements.

    ``sqlite3.complete_statement`` understands quoting, comments and trigger
    bodies, so a ``;`` inside any of them does not end a statement. Executing
    statement by statement (instead of ``executescript``, which commits any
    open transaction first) keeps the whole migration in one transaction.
    """
    statements: list[str] = []
    buf = ""
    for line in script.splitlines(keepends=True):
        buf += line
        if sqlite3.complete_statement(buf):
            if _has_sql(buf):
                statements.append(buf.strip())
            buf = ""
    if _has_sql(buf):
        raise MigrationError(f"incomplete SQL statement at end of script: {buf.strip()[:80]!r}")
    return statements


def _has_sql(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("--") and stripped != ";":
            return True
    return False


def _bootstrap(conn: sqlite3.Connection, params: Mapping[str, str]) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        " version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )
    conn.execute("CREATE TABLE IF NOT EXISTS gp_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    for key, value in params.items():
        conn.execute("INSERT OR IGNORE INTO gp_meta (key, value) VALUES (?, ?)", (key, value))


def applied_versions(conn: sqlite3.Connection) -> set[int]:
    try:
        return {row[0] for row in conn.execute("SELECT version FROM schema_migrations")}
    except sqlite3.OperationalError:
        return set()


def schema_version(conn: sqlite3.Connection) -> int:
    """Highest applied migration version (0 for a database never migrated)."""
    return max(applied_versions(conn), default=0)


def pending_sqlite_migrations(conn: sqlite3.Connection) -> list[Migration]:
    done = applied_versions(conn)
    return [m for m in sqlite_migrations() if m.version not in done]


def apply_sqlite_migrations(
    conn: sqlite3.Connection,
    params: Mapping[str, str] | None = None,
) -> list[Migration]:
    """Apply every pending migration. Returns the ones applied by this call.

    ``conn`` must be in autocommit mode (``isolation_level=None``): the runner
    issues its own BEGIN/COMMIT. Safe to call concurrently from two processes:
    each migration re-checks ``schema_migrations`` after taking the write lock.
    """
    if conn.isolation_level is not None:
        raise MigrationError("apply_sqlite_migrations needs a connection with isolation_level=None")

    conn.execute("BEGIN IMMEDIATE")
    try:
        _bootstrap(conn, params or {})
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise

    applied: list[Migration] = []
    for migration in sqlite_migrations():
        conn.execute("BEGIN IMMEDIATE")
        try:
            already = conn.execute(
                "SELECT 1 FROM schema_migrations WHERE version = ?", (migration.version,)
            ).fetchone()
            if already:
                conn.execute("COMMIT")
                continue
            for statement in split_statements(migration.sql):
                conn.execute(statement)
            conn.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                (migration.version, migration.name, datetime.now(UTC).isoformat()),
            )
            conn.execute("COMMIT")
        except Exception as exc:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise MigrationError(
                f"migration {migration.version:04d}_{migration.name} failed: {exc}"
            ) from exc
        applied.append(migration)
    if any(m.vacuum_after for m in applied):
        purge_free_pages(conn)
    return applied


def purge_free_pages(conn: sqlite3.Connection) -> int:
    """Rewrite the database without free pages; returns how many there were.

    ``VACUUM`` rebuilds the file from live rows only, and the TRUNCATE
    checkpoint moves the result into the main file and empties the WAL, so
    no deleted bytes are left in either (or in a later Litestream snapshot).
    Needs autocommit mode and no open transaction.
    """
    free = conn.execute("PRAGMA freelist_count").fetchone()[0]
    conn.execute("VACUUM")
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    return free
