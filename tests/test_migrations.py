"""SQLite migration runner."""

import sqlite3

import pytest

from guardpost.storage.migrations import (
    MigrationError,
    apply_sqlite_migrations,
    schema_version,
    split_statements,
    sqlite_migrations,
)


def _conn(path):
    return sqlite3.connect(str(path), isolation_level=None)


def test_bundled_migrations_are_numbered_from_one():
    versions = [m.version for m in sqlite_migrations()]
    assert versions[0] == 1
    assert versions == sorted(versions) == list(range(1, len(versions) + 1))


def test_fresh_database_reaches_latest(tmp_path):
    conn = _conn(tmp_path / "fresh.db")
    applied = apply_sqlite_migrations(conn)
    assert [m.version for m in applied] == [m.version for m in sqlite_migrations()]
    assert schema_version(conn) == sqlite_migrations()[-1].version
    # Idempotent: a second run applies nothing.
    assert apply_sqlite_migrations(conn) == []


def test_failed_migration_rolls_back(tmp_path, monkeypatch):
    from guardpost.storage import migrations

    conn = _conn(tmp_path / "bad.db")
    apply_sqlite_migrations(conn)
    latest = schema_version(conn)
    bad = migrations.Migration(latest + 1, "broken", "CREATE TABLE t_ok (x);\nINSERT INTO nope VALUES (1);\n")
    monkeypatch.setattr(migrations, "sqlite_migrations", lambda: [*sqlite_migrations(), bad])
    with pytest.raises(MigrationError):
        apply_sqlite_migrations(conn)
    assert schema_version(conn) == latest
    assert conn.execute("SELECT name FROM sqlite_master WHERE name = 't_ok'").fetchone() is None


def test_params_recorded_first_value_wins(tmp_path):
    conn = _conn(tmp_path / "meta.db")
    apply_sqlite_migrations(conn, {"k": "first"})
    apply_sqlite_migrations(conn, {"k": "second"})
    assert conn.execute("SELECT value FROM gp_meta WHERE key = 'k'").fetchone()[0] == "first"


def test_split_statements_respects_strings_and_comments():
    script = "-- a; comment\nCREATE TABLE a (x TEXT DEFAULT 'a;b');\n\nINSERT INTO a VALUES ('1');\n-- trailing\n"
    assert split_statements(script) == [
        "-- a; comment\nCREATE TABLE a (x TEXT DEFAULT 'a;b');",
        "INSERT INTO a VALUES ('1');",
    ]


def test_requires_autocommit_connection(tmp_path):
    with pytest.raises(MigrationError):
        apply_sqlite_migrations(sqlite3.connect(str(tmp_path / "x.db")))
