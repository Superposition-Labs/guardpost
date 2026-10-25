"""Upgrading a Guardpost 0.2 SQLite database to the tenancy schema."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from guardpost.api.server import create_app
from guardpost.email.validator import normalize_email
from guardpost.storage.migrations import schema_version, sqlite_migrations
from guardpost.storage.sqlite import SQLiteStorage
from guardpost.tenancy import keys
from guardpost.tenancy.models import Tenant

# Verbatim from guardpost 0.2.0 SQLiteStorage._initialize_sync.
SCHEMA_02 = """
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

BANNED = "banned.person@gmail.com"


def _sha(email: str) -> str:
    """How 0.2 keyed a ban: sha256 of the normalized address."""
    return hashlib.sha256(normalize_email(email).encode()).hexdigest()


def _ip_row(key: str, total: int, suspicious: int, status: str = "clean", whitelisted: bool = False) -> tuple:
    data = {
        "ip_address": key, "total_registrations": total, "suspicious_registrations": suspicious,
        "first_registration_at": "2026-08-01T10:00:00+00:00", "last_registration_at": "2026-09-01T10:00:00+00:00",
        "status": status, "status_reason": None, "status_changed_at": None,
        "manually_whitelisted": whitelisted, "whitelisted_by": None, "whitelist_reason": None,
    }
    return key, json.dumps(data)


@pytest.fixture
def db_02(tmp_path):
    """A database exactly as Guardpost 0.2 left it, with data in every table."""
    path = tmp_path / "guardpost.db"
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA_02)
    conn.executemany("INSERT INTO ip_reputation VALUES (?, ?)", [
        _ip_row("198.51.100.7", 12, 6, "graylisted"),
        _ip_row("198.51.100.8", 3, 0),
        _ip_row("198.51.100.0/24", 15, 6),  # /24 rows: not counted again
        _ip_row("2001:db8::1", 2, 1),
        _ip_row("192.0.2.1", 0, 0, whitelisted=True),
    ])
    conn.executemany("INSERT INTO banned_emails VALUES (?, ?)", [
        (_sha(BANNED), json.dumps({"normalized_email_hash": _sha(BANNED), "banned_at": "2026-09-10T12:00:00+00:00",
                                   "banned_by": "admin", "reason": "referral farm"})),
        (_sha("other@yandex.ru"), json.dumps({"normalized_email_hash": _sha("other@yandex.ru"),
                                              "banned_at": "2026-09-11T12:00:00+00:00",
                                              "banned_by": None, "reason": None})),
    ])
    now = time.time()
    conn.executemany(
        "INSERT INTO registrations (email, username, domain, ip_address, timestamp) VALUES (?, ?, ?, ?, ?)",
        [("plain.text.victim@gmail.com", "plain.text.victim", "gmail.com", "198.51.100.7", now - 60),
         ("second.victim@mail.ru", "second.victim", "mail.ru", "198.51.100.8", now - 30)],
    )
    conn.commit()
    conn.close()
    return path


def test_upgrade_from_02(db_02):
    storage = SQLiteStorage(db_02, legacy_tenant="factory")
    asyncio.run(storage.initialize())

    conn = sqlite3.connect(str(db_02))
    assert schema_version(conn) == sqlite_migrations()[-1].version
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"tenants", "api_keys", "bans", "registration_events", "tenant_counters", "schema_migrations"} <= tables
    # The plaintext registrations and the global ban list are gone.
    assert "registrations" not in tables and "banned_emails" not in tables
    dump = "\n".join(conn.iterdump())
    assert "victim" not in dump

    async def inspect():
        try:
            tenant = await storage.get_tenant("factory")
            assert tenant is not None and tenant.active
            assert await storage.get_meta("legacy_tenant") == "factory"
            # Bans moved to the legacy tenant, details intact.
            assert await storage.is_email_banned(_sha(BANNED), tenant_id="factory")
            assert await storage.is_email_banned(_sha(BANNED))  # None -> legacy tenant
            record = await storage.get_banned_email(_sha(BANNED), tenant_id="factory")
            assert (record.banned_by, record.reason) == ("admin", "referral farm")
            assert record.banned_at.isoformat() == "2026-09-10T12:00:00+00:00"
            # Shared IP reputation untouched.
            ip = await storage.get_ip_reputation("198.51.100.7")
            assert (ip.total_registrations, ip.status) == (12, "graylisted")
            assert (await storage.get_ip_reputation("192.0.2.1")).manually_whitelisted
            # All-time counters carried over from the per-IP rows (no /24 double count).
            stats = await storage.get_tenant_stats("factory")
            assert stats["total_registrations"] == 12 + 3 + 2
            assert stats["total_suspicious_registrations"] == 6 + 1
            assert stats["total_banned_emails"] == 2
        finally:
            await storage.close()

    asyncio.run(inspect())

    # Running again is a no-op.
    again = SQLiteStorage(db_02, legacy_tenant="factory")
    assert again.migrate() == []


def test_upgraded_database_serves_v1_clients(db_02, clean_env):
    clean_env.setenv("GUARDPOST_LEGACY_TENANT", "factory")
    legacy = "v1-shared-key"
    with TestClient(create_app(db_path=str(db_02), api_key=legacy)) as client:
        headers = {"X-Api-Key": legacy}
        body = client.post("/api/v1/check", json={"email": BANNED, "record_ip": False}, headers=headers).json()
        assert body["is_banned"] is True and body["risk_score"] == 100
        assert client.post("/api/v1/ip/check", json={"ip_address": "198.51.100.7"},
                           headers=headers).json()["status"] == "graylisted"
        assert client.get("/api/v1/stats", headers=headers).json()["total_banned_emails"] == 2

    async def add_tenant():
        storage = SQLiteStorage(db_02, legacy_tenant="factory")
        await storage.initialize()
        try:
            await storage.create_tenant(Tenant(id="newco", name="NewCo"))
            plaintext, _ = await keys.create_key(storage, "newco", "check,dashboard")
            return plaintext
        finally:
            await storage.close()

    newco = asyncio.run(add_tenant())
    with TestClient(create_app(db_path=str(db_02), api_key=legacy)) as client:
        headers = {"X-Api-Key": newco}
        body = client.post("/api/v1/check", json={"email": BANNED, "record_ip": False}, headers=headers).json()
        assert body["is_banned"] is False
        assert client.get("/api/v1/stats", headers=headers).json()["total_banned_emails"] == 0


def test_legacy_tenant_defaults_to_default(db_02):
    storage = SQLiteStorage(db_02)
    asyncio.run(storage.initialize())

    async def inspect():
        try:
            assert await storage.is_email_banned(_sha(BANNED), tenant_id="default")
        finally:
            await storage.close()

    asyncio.run(inspect())
