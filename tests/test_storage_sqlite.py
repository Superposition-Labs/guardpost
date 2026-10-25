"""Tests for SQLite storage backend."""

import pytest

from guardpost.email.banned import BannedEmailRecord
from guardpost.ip.reputation import IPReputationRecord
from guardpost.storage.sqlite import SQLiteStorage


@pytest.fixture
async def storage(tmp_path):
    db_path = tmp_path / "test.db"
    s = SQLiteStorage(db_path)
    await s.initialize()
    yield s
    await s.close()


@pytest.mark.asyncio
class TestSQLiteStorage:
    async def test_ip_reputation_round_trip(self, storage):
        record = IPReputationRecord(
            ip_address="1.2.3.4", total_registrations=3)
        await storage.save_ip_reputation(record)

        loaded = await storage.get_ip_reputation("1.2.3.4")
        assert loaded is not None
        assert loaded.ip_address == "1.2.3.4"
        assert loaded.total_registrations == 3

    async def test_ip_reputation_not_found(self, storage):
        assert await storage.get_ip_reputation("9.9.9.9") is None

    async def test_ip_reputation_upsert(self, storage):
        record = IPReputationRecord(
            ip_address="1.1.1.1", total_registrations=1)
        await storage.save_ip_reputation(record)

        record.total_registrations = 5
        await storage.save_ip_reputation(record)

        loaded = await storage.get_ip_reputation("1.1.1.1")
        assert loaded.total_registrations == 5

    async def test_banned_email_round_trip(self, storage):
        record = BannedEmailRecord(
            normalized_email_hash="abc123",
        )
        await storage.save_banned_email(record)

        assert await storage.is_email_banned("abc123") is True
        loaded = await storage.get_banned_email("abc123")
        assert loaded is not None
        assert loaded.normalized_email_hash == "abc123"

    async def test_banned_email_not_found(self, storage):
        assert await storage.is_email_banned("nonexistent") is False
        assert await storage.get_banned_email("nonexistent") is None

    async def test_delete_banned_email(self, storage):
        record = BannedEmailRecord(
            normalized_email_hash="del123",
        )
        await storage.save_banned_email(record)
        assert await storage.is_email_banned("del123") is True

        result = await storage.delete_banned_email("del123")
        assert result is True
        assert await storage.is_email_banned("del123") is False

    async def test_delete_nonexistent(self, storage):
        result = await storage.delete_banned_email("nope")
        assert result is False

    async def test_registrations_are_not_persisted_in_plaintext(self, storage):
        import sqlite3
        import time

        from guardpost.fraud.patterns import Registration

        now = time.time()
        await storage.save_registration(Registration(
            email="someone@example.com", username="someone", domain="example.com",
            ip_address="1.2.3.4", timestamp=now))

        # 0.3: counted (timeline, stats) but the email is never written.
        assert await storage.get_recent_registrations(now - 10) == []
        timeline = await storage.get_registration_timeline(now - 10, 60)
        assert sum(b["count"] for b in timeline) == 1
        assert (await storage.get_stats())["total_registrations"] == 1

        raw = sqlite3.connect(str(storage.db_path))
        tables = {r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert "registrations" not in tables
        dump = "\n".join(raw.iterdump())
        assert "someone@example.com" not in dump and "1.2.3.4" not in dump
