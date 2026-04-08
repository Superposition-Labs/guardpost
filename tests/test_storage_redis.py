"""Tests for Redis 8 storage backend.

Requires a running Redis 8 instance. Set TEST_REDIS_URL env var to override
the default ``redis://localhost:6379/15``.

Run with:
    TEST_REDIS_URL=redis://localhost:6379/15 pytest tests/test_storage_redis.py -v
"""

import os
import time

import pytest

from guardpost.email.banned import BannedEmailRecord
from guardpost.fraud.patterns import Registration
from guardpost.ip.reputation import IPReputationRecord

REDIS_URL = os.environ.get("TEST_REDIS_URL", "redis://localhost:6379/15")


def _redis_available() -> bool:
    try:
        import redis

        r = redis.from_url(REDIS_URL)
        r.ping()
        r.close()
        return True
    except Exception:
        return False


pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not _redis_available(),
        reason="Redis not available — set TEST_REDIS_URL",
    ),
]


@pytest.fixture
async def storage():
    from guardpost.storage.redis import RedisStorage

    s = RedisStorage(REDIS_URL)
    # Flush test DB before each test
    await s._redis.flushdb()
    await s.initialize()
    yield s
    await s._redis.flushdb()
    await s.close()


class TestRedisIPReputation:
    async def test_round_trip(self, storage):
        record = IPReputationRecord(
            ip_address="1.2.3.4", total_registrations=3)
        await storage.save_ip_reputation(record)

        loaded = await storage.get_ip_reputation("1.2.3.4")
        assert loaded is not None
        assert loaded.ip_address == "1.2.3.4"
        assert loaded.total_registrations == 3

    async def test_not_found(self, storage):
        assert await storage.get_ip_reputation("9.9.9.9") is None

    async def test_upsert(self, storage):
        record = IPReputationRecord(
            ip_address="1.1.1.1", total_registrations=1)
        await storage.save_ip_reputation(record)

        record.total_registrations = 5
        await storage.save_ip_reputation(record)

        loaded = await storage.get_ip_reputation("1.1.1.1")
        assert loaded.total_registrations == 5


class TestRedisBannedEmails:
    async def test_round_trip(self, storage):
        record = BannedEmailRecord(normalized_email_hash="abc123")
        await storage.save_banned_email(record)

        assert await storage.is_email_banned("abc123") is True
        loaded = await storage.get_banned_email("abc123")
        assert loaded is not None
        assert loaded.normalized_email_hash == "abc123"

    async def test_not_found(self, storage):
        assert await storage.is_email_banned("nonexistent") is False
        assert await storage.get_banned_email("nonexistent") is None

    async def test_bloom_filter_fast_negative(self, storage):
        """Bloom filter returns definite negatives without JSON lookup."""
        assert await storage.is_email_banned("never_added") is False

    async def test_delete(self, storage):
        record = BannedEmailRecord(normalized_email_hash="del123")
        await storage.save_banned_email(record)
        assert await storage.is_email_banned("del123") is True

        result = await storage.delete_banned_email("del123")
        assert result is True
        assert await storage.get_banned_email("del123") is None

    async def test_delete_nonexistent(self, storage):
        result = await storage.delete_banned_email("nope")
        assert result is False


class TestRedisRegistrations:
    async def test_save_and_get_recent(self, storage):
        now = time.time()
        reg1 = Registration(
            email="a@b.com", username="a", domain="b.com",
            ip_address="1.2.3.4", timestamp=now,
        )
        reg2 = Registration(
            email="c@d.com", username="c", domain="d.com",
            ip_address="5.6.7.8", timestamp=now + 1,
        )
        old = Registration(
            email="old@old.com", username="old", domain="old.com",
            timestamp=now - 7200,
        )

        await storage.save_registration(old)
        await storage.save_registration(reg1)
        await storage.save_registration(reg2)

        recent = await storage.get_recent_registrations(now - 8000)
        assert len(recent) == 3

        recent_only = await storage.get_recent_registrations(now - 1)
        assert len(recent_only) == 2

    async def test_purge_old(self, storage):
        now = time.time()
        old = Registration(
            email="old@old.com", username="old", domain="old.com",
            timestamp=now - 7200,
        )
        new = Registration(
            email="new@new.com", username="new", domain="new.com",
            timestamp=now,
        )
        await storage.save_registration(old)
        await storage.save_registration(new)

        purged = await storage.purge_old_registrations(now - 3600)
        assert purged == 1

        remaining = await storage.get_recent_registrations(0)
        assert len(remaining) == 1
        assert remaining[0].email == "new@new.com"

    async def test_timeline(self, storage):
        now = time.time()
        for i in range(5):
            reg = Registration(
                email=f"user{i}@test.com", username=f"user{i}",
                domain="test.com", timestamp=now + i,
            )
            await storage.save_registration(reg)

        timeline = await storage.get_registration_timeline(now - 10, bucket_seconds=3600)
        assert len(timeline) >= 1
        total = sum(b["count"] for b in timeline)
        assert total == 5


class TestRedisStats:
    async def test_empty_stats(self, storage):
        stats = await storage.get_stats()
        assert stats["total_ips"] == 0
        assert stats["total_banned_emails"] == 0

    async def test_stats_with_data(self, storage):
        await storage.save_ip_reputation(
            IPReputationRecord(
                ip_address="1.1.1.1", status="graylisted",
                total_registrations=10, suspicious_registrations=2,
            )
        )
        await storage.save_ip_reputation(
            IPReputationRecord(
                ip_address="2.2.2.2", status="blacklisted",
                total_registrations=50, suspicious_registrations=20,
            )
        )
        await storage.save_banned_email(
            BannedEmailRecord(normalized_email_hash="banned1")
        )

        # Give the search index a moment to update
        import asyncio
        await asyncio.sleep(0.5)

        stats = await storage.get_stats()
        assert stats["total_ips"] == 2
        assert stats["graylisted_ips"] == 1
        assert stats["blacklisted_ips"] == 1
        assert stats["total_banned_emails"] == 1
        assert stats["total_registrations"] == 60
        assert stats["total_suspicious_registrations"] == 22


class TestRedisRateLimiter:
    async def test_allows_within_limit(self, storage):
        for _ in range(5):
            assert await storage.rate_limit_check("test_ip", 10, 60.0) is True

    async def test_blocks_over_limit(self, storage):
        for _ in range(3):
            await storage.rate_limit_check("blocked_ip", 3, 60.0)
        assert await storage.rate_limit_check("blocked_ip", 3, 60.0) is False

    async def test_separate_keys(self, storage):
        for _ in range(3):
            await storage.rate_limit_check("ip_a", 3, 60.0)
        # ip_a is exhausted, but ip_b should still be allowed
        assert await storage.rate_limit_check("ip_b", 3, 60.0) is True


class TestRedisAICache:
    async def test_cache_miss(self, storage):
        assert await storage.get_ai_cache("nonexistent") is None

    async def test_cache_round_trip(self, storage):
        data = {
            "email": "test@example.com",
            "risk_score": 75,
            "confidence": 0.9,
            "reasons": ["suspicious"],
            "analysis": "test",
            "model": "test-model",
            "cached": False,
        }
        await storage.set_ai_cache("test_key", data, ttl_seconds=60)
        loaded = await storage.get_ai_cache("test_key")
        assert loaded is not None
        assert loaded["risk_score"] == 75
        assert loaded["email"] == "test@example.com"


class TestRedisProbabilistic:
    async def test_top_ips(self, storage):
        now = time.time()
        for i in range(10):
            reg = Registration(
                email=f"user{i}@test.com", username=f"user{i}",
                domain="test.com", ip_address="10.0.0.1", timestamp=now + i,
            )
            await storage.save_registration(reg)

        top = await storage.get_top_ips()
        assert "10.0.0.1" in top

    async def test_ip_frequency(self, storage):
        now = time.time()
        for i in range(5):
            reg = Registration(
                email=f"u{i}@t.com", username=f"u{i}", domain="t.com",
                ip_address="10.0.0.2", timestamp=now + i,
            )
            await storage.save_registration(reg)

        freq = await storage.get_ip_frequency("10.0.0.2")
        assert freq >= 5  # CMS may over-count, never under-count
