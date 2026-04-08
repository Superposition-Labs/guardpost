"""Tests for IP reputation engine."""

import pytest

from guardpost.ip.reputation import (
    DEFAULT_BLACKLIST_SUSPICIOUS_THRESHOLD,
    DEFAULT_GRAYLIST_SUSPICIOUS_THRESHOLD,
    IPReputationEngine,
    IPReputationRecord,
)
from guardpost.storage.memory import MemoryStorage


@pytest.fixture
def storage():
    return MemoryStorage()


@pytest.fixture
def engine(storage):
    return IPReputationEngine(storage)


@pytest.mark.asyncio
class TestIPReputationEngine:
    async def test_clean_ip_by_default(self, engine):
        status, reason = await engine.check_ip("1.2.3.4")
        assert status == "clean"
        assert reason is None

    async def test_record_clean_registration(self, engine):
        record = await engine.record_registration("1.2.3.4", is_suspicious=False)
        assert record.total_registrations == 1
        assert record.suspicious_registrations == 0
        assert record.status == "clean"

    async def test_record_suspicious_registration(self, engine):
        record = await engine.record_registration("1.2.3.4", is_suspicious=True)
        assert record.suspicious_registrations == 1

    async def test_graylist_after_threshold(self, engine):
        ip = "10.0.0.1"
        for _ in range(DEFAULT_GRAYLIST_SUSPICIOUS_THRESHOLD):
            record = await engine.record_registration(ip, is_suspicious=True)
        assert record.status == "graylisted"

    async def test_blacklist_after_threshold(self, engine):
        ip = "10.0.0.2"
        for _ in range(DEFAULT_BLACKLIST_SUSPICIOUS_THRESHOLD):
            record = await engine.record_registration(ip, is_suspicious=True)
        assert record.status == "blacklisted"

    async def test_whitelist_overrides_status(self, engine):
        ip = "10.0.0.3"
        for _ in range(DEFAULT_BLACKLIST_SUSPICIOUS_THRESHOLD):
            await engine.record_registration(ip, is_suspicious=True)

        status, _ = await engine.check_ip(ip)
        assert status == "blacklisted"

        await engine.whitelist_ip(ip, whitelisted_by="admin", reason="corporate VPN")
        status, _ = await engine.check_ip(ip)
        assert status == "clean"

    async def test_check_ip_after_record(self, engine):
        await engine.record_registration("2.3.4.5", is_suspicious=False)
        status, reason = await engine.check_ip("2.3.4.5")
        assert status == "clean"

    async def test_custom_thresholds(self, storage):
        engine = IPReputationEngine(storage, graylist_suspicious=2, blacklist_suspicious=3)
        ip = "5.5.5.5"
        await engine.record_registration(ip, is_suspicious=True)
        status, _ = await engine.check_ip(ip)
        assert status == "clean"

        await engine.record_registration(ip, is_suspicious=True)
        status, _ = await engine.check_ip(ip)
        assert status == "graylisted"

        await engine.record_registration(ip, is_suspicious=True)
        status, _ = await engine.check_ip(ip)
        assert status == "blacklisted"


class TestIPReputationRecordSerialization:
    def test_round_trip(self):
        record = IPReputationRecord(ip_address="1.1.1.1", total_registrations=5)
        data = record.to_dict()
        restored = IPReputationRecord.from_dict(data)
        assert restored.ip_address == "1.1.1.1"
        assert restored.total_registrations == 5
