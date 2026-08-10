"""Tests for IP reputation engine."""

import pytest

from guardpost.ip.reputation import (
    DEFAULT_BLACKLIST_SUSPICIOUS_THRESHOLD,
    DEFAULT_GRAYLIST_SUSPICIOUS_THRESHOLD,
    IPReputationEngine,
    IPReputationRecord,
    subnet_key,
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


@pytest.mark.asyncio
class TestSubnetReputation:
    """A /24 layer exists because per-IP reputation is blind to rotating pools.

    In factory_ru (Aug 2026) six /24 blocks produced 45 registrations from 45
    distinct IPs. Every per-IP counter stayed at 1, so nothing ever tripped.
    """

    async def test_subnet_key_for_ipv4(self):
        assert subnet_key("185.193.158.79") == "185.193.158.0/24"
        assert subnet_key("64.238.203.1") == "64.238.203.0/24"

    async def test_subnet_key_skips_ipv6_and_junk(self):
        # A single household routinely holds a whole IPv6 /64, so no prefix
        # there carries the meaning a /24 does.
        assert subnet_key("2001:db8::1") is None
        assert subnet_key("not-an-ip") is None
        assert subnet_key("") is None

    async def test_rotating_pool_caught_while_every_ip_stays_clean(self, engine):
        # The real signature: one suspicious registration per address.
        for host in range(70, 78):
            await engine.record_registration(f"185.193.158.{host}", is_suspicious=True)

        for host in range(70, 78):
            ip_status, _ = await engine.check_ip(f"185.193.158.{host}")
            assert ip_status == "clean", host

        status, reason = await engine.check_subnet("185.193.158.79")
        assert status == "graylisted"
        assert reason is not None

    async def test_subnet_stays_clean_below_the_threshold(self, engine):
        for host in range(1, 8):
            await engine.record_registration(f"10.0.5.{host}", is_suspicious=True)
        status, _ = await engine.check_subnet("10.0.5.99")
        assert status == "clean"

    async def test_subnet_thresholds_are_higher_than_per_ip(self, engine):
        # A /24 is shared by strangers — CGNAT, campuses, small ISPs — so the
        # innocent-neighbour cost is real and the bar must sit higher.
        assert engine._subnet_thresholds.graylist_suspicious > engine.graylist_suspicious
        assert engine._subnet_thresholds.blacklist_suspicious > engine.blacklist_suspicious

    async def test_whitelisted_ip_is_exempt_from_its_neighbours(self, engine):
        for host in range(70, 78):
            await engine.record_registration(f"185.193.158.{host}", is_suspicious=True)
        await engine.whitelist_ip("185.193.158.70", "admin", "corporate VPN")

        assert (await engine.check_subnet("185.193.158.70"))[0] == "clean"
        assert (await engine.check_subnet("185.193.158.71"))[0] == "graylisted"

    async def test_per_ip_record_is_still_what_is_returned(self, engine):
        record = await engine.record_registration("1.2.3.4", is_suspicious=False)
        assert record.ip_address == "1.2.3.4"
        assert record.total_registrations == 1

    async def test_subnet_tracking_can_be_disabled(self, storage):
        off = IPReputationEngine(storage, track_subnets=False)
        for host in range(70, 90):
            await off.record_registration(f"185.193.158.{host}", is_suspicious=True)
        assert await off.check_subnet("185.193.158.79") == ("clean", None)
        assert await storage.get_ip_reputation("185.193.158.0/24") is None

    async def test_ipv6_registration_does_not_create_a_subnet_record(self, engine, storage):
        await engine.record_registration("2001:db8::1", is_suspicious=True)
        assert await engine.check_subnet("2001:db8::1") == ("clean", None)
