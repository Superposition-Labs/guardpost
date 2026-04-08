"""Tests for the main Guardpost engine."""

import pytest

from guardpost.engine import Guardpost
from guardpost.storage.memory import MemoryStorage


@pytest.fixture
async def gp():
    engine = Guardpost(storage=MemoryStorage())
    await engine.initialize()
    yield engine
    await engine.close()


@pytest.mark.asyncio
class TestGuardpostEngine:
    async def test_clean_email(self, gp):
        result = await gp.check("realuser@gmail.com")
        assert result.is_suspicious is False
        assert result.risk_score == 0
        assert result.is_banned is False

    async def test_disposable_email(self, gp):
        result = await gp.check("test@mailinator.com")
        assert result.is_suspicious is True
        assert result.risk_score > 0
        assert "disposable_domain" in result.reasons

    async def test_banned_email(self, gp):
        await gp.ban_email("bad@example.com", reason="abuse")
        result = await gp.check("bad@example.com")
        assert result.is_banned is True
        assert result.risk_score == 100

    async def test_ip_tracking(self, gp):
        for _ in range(5):
            await gp.check("x@mailinator.com", ip_address="10.0.0.1")
        status, _ = await gp.check_ip("10.0.0.1")
        assert status == "graylisted"

    async def test_normalize_email(self, gp):
        assert gp.normalize_email("U.S.E.R+tag@gmail.com") == "user@gmail.com"

    async def test_check_result_to_dict(self, gp):
        result = await gp.check("user@gmail.com")
        d = result.to_dict()
        assert "email" in d
        assert "risk_score" in d
        assert "reasons" in d

    async def test_whitelist_ip(self, gp):
        # Blacklist the IP first
        for _ in range(8):
            await gp.check("x@yopmail.com", ip_address="10.0.0.2")
        status, _ = await gp.check_ip("10.0.0.2")
        assert status == "blacklisted"

        # Whitelist it
        await gp.whitelist_ip("10.0.0.2", "admin", "office network")
        status, _ = await gp.check_ip("10.0.0.2")
        assert status == "clean"

    async def test_no_record_ip(self, gp):
        await gp.check("test@mailinator.com", ip_address="10.0.0.3", record_ip=False)
        status, _ = await gp.check_ip("10.0.0.3")
        assert status == "clean"
