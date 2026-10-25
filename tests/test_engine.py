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


@pytest.mark.asyncio
class TestWeakSignalVerdict:
    """A weak reason raises the score but must never decide the verdict."""

    async def test_relay_scores_without_condemning(self, gp):
        result = await gp.check("user@duck.com")
        assert result.is_suspicious is False
        assert result.risk_score > 0
        assert "relay_domain" in result.reasons
        assert "relay_domain" in result.weak_reasons

    async def test_weak_reasons_are_a_subset_of_reasons(self, gp):
        result = await gp.check("user@duck.com")
        assert set(result.weak_reasons) <= set(result.reasons)

    async def test_hard_reason_still_condemns(self, gp):
        # Not "test@": that is an extended role prefix, itself a weak reason.
        result = await gp.check("someone@mailinator.com")
        assert result.is_suspicious is True
        assert result.weak_reasons == []

    async def test_dot_noise_is_hard(self, gp):
        # Verbatim from factory_ru — 71 such accounts, none of which ever paid.
        result = await gp.check("pe.llig.rino.phi.lip.os.e7.60@gmail.com")
        assert result.is_suspicious is True
        assert "dot_noise_local" in result.reasons
        assert result.risk_score >= 30

    async def test_ordinary_gmail_unaffected(self, gp):
        result = await gp.check("ivan.petrov@gmail.com")
        assert result.is_suspicious is False
        assert result.risk_score == 0

    async def test_weak_reasons_survive_serialization(self, gp):
        payload = (await gp.check("user@duck.com")).to_dict()
        assert payload["weak_reasons"] == ["relay_domain"]
        assert payload["is_suspicious"] is False
        assert payload["subnet_status"] == "clean"


@pytest.mark.asyncio
class TestSubnetBurstReason:
    async def test_rotating_pool_flagged_on_a_clean_ip(self, gp):
        # Eight suspicious registrations, one per address — no per-IP counter
        # ever moves, so only the /24 layer can see this.
        for host in range(70, 78):
            await gp.check("test@mailinator.com", ip_address=f"185.193.158.{host}")

        result = await gp.check("realuser@gmail.com", ip_address="185.193.158.90")
        assert result.subnet_status == "graylisted"
        assert "subnet_burst:185.193.158.0/24" in result.reasons
        assert result.is_suspicious is True

    async def test_quiet_subnet_adds_nothing(self, gp):
        result = await gp.check("realuser@gmail.com", ip_address="8.8.8.8")
        assert result.subnet_status == "clean"
        assert result.reasons == []
        assert result.is_suspicious is False


@pytest.mark.asyncio
class TestTrustedExtraAndTypoSource:
    async def test_engine_trusts_configured_extras(self):
        from guardpost.email.validator import _mx_host_cache, clear_caches

        clear_caches()
        _mx_host_cache["factory.bot"] = None
        try:
            plain = Guardpost(storage=MemoryStorage(), trusted_extra_domains=())
            factory = Guardpost(storage=MemoryStorage(), trusted_extra_domains="factory.bot,deleted.local")
            assert "no_mx_records" in (await plain.check("telegram_1@factory.bot")).reasons
            result = await factory.check("telegram_1@factory.bot")
            assert result.reasons == []
            assert result.is_suspicious is False
            assert (await factory.is_suspicious("telegram_1@factory.bot")) == (False, [])
        finally:
            clear_caches()

    async def test_engine_reads_env_by_default(self, monkeypatch):
        monkeypatch.setenv("GUARDPOST_TRUSTED_EXTRA_DOMAINS", "factory.bot")
        assert Guardpost(storage=MemoryStorage()).trusted_extra_domains == {"factory.bot"}

    async def test_typo_source_in_result(self, gp):
        result = await gp.check("x@googlemail.con")
        assert "typo_domain" in result.reasons
        assert result.suggested_domain == "googlemail.com"
        assert result.typo_source == "tld"
        assert result.to_dict()["typo_source"] == "tld"

    async def test_no_typo_fields_on_a_clean_address(self, gp):
        result = await gp.check("realuser@gmail.com")
        assert result.suggested_domain is None
        assert result.typo_source is None
