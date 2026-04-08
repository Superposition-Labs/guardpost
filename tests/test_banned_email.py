"""Tests for banned email system."""

import pytest

from guardpost.email.banned import BannedEmailEngine
from guardpost.storage.memory import MemoryStorage


@pytest.fixture
def storage():
    return MemoryStorage()


@pytest.fixture
def engine(storage):
    return BannedEmailEngine(storage)


@pytest.mark.asyncio
class TestBannedEmailEngine:
    async def test_not_banned_by_default(self, engine):
        assert await engine.is_banned("user@example.com") is False

    async def test_ban_and_check(self, engine):
        await engine.ban("user@example.com", banned_by="admin", reason="abuse")
        assert await engine.is_banned("user@example.com") is True

    async def test_ban_idempotent(self, engine):
        r1 = await engine.ban("user@example.com")
        r2 = await engine.ban("user@example.com")
        assert r1.normalized_email_hash == r2.normalized_email_hash

    async def test_unban(self, engine):
        await engine.ban("user@example.com")
        assert await engine.is_banned("user@example.com") is True

        result = await engine.unban("user@example.com")
        assert result is True
        assert await engine.is_banned("user@example.com") is False

    async def test_unban_nonexistent(self, engine):
        result = await engine.unban("nobody@example.com")
        assert result is False

    async def test_gmail_normalization(self, engine):
        """Banning j.o.h.n@gmail.com also bans john@gmail.com."""
        await engine.ban("j.o.h.n@gmail.com")
        assert await engine.is_banned("john@gmail.com") is True
        assert await engine.is_banned("j.o.h.n+tag@gmail.com") is True

    async def test_case_insensitive(self, engine):
        await engine.ban("User@Example.COM")
        assert await engine.is_banned("user@example.com") is True
