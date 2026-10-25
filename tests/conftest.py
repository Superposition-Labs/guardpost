"""Shared fixtures: an isolated environment for every API test."""

import pytest

GUARDPOST_ENV = (
    "GUARDPOST_API_KEY", "GUARDPOST_REDIS_URL", "GUARDPOST_RATE_LIMIT", "GUARDPOST_TRUSTED_PROXIES",
    "GUARDPOST_ENABLE_METRICS", "GUARDPOST_METRICS_PORT", "GUARDPOST_TRUSTED_EXTRA_DOMAINS",
    "GUARDPOST_ALLOW_OPEN", "GUARDPOST_LEGACY_TENANT", "GUARDPOST_STORAGE", "GUARDPOST_MULTI_TENANT",
    "GUARDPOST_SECRET", "GUARDPOST_DB_PATH", "GUARDPOST_ENABLE_PATTERNS",
)


@pytest.fixture
def clean_env(monkeypatch):
    for var in GUARDPOST_ENV:
        monkeypatch.delenv(var, raising=False)
    return monkeypatch
