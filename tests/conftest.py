"""Shared fixtures: an isolated environment for every API test."""

import pytest

GUARDPOST_ENV = (
    "GUARDPOST_API_KEY", "GUARDPOST_REDIS_URL", "GUARDPOST_RATE_LIMIT", "GUARDPOST_TRUSTED_PROXIES",
    "GUARDPOST_ENABLE_METRICS", "GUARDPOST_METRICS_PORT", "GUARDPOST_TRUSTED_EXTRA_DOMAINS",
    "GUARDPOST_ALLOW_OPEN", "GUARDPOST_LEGACY_TENANT", "GUARDPOST_STORAGE", "GUARDPOST_MULTI_TENANT",
    "GUARDPOST_SECRET", "GUARDPOST_DB_PATH", "GUARDPOST_ENABLE_PATTERNS", "GUARDPOST_ALLOW_DB_SECRET",
    "GUARDPOST_PURGE_INTERVAL",
)


@pytest.fixture
def clean_env(monkeypatch):
    for var in GUARDPOST_ENV:
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


# ---------------------------------------------------------------------------
# v2 ledger helpers
# ---------------------------------------------------------------------------

V2_SECRET = "test-secret-not-for-production"
ALL_V2_SCOPES = "check,lifecycle,dashboard,backfill,admin"


def provision_tenants(db, tenants, scopes=ALL_V2_SCOPES):
    """Create tenants (id -> config dict) with one key each; returns id -> plaintext key."""
    import asyncio

    from guardpost.storage.sqlite import SQLiteStorage
    from guardpost.tenancy import keys
    from guardpost.tenancy.config import TenantConfig
    from guardpost.tenancy.models import Tenant

    async def go():
        storage = SQLiteStorage(db)
        await storage.initialize()
        try:
            out = {}
            for tenant_id, config in tenants.items():
                await storage.create_tenant(Tenant(id=tenant_id, name=tenant_id,
                                                   config=TenantConfig.model_validate(config or {})))
                out[tenant_id], _ = await keys.create_key(storage, tenant_id, scopes, label="test")
            return out
        finally:
            await storage.close()

    return asyncio.run(go())


@pytest.fixture
def v2_app(tmp_path, clean_env):
    """Boot an app with a real secret and a stub DNS: ``v2_app(tenants=..., dns=...)``."""
    from fastapi.testclient import TestClient

    from guardpost.api.server import create_app
    from guardpost.email.validator import StubDnsResolver

    clients = []

    def boot(*, db=None, dns=None, secret=V2_SECRET, **kwargs):
        db = db or tmp_path / f"v2-{len(clients)}.db"
        kwargs.setdefault("purge_interval", 0)
        app = create_app(db_path=str(db), secret=secret, dns_resolver=StubDnsResolver(**(dns or {})), **kwargs)
        client = TestClient(app, client=("203.0.113.9", 50000))
        client.__enter__()
        clients.append(client)
        return client

    yield boot
    for c in clients:
        c.__exit__(None, None, None)
