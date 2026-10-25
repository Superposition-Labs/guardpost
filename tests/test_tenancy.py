"""Multi-tenancy: isolation, shared intel, legacy compatibility, keys, open mode."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import sqlite3
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from guardpost.api.server import create_app
from guardpost.storage.memory import MemoryStorage
from guardpost.storage.sqlite import SQLiteStorage
from guardpost.tenancy import keys
from guardpost.tenancy.config import TenantConfig
from guardpost.tenancy.models import Tenant, utcnow

LEGACY_KEY = "legacy-0.2-shared-key"
PEER = ("203.0.113.9", 50000)


def run(coro):
    return asyncio.run(coro)


async def _with_storage(db, fn, legacy_tenant="default"):
    storage = SQLiteStorage(db, legacy_tenant=legacy_tenant)
    await storage.initialize()
    try:
        return await fn(storage)
    finally:
        await storage.close()


def provision(db, tenants: dict[str, dict], scopes="check,lifecycle,dashboard") -> dict[str, str]:
    """Create tenants (id -> config) with one key each, the way the CLI does."""

    async def go(storage):
        out = {}
        for tenant_id, config in tenants.items():
            await storage.create_tenant(Tenant(id=tenant_id, name=tenant_id.upper(),
                                               config=TenantConfig.model_validate(config)))
            out[tenant_id], _ = await keys.create_key(storage, tenant_id, scopes, label="test")
        return out

    return run(_with_storage(db, go))


def h(key: str) -> dict:
    return {"X-Api-Key": key}


@pytest.fixture
def boot(tmp_path, clean_env):
    clients = []

    def _boot(db=None, **kwargs):
        db = db or tmp_path / "gp.db"
        client = TestClient(create_app(db_path=str(db), **kwargs), client=PEER)
        client.__enter__()
        clients.append(client)
        return client

    yield _boot
    for c in clients:
        c.__exit__(None, None, None)


@pytest.fixture
def two_tenants(tmp_path, boot):
    db = tmp_path / "gp.db"
    k = provision(db, {"alpha": {}, "beta": {}})
    client = boot(db, api_key=LEGACY_KEY, enable_patterns=True)
    return client, k["alpha"], k["beta"]


def check(client, key, email, ip=None, record_ip=True):
    body = {"email": email, "record_ip": record_ip}
    if ip:
        body["ip_address"] = ip
    resp = client.post("/api/v1/check", json=body, headers=h(key))
    assert resp.status_code == 200, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Isolation
# ---------------------------------------------------------------------------


class TestIsolation:
    def test_ban_in_a_is_not_a_ban_in_b(self, two_tenants):
        client, a, b = two_tenants
        assert client.post("/api/v1/email/ban", json={"email": "Mallory@Gmail.com"}, headers=h(a)).status_code == 200
        assert check(client, a, "mallory@gmail.com", record_ip=False)["is_banned"] is True
        assert check(client, b, "mallory@gmail.com", record_ip=False)["is_banned"] is False
        assert check(client, LEGACY_KEY, "mallory@gmail.com", record_ip=False)["is_banned"] is False

    def test_a_cannot_unban_in_b(self, two_tenants):
        client, a, b = two_tenants
        client.post("/api/v1/email/ban", json={"email": "eve@gmail.com"}, headers=h(b))
        resp = client.request("DELETE", "/api/v1/email/ban", json={"email": "eve@gmail.com"}, headers=h(a))
        assert resp.json()["banned"] is True  # nothing to unban in alpha
        assert check(client, b, "eve@gmail.com", record_ip=False)["is_banned"] is True

    def test_key_alone_decides_the_tenant(self, two_tenants):
        client, a, b = two_tenants
        # No request field, header or query parameter can pick another tenant.
        client.post("/api/v1/email/ban?tenant=beta", json={"email": "x@gmail.com"},
                    headers={**h(a), "X-Tenant": "beta", "X-Tenant-Id": "beta"})
        assert check(client, b, "x@gmail.com", record_ip=False)["is_banned"] is False
        assert check(client, a, "x@gmail.com", record_ip=False)["is_banned"] is True

    def test_stats_are_per_tenant(self, two_tenants):
        client, a, b = two_tenants
        for i in range(3):
            check(client, a, f"user{i}@gmail.com", ip=f"198.51.100.{i + 1}")
        client.post("/api/v1/email/ban", json={"email": "z@gmail.com"}, headers=h(a))
        check(client, b, "other@gmail.com", ip="192.0.2.10")

        sa = client.get("/api/v1/stats", headers=h(a)).json()
        sb = client.get("/api/v1/stats", headers=h(b)).json()
        assert (sa["total_registrations"], sa["total_ips"], sa["total_banned_emails"]) == (3, 3, 1)
        assert (sb["total_registrations"], sb["total_ips"], sb["total_banned_emails"]) == (1, 1, 0)
        legacy = client.get("/api/v1/stats", headers=h(LEGACY_KEY)).json()
        assert legacy["total_registrations"] == 0 and legacy["total_banned_emails"] == 0

    def test_timeline_is_per_tenant(self, two_tenants):
        client, a, b = two_tenants
        check(client, a, "t1@gmail.com", ip="198.51.100.1")
        check(client, a, "t2@gmail.com", ip="198.51.100.2")
        ta = client.get("/api/v1/stats/timeline", headers=h(a)).json()
        tb = client.get("/api/v1/stats/timeline", headers=h(b)).json()
        assert sum(x["count"] for x in ta["buckets"]) == 2
        assert tb["buckets"] == []

    def test_dashboard_basic_auth_per_tenant(self, two_tenants):
        client, a, b = two_tenants
        check(client, a, "dash@gmail.com", ip="198.51.100.1")

        def basic(key):
            return {"Authorization": "Basic " + base64.b64encode(f"any:{key}".encode()).decode()}

        assert client.get("/dashboard", headers=basic(b)).status_code == 200
        assert client.get("/api/v1/stats", headers=basic(b)).json()["total_registrations"] == 0
        assert client.get("/api/v1/stats", headers=basic(a)).json()["total_registrations"] == 1
        denied = client.get("/dashboard")
        assert denied.status_code == 401
        assert denied.headers["WWW-Authenticate"].startswith("Basic")

    def test_pattern_report_is_per_tenant(self, two_tenants):
        client, a, b = two_tenants
        for i in range(4):
            check(client, a, f"bot{1000 + i}@gmail.com", ip="198.51.100.77")
        ra = client.get("/api/v1/patterns/report", headers=h(a)).json()
        rb = client.get("/api/v1/patterns/report", headers=h(b)).json()
        assert ra["total_registrations"] == 4
        assert rb["total_registrations"] == 0 and rb["clusters"] == []

    def test_no_plaintext_email_or_ip_on_disk(self, tmp_path, two_tenants):
        client, a, _ = two_tenants
        check(client, a, "very.private.person@gmail.com", ip="2001:db8::77")
        dump = "\n".join(sqlite3.connect(str(tmp_path / "gp.db")).iterdump())
        assert "very.private.person" not in dump
        # The shared reputation table holds the address with no tenant link;
        # nothing tenant-scoped does.
        lines = [line for line in dump.splitlines() if "2001:db8::77" in line]
        assert lines and all(line.startswith('INSERT INTO "ip_reputation"') for line in lines)
        assert any(line.startswith('INSERT INTO "registration_events"') for line in dump.splitlines())


# ---------------------------------------------------------------------------
# Shared intel
# ---------------------------------------------------------------------------


class TestSharedIntel:
    def test_ip_reputation_is_shared(self, two_tenants):
        client, a, b = two_tenants
        for _ in range(5):  # graylist threshold: 5 suspicious
            client.post("/api/v1/ip/record", json={"ip_address": "198.51.100.200", "is_suspicious": True},
                        headers=h(a))
        assert client.post("/api/v1/ip/check", json={"ip_address": "198.51.100.200"},
                           headers=h(b)).json()["status"] == "graylisted"
        assert check(client, b, "fine@gmail.com", ip="198.51.100.200", record_ip=False)["ip_status"] == "graylisted"
        # ...but B's stats show none of A's traffic.
        assert client.get("/api/v1/stats", headers=h(b)).json()["total_ips"] == 0
        assert client.get("/api/v1/stats", headers=h(a)).json()["graylisted_ips"] == 1

    def test_subnet_reputation_is_shared(self, two_tenants):
        client, a, b = two_tenants
        for i in range(1, 9):  # subnet graylist: 8 suspicious across the /24
            client.post("/api/v1/ip/record", json={"ip_address": f"203.0.113.{i}", "is_suspicious": True},
                        headers=h(a))
        body = check(client, b, "fine@gmail.com", ip="203.0.113.250", record_ip=False)
        assert body["subnet_status"] == "graylisted"
        assert "subnet_burst:203.0.113.0/24" in body["reasons"]


# ---------------------------------------------------------------------------
# Legacy compatibility
# ---------------------------------------------------------------------------

# Response keys of every v1 route as of 0.2.0.
V02_KEYS = {
    "health": {"status", "version"},
    "stats": {"total_ips", "graylisted_ips", "blacklisted_ips", "whitelisted_ips", "total_banned_emails",
              "total_registrations", "total_suspicious_registrations"},
    "timeline": {"buckets", "bucket_seconds"},
    "check": {"email", "ip_address", "is_suspicious", "risk_score", "reasons", "weak_reasons", "soft_reasons",
              "hard_reasons", "ip_status", "ip_reason", "subnet_status", "subnet_reason", "is_banned",
              "normalized_email", "suggested_domain", "typo_source", "smtp_status", "smtp_catch_all", "ip_type",
              "is_datacenter", "is_vpn", "is_proxy", "is_tor", "ip_provider", "ai_risk_score", "ai_confidence",
              "ai_reasons", "ai_analysis", "is_b2c", "gravatar_url", "breach_count"},
    "validate": {"email", "normalized_email", "is_valid", "format_error", "is_disposable", "is_role_account",
                 "is_b2c", "is_suspicious", "reasons", "suggested_domain", "typo_source"},
    "ip": {"ip_address", "status", "reason"},
    "ban": {"email", "normalized_email_hash", "banned"},
    "patterns": {"total_registrations", "suspicious_count", "risk_level", "velocity_per_minute", "clusters"},
}


class TestLegacyKey:
    @pytest.fixture
    def client(self, boot, clean_env):
        clean_env.setenv("GUARDPOST_LEGACY_TENANT", "factory")
        return boot(api_key=LEGACY_KEY, enable_patterns=True)

    @pytest.mark.parametrize("auth", ["x-api-key", "bearer", "basic"])
    def test_every_v1_route(self, client, auth):
        headers = {
            "x-api-key": {"X-Api-Key": LEGACY_KEY},
            "bearer": {"Authorization": f"Bearer {LEGACY_KEY}"},
            "basic": {"Authorization": "Basic " + base64.b64encode(f"admin:{LEGACY_KEY}".encode()).decode()},
        }[auth]
        ip = {"ip_address": "198.51.100.5"}

        def ok(resp, kind):
            assert resp.status_code == 200, resp.text
            assert set(resp.json()) == V02_KEYS[kind]
            return resp.json()

        ok(client.get("/api/v1/health", headers=headers), "health")
        ok(client.post("/api/v1/check", json={"email": "a@gmail.com", **ip}, headers=headers), "check")
        ok(client.post("/api/v1/email/validate", json={"email": "a@gmail.com"}, headers=headers), "validate")
        ok(client.post("/api/v1/ip/check", json=ip, headers=headers), "ip")
        ok(client.post("/api/v1/ip/record", json=ip, headers=headers), "ip")
        assert ok(client.post("/api/v1/email/ban", json={"email": "b@gmail.com"}, headers=headers), "ban")["banned"]
        assert not ok(client.request("DELETE", "/api/v1/email/ban", json={"email": "b@gmail.com"},
                                     headers=headers), "ban")["banned"]
        stats = ok(client.get("/api/v1/stats", headers=headers), "stats")
        assert stats["total_registrations"] == 2
        ok(client.get("/api/v1/stats/timeline", headers=headers), "timeline")
        ok(client.get("/api/v1/patterns/report", headers=headers), "patterns")
        # Optional features answer exactly as in 0.2 when disabled.
        for path, body in [("/api/v1/email/smtp", {"email": "a@gmail.com"}), ("/api/v1/ip/proxy", ip),
                           ("/api/v1/ai/score", {"email": "a@gmail.com"}),
                           ("/api/v1/ai/score/batch", {"emails": ["a@gmail.com"]})]:
            assert client.post(path, json=body, headers=headers).status_code == 501
        assert client.get("/dashboard", headers=headers).status_code == 200

    def test_legacy_key_acts_as_legacy_tenant(self, tmp_path, client):
        client.post("/api/v1/email/ban", json={"email": "c@gmail.com"}, headers=h(LEGACY_KEY))

        async def banned(storage):
            return await storage.is_email_banned(hashlib.sha256(b"c@gmail.com").hexdigest(), tenant_id="factory")

        assert run(_with_storage(tmp_path / "gp.db", banned, legacy_tenant="factory"))

    def test_wrong_key_is_401_with_the_02_message(self, client):
        for headers in ({"X-Api-Key": "nope"}, {"Authorization": "Bearer nope"}, {}):
            resp = client.post("/api/v1/check", json={"email": "a@gmail.com"}, headers=headers)
            assert resp.status_code == 401
            assert resp.json() == {"detail": "Invalid or missing API key"}

    def test_env_is_the_source_of_truth(self, tmp_path, boot, clean_env):
        db = tmp_path / "env.db"
        first = boot(db, api_key="first-key")
        assert first.get("/api/v1/health", headers=h("first-key")).status_code == 200
        first.__exit__(None, None, None)
        second = boot(db, api_key="second-key")
        assert second.get("/api/v1/health", headers=h("first-key")).status_code == 401
        assert second.get("/api/v1/health", headers=h("second-key")).status_code == 200
        second.__exit__(None, None, None)
        # Unset: the legacy row is revoked, and with no other key boot refuses.
        with pytest.raises(RuntimeError, match="GUARDPOST_ALLOW_OPEN"):
            boot(db)


# ---------------------------------------------------------------------------
# Keys: scopes, rotation, revocation, expiry
# ---------------------------------------------------------------------------


class TestKeys:
    def test_key_format_and_storage(self, tmp_path):
        async def go(storage):
            await storage.create_tenant(Tenant(id="acme", name="Acme"))
            plaintext, record = await keys.create_key(storage, "acme", "check", label="ci")
            assert plaintext.startswith(f"gpk_{record.id}_") and len(plaintext) > 50
            assert record.key_sha256 == hashlib.sha256(plaintext.encode()).hexdigest()
            stored = await storage.get_api_key(record.id)
            assert stored.key_sha256 == record.key_sha256 and stored.scopes == {"check"}
            return plaintext

        plaintext = run(_with_storage(tmp_path / "k.db", go))
        dump = "\n".join(sqlite3.connect(str(tmp_path / "k.db")).iterdump())
        assert plaintext not in dump

    def test_scopes_enforced(self, tmp_path, boot):
        db = tmp_path / "gp.db"
        only_check = provision(db, {"narrow": {}}, scopes="check")["narrow"]
        client = boot(db)
        assert client.post("/api/v1/check", json={"email": "a@gmail.com"}, headers=h(only_check)).status_code == 200
        resp = client.post("/api/v1/email/ban", json={"email": "a@gmail.com"}, headers=h(only_check))
        assert resp.status_code == 403 and "lifecycle" in resp.json()["detail"]
        assert client.get("/api/v1/stats", headers=h(only_check)).status_code == 403
        assert client.get("/dashboard", headers=h(only_check)).status_code == 403

    def test_rotation_with_grace(self, tmp_path):
        async def go(storage):
            await storage.create_tenant(Tenant(id="acme", name="Acme"))
            old_plain, old = await keys.create_key(storage, "acme", "check,lifecycle", label="app")
            t0 = utcnow()
            new_plain, new, old_after = await keys.rotate_key(storage, old.id, grace=timedelta(days=7), now=t0)
            assert new.scopes == old.scopes and new.tenant_id == "acme" and new.label == "app"
            assert old_after.expires_at == t0 + timedelta(days=7)
            # Within the grace period both keys work...
            assert await keys.authenticate(storage, old_plain, now=t0 + timedelta(days=6))
            assert await keys.authenticate(storage, new_plain, now=t0 + timedelta(days=6))
            # ...after it only the new one.
            assert await keys.authenticate(storage, old_plain, now=t0 + timedelta(days=7, seconds=1)) is None
            assert await keys.authenticate(storage, new_plain, now=t0 + timedelta(days=30))
            with pytest.raises(ValueError):
                await keys.rotate_key(storage, old.id, grace=timedelta(days=1), now=t0 + timedelta(days=8))

        run(_with_storage(tmp_path / "rot.db", go))

    def test_rotation_never_extends_an_earlier_expiry(self, tmp_path):
        async def go(storage):
            await storage.create_tenant(Tenant(id="acme", name="Acme"))
            _, old = await keys.create_key(storage, "acme", "check", expires_in=timedelta(days=1))
            _, _, old_after = await keys.rotate_key(storage, old.id, grace=timedelta(days=7))
            assert old_after.expires_at == old.expires_at

        run(_with_storage(tmp_path / "rot2.db", go))

    def test_legacy_key_cannot_be_rotated_by_cli(self, tmp_path):
        async def go(storage):
            await keys.sync_legacy_key(storage, "env-key", "default")
            with pytest.raises(ValueError, match="GUARDPOST_API_KEY"):
                await keys.rotate_key(storage, "legacy", grace=timedelta(days=1))

        run(_with_storage(tmp_path / "rot3.db", go))

    def test_revocation_and_expiry_over_http(self, tmp_path, boot):
        db = tmp_path / "gp.db"

        async def go(storage):
            await storage.create_tenant(Tenant(id="acme", name="Acme"))
            revoked, r = await keys.create_key(storage, "acme", "check")
            expired, _ = await keys.create_key(storage, "acme", "check", expires_in=timedelta(seconds=-1))
            rotated, rot = await keys.create_key(storage, "acme", "check")
            live, _ = await keys.create_key(storage, "acme", "check")
            return revoked, r.id, expired, rotated, rot.id, live

        revoked, revoked_id, expired, rotated, rotated_id, live = run(_with_storage(db, go))
        client = boot(db)

        def status(key):
            return client.post("/api/v1/email/validate", json={"email": "a@gmail.com"}, headers=h(key)).status_code

        assert status(revoked) == 200 and status(rotated) == 200
        run(_with_storage(db, lambda s: keys.revoke_key(s, revoked_id)))
        new_plain, _, _ = run(_with_storage(db, lambda s: keys.rotate_key(s, rotated_id, grace=timedelta(0))))
        # Revocation and rotation take effect on the running server at once.
        assert status(revoked) == 401
        assert status(rotated) == 401
        assert status(new_plain) == 200
        assert status(expired) == 401
        assert status(live) == 200

    def test_last_used_recorded(self, tmp_path, boot):
        db = tmp_path / "gp.db"
        key = provision(db, {"acme": {}})["acme"]
        client = boot(db)
        client.get("/api/v1/health", headers=h(key))
        key_id = keys.split_key(key)[0]
        record = run(_with_storage(db, lambda s: s.get_api_key(key_id)))
        assert record.last_used_at is not None

    def test_suspended_tenant_is_403(self, tmp_path, boot):
        db = tmp_path / "gp.db"
        key = provision(db, {"acme": {}})["acme"]
        client = boot(db)

        async def suspend(storage):
            tenant = await storage.get_tenant("acme")
            tenant.status = "suspended"
            await storage.save_tenant(tenant)

        run(_with_storage(db, suspend))
        assert client.get("/api/v1/health", headers=h(key)).status_code == 403

    def test_parse_helpers(self):
        assert keys.parse_duration("90d") == timedelta(days=90)
        assert keys.parse_duration("12h") == timedelta(hours=12)
        assert keys.parse_duration("2w") == timedelta(weeks=2)
        with pytest.raises(ValueError):
            keys.parse_duration("soon")
        assert keys.parse_scopes("check, lifecycle") == {"check", "lifecycle"}
        with pytest.raises(ValueError, match="unknown scope"):
            keys.parse_scopes("check,root")
        assert keys.split_key("gpk_0123456789ab_" + "x" * 43) == ("0123456789ab", "x" * 43)
        assert keys.split_key("not-a-gpk-key") is None


# ---------------------------------------------------------------------------
# Open mode and backend refusal
# ---------------------------------------------------------------------------


class TestOpenMode:
    def test_no_keys_refuses_to_boot(self, boot):
        with pytest.raises(RuntimeError) as exc:
            boot()
        message = str(exc.value)
        assert "no API keys" in message
        assert "GUARDPOST_ALLOW_OPEN=1" in message and "GUARDPOST_API_KEY" in message
        assert "guardpost key create" in message

    def test_allow_open_serves_unauthenticated(self, boot, clean_env):
        clean_env.setenv("GUARDPOST_ALLOW_OPEN", "1")
        client = boot()
        assert client.post("/api/v1/check", json={"email": "a@gmail.com"}).status_code == 200
        assert client.get("/api/v1/stats").status_code == 200

    def test_allow_open_does_not_bypass_existing_keys(self, tmp_path, boot):
        db = tmp_path / "gp.db"
        key = provision(db, {"acme": {}})["acme"]
        client = boot(db, allow_open=True)
        assert client.get("/api/v1/health").status_code == 401
        assert client.get("/api/v1/health", headers=h(key)).status_code == 200

    def test_multi_tenant_refused_on_a_backend_without_tenancy(self, boot):
        class SingleTenant(MemoryStorage):
            supports_tenancy = False

        with pytest.raises(RuntimeError, match="needs the SQLite storage backend"):
            boot(storage=SingleTenant(), multi_tenant=True, api_key=LEGACY_KEY)

    def test_single_tenant_backend_still_serves_the_legacy_key(self, boot):
        class SingleTenant(MemoryStorage):
            supports_tenancy = False

        client = boot(storage=SingleTenant(), api_key=LEGACY_KEY)
        assert client.post("/api/v1/email/ban", json={"email": "s@gmail.com"}, headers=h(LEGACY_KEY)).json()["banned"]
        assert check(client, LEGACY_KEY, "s@gmail.com", record_ip=False)["is_banned"] is True
        assert client.get("/api/v1/health", headers=h("wrong")).status_code == 401

    def test_unknown_storage_backend(self, boot):
        with pytest.raises(RuntimeError, match="unknown GUARDPOST_STORAGE"):
            boot(storage_backend="mongo", api_key=LEGACY_KEY)


# ---------------------------------------------------------------------------
# Per-tenant config and rate limits
# ---------------------------------------------------------------------------


class TestTenantConfig:
    @pytest.fixture
    def regional(self, tmp_path, boot):
        from guardpost.email.validator import _mx_host_cache, clear_caches

        clear_caches()
        for d in ("i.ua", "kpi.ua", "factory.bot"):
            _mx_host_cache[d] = None
        db = tmp_path / "gp.db"
        k = provision(db, {
            "ru": {"region": "ru", "email": {"trusted_extra_domains": ["factory.bot"]}},
            "global": {"region": "global", "email": {"reason_tiers": {"role_account": "weak"}}},
            "optin": {"region_rules": {"ua_domain": True}},
        })
        yield boot(db, trusted_extra_domains=""), k
        clear_caches()

    def test_ua_domain_rule_for_ru(self, regional):
        client, k = regional
        ru = check(client, k["ru"], "someone@i.ua", record_ip=False)
        assert "ua_domain" in ru["soft_reasons"] and ru["is_suspicious"] is True
        glob = check(client, k["global"], "someone@i.ua", record_ip=False)
        assert "ua_domain" not in glob["reasons"] and glob["is_suspicious"] is False
        assert "ua_domain" in check(client, k["optin"], "someone@i.ua", record_ip=False)["reasons"]
        assert check(client, k["ru"], "someone@gmail.com", record_ip=False)["reasons"] == []

    def test_trusted_extra_domains_per_tenant(self, regional):
        client, k = regional
        assert check(client, k["ru"], "telegram_1@factory.bot", record_ip=False)["reasons"] == []
        assert "no_mx_records" in check(client, k["global"], "telegram_1@factory.bot", record_ip=False)["reasons"]

    def test_reason_tiers_per_tenant(self, regional):
        client, k = regional
        glob = check(client, k["global"], "admin@gmail.com", record_ip=False)
        assert glob["weak_reasons"] == ["role_account"] and glob["is_suspicious"] is False
        ru = check(client, k["ru"], "admin@gmail.com", record_ip=False)
        assert ru["soft_reasons"] == ["role_account"] and ru["is_suspicious"] is True

    def test_config_change_applies_without_restart(self, tmp_path, regional):
        client, k = regional

        async def flip(storage):
            from guardpost.tenancy.config import apply_patch

            tenant = await storage.get_tenant("global")
            tenant.config = apply_patch(tenant.config, {"region_rules": {"ua_domain": True}})
            await storage.save_tenant(tenant)

        run(_with_storage(tmp_path / "gp.db", flip))
        assert "ua_domain" in check(client, k["global"], "someone@kpi.ua", record_ip=False)["reasons"]

    def test_config_validation(self):
        from pydantic import ValidationError

        from guardpost.tenancy.config import apply_patch, parse_assignment

        cfg = TenantConfig()
        assert cfg.device_repeat.window_days == 7 and cfg.device_repeat.prior_threshold == 2
        assert (cfg.same_person.device_window_days, cfg.same_person.name_window_days) == (7, 30)
        assert (cfg.referral.same_ip_limit, cfg.referral.velocity_24h, cfg.referral.velocity_7d) == (3, 3, 10)
        assert cfg.retention.signals_days == 35 and cfg.rate_limit_per_minute is None
        assert cfg.to_json() == "{}"
        with pytest.raises(ValidationError):
            TenantConfig.model_validate({"emial": {}})
        with pytest.raises(ValidationError):
            TenantConfig.model_validate({"email": {"reason_tiers": {"typo_domain": "block"}}})
        with pytest.raises(ValidationError):
            TenantConfig.model_validate({"retention": {"signals_days": 0}})
        patched = apply_patch(cfg, parse_assignment("referral.velocity_24h=5"))
        assert patched.referral.velocity_24h == 5 and patched.referral.velocity_7d == 10
        assert patched.to_json() == '{"referral": {"velocity_24h": 5}}'
        assert apply_patch(patched, parse_assignment("referral=null")).to_json() == "{}"


class TestRateLimits:
    def test_per_tenant_bucket(self, tmp_path, boot):
        db = tmp_path / "gp.db"
        k = provision(db, {"tight": {"rate_limit_per_minute": 2}, "loose": {}})
        client = boot(db, rate_limit=100)
        codes = [client.get("/api/v1/health", headers=h(k["tight"])).status_code for _ in range(3)]
        assert codes == [200, 200, 429]
        # Another tenant on the same IP is unaffected...
        assert client.get("/api/v1/health", headers=h(k["loose"])).status_code == 200
        # ...and so is unauthenticated traffic from that IP.
        assert client.get("/healthz").status_code == 200

    def test_tenant_bucket_is_shared_by_its_keys(self, tmp_path, boot):
        db = tmp_path / "gp.db"
        k = provision(db, {"tight": {"rate_limit_per_minute": 2}})
        second, _ = run(_with_storage(db, lambda s: keys.create_key(s, "tight", "check")))
        client = boot(db)
        assert client.get("/api/v1/health", headers=h(k["tight"])).status_code == 200
        assert client.get("/api/v1/health", headers=h(second)).status_code == 200
        assert client.get("/api/v1/health", headers=h(second)).status_code == 429

    def test_authenticated_traffic_skips_the_ip_bucket(self, tmp_path, boot):
        db = tmp_path / "gp.db"
        k = provision(db, {"acme": {"rate_limit_per_minute": 0}})
        client = boot(db, rate_limit=2)
        assert [client.get("/healthz").status_code for _ in range(3)] == [200, 200, 429]
        # Same IP, but authenticated: the tenant's (unlimited) bucket applies.
        assert all(client.get("/api/v1/health", headers=h(k["acme"])).status_code == 200 for _ in range(5))
        # A rejected key is unauthenticated traffic: per-IP bucket, already empty.
        assert client.get("/api/v1/health", headers=h("gpk_000000000000_wrongwrongwrongwrongwrong")).status_code == 429
