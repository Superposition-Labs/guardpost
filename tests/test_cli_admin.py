"""guardpost migrate / tenant / key / ip CLI."""

from __future__ import annotations

import asyncio
import json
import sqlite3

import pytest

from guardpost import cli
from guardpost.storage.migrations import sqlite_migrations
from guardpost.storage.sqlite import SQLiteStorage
from guardpost.tenancy import keys


@pytest.fixture
def gp(tmp_path, clean_env, capsys):
    db = str(tmp_path / "cli.db")

    def run(*argv, ok=True):
        with pytest.raises(SystemExit) as exc:
            cli.main([*argv, "--db", db])
        out = capsys.readouterr()
        assert (exc.value.code == 0) is ok, out
        return out.out, out.err

    run.db = db
    return run


def _auth(db, presented):
    async def go():
        storage = SQLiteStorage(db)
        try:
            return await keys.authenticate(storage, presented)
        finally:
            await storage.close()

    return asyncio.run(go())


def test_migrate(gp):
    out, _ = gp("migrate", "--status")
    assert "schema version 0" in out and "pending: 0001_initial" in out
    out, _ = gp("migrate")
    assert f"now at version {sqlite_migrations()[-1].version}" in out
    out, _ = gp("migrate")
    assert "up to date" in out


def test_commands_refuse_an_unmigrated_database(gp):
    _, err = gp("tenant", "list", ok=False)
    assert "guardpost migrate" in err


def test_tenant_lifecycle(gp):
    gp("migrate")
    out, _ = gp("tenant", "create", "factory", "--name", "Factory", "--region", "ru")
    created = json.loads(out)
    assert created["config"] == {"region": "ru"}
    assert created["effective_config"]["referral"]["velocity_7d"] == 10
    gp("tenant", "create", "factory", ok=False)
    gp("tenant", "create", "Bad Id", ok=False)

    out, _ = gp("tenant", "config-set", "factory", "email.reason_tiers.typo_domain=hard",
                "rate_limit_per_minute=600", "--json", '{"email": {"trusted_extra_domains": ["factory.bot"]}}')
    config = json.loads(out)["config"]
    assert config["email"] == {"reason_tiers": {"typo_domain": "hard"}, "trusted_extra_domains": ["factory.bot"]}
    assert config["rate_limit_per_minute"] == 600

    out, _ = gp("tenant", "config-set", "factory", "rate_limit_per_minute=null")
    assert "rate_limit_per_minute" not in json.loads(out)["config"]
    _, err = gp("tenant", "config-set", "factory", "referral.velocty_24h=5", ok=False)
    assert "velocty_24h" in err
    _, err = gp("tenant", "config-set", "factory", "retention.signals_days=0", ok=False)
    assert "signals_days" in err
    out, _ = gp("tenant", "config-set", "factory", "--replace", "--json", '{"region": "global"}')
    assert json.loads(out)["config"] == {"region": "global"}

    out, _ = gp("tenant", "list")
    assert "factory" in out and "default" in out
    out, _ = gp("tenant", "show", "factory")
    assert json.loads(out)["keys"] == []
    out, _ = gp("tenant", "set-status", "factory", "suspended")
    assert json.loads(out)["status"] == "suspended"
    gp("tenant", "show", "nope", ok=False)


def test_key_create_list_revoke_rotate(gp):
    gp("migrate")
    gp("tenant", "create", "acme")
    out, err = gp("key", "create", "--tenant", "acme", "--label", "ci", "--scopes", "check,lifecycle",
                  "--expires", "90d")
    plaintext = out.strip()
    assert plaintext.startswith("gpk_") and "\n" not in plaintext
    assert "shown only this once" in err
    key_id = keys.split_key(plaintext)[0]
    record, tenant = _auth(gp.db, plaintext)
    assert tenant.id == "acme" and record.scopes == {"check", "lifecycle"} and record.expires_at is not None

    # The plaintext is never printed again, nor stored.
    out, _ = gp("key", "list", "--tenant", "acme")
    assert key_id in out and plaintext not in out and "active" in out
    out, _ = gp("tenant", "show", "acme")
    assert plaintext not in out and "key_sha256" not in out
    assert plaintext not in "\n".join(sqlite3.connect(gp.db).iterdump())

    out, err = gp("key", "rotate", key_id, "--grace", "7d")
    rotated = out.strip()
    assert rotated.startswith("gpk_") and rotated != plaintext and "expires at" in err
    assert _auth(gp.db, plaintext) is not None  # grace period
    assert _auth(gp.db, rotated) is not None

    gp("key", "revoke", key_id)
    assert _auth(gp.db, plaintext) is None
    out, _ = gp("key", "list")
    assert "revoked" in out

    gp("key", "create", "--tenant", "nope", "--label", "x", "--scopes", "check", ok=False)
    _, err = gp("key", "create", "--tenant", "acme", "--label", "x", "--scopes", "root", ok=False)
    assert "unknown scope" in err
    gp("key", "rotate", "000000000000", ok=False)


def test_ip_whitelist_global(gp):
    gp("migrate")
    _, err = gp("ip", "whitelist", "198.51.100.7", ok=False)
    assert "--global" in err
    out, _ = gp("ip", "whitelist", "--global", "198.51.100.7", "--reason", "office NAT")
    assert "198.51.100.7" in out
    out, _ = gp("ip", "whitelist", "--global", "203.0.113.9/24")
    assert "203.0.113.0/24" in out
    gp("ip", "whitelist", "--global", "10.0.0.0/8", ok=False)

    async def read():
        storage = SQLiteStorage(gp.db)
        try:
            return (await storage.get_ip_reputation("198.51.100.7"), await storage.get_ip_reputation("203.0.113.0/24"))
        finally:
            await storage.close()

    ip, net = asyncio.run(read())
    assert ip.manually_whitelisted and ip.whitelist_reason == "office NAT"
    assert net.manually_whitelisted


def test_cli_key_works_against_the_server(gp, clean_env):
    from fastapi.testclient import TestClient

    from guardpost.api.server import create_app

    gp("migrate")
    gp("tenant", "create", "acme")
    out, _ = gp("key", "create", "--tenant", "acme", "--label", "app", "--scopes", "check")
    with TestClient(create_app(db_path=gp.db)) as client:
        resp = client.post("/api/v1/check", json={"email": "a@gmail.com"},
                           headers={"Authorization": f"Bearer {out.strip()}"})
        assert resp.status_code == 200
