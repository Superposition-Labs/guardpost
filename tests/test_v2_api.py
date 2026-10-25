"""The v2 check API and ledger: commit flow, idempotency, lifecycle, imports, retention.

The release gates are marked ``gate``: concurrency (two commits from one IP
count +2), idempotency (a replay returns the identical result), tenant
isolation of the ledger, and no email in any evidence or ledger row.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
import time
from datetime import UTC, datetime, timedelta

import pytest
from conftest import V2_SECRET, provision_tenants
from fastapi.testclient import TestClient

from guardpost.api.server import create_app
from guardpost.ledger import rekey

UA = "Mozilla/5.0 (X11; Linux x86_64) Test/1.0"


def h(key: str) -> dict:
    return {"X-Api-Key": key}


def iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def now_iso(**delta) -> str:
    return iso(datetime.now(UTC) + timedelta(**delta))


def signup(account=None, email="person@gmail.com", ip="198.51.210.10", ua=UA, mode="commit", **extra):
    body = {"mode": mode, "email": email, "ip": ip, "device": {"user_agent": ua, "accept_language": "en"}}
    if account:
        body["account"] = {"id": account}
    body.update(extra)
    return body


@pytest.fixture
def env(tmp_path, v2_app):
    """Two tenants with all v2 scopes, plus a check-only key for alpha."""
    db = tmp_path / "gp.db"
    k = provision_tenants(db, {"alpha": {}, "beta": {}})
    k["alpha_check"] = provision_tenants(db, {"gamma": {}}, scopes="check")["gamma"]
    client = v2_app(db=db, dns={"mx": {"corp-example.com": ["mx.corp-example.com"]},
                                "a": {"mx.corp-example.com": ["192.0.2.1"], "corp-example.com": ["192.0.2.2"]}})
    return client, k, db


def ip_row(db, key):
    conn = sqlite3.connect(db)
    try:
        row = conn.execute("SELECT data FROM ip_reputation WHERE ip_address = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else None
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Secret gate
# ---------------------------------------------------------------------------


class TestSecretGate:
    def test_db_secret_disables_v2(self, tmp_path, clean_env):
        db = tmp_path / "gp.db"
        key = provision_tenants(db, {"alpha": {}})["alpha"]
        with TestClient(create_app(db_path=str(db), purge_interval=0)) as client:
            r = client.post("/api/v2/check", json=signup("a1"), headers=h(key))
            assert r.status_code == 503
            assert "GUARDPOST_SECRET" in r.json()["detail"]
            # v1 keeps working on the generated secret.
            assert client.post("/api/v1/check", json={"email": "x@gmail.com"}, headers=h(key)).status_code == 200

    def test_allow_db_secret_flag(self, tmp_path, clean_env):
        db = tmp_path / "gp.db"
        key = provision_tenants(db, {"alpha": {}})["alpha"]
        clean_env.setenv("GUARDPOST_ALLOW_DB_SECRET", "1")
        with TestClient(create_app(db_path=str(db), purge_interval=0)) as client:
            assert client.post("/api/v2/check", json=signup("a1"), headers=h(key)).status_code == 200

    def test_env_secret_enables_v2(self, tmp_path, clean_env):
        db = tmp_path / "gp.db"
        key = provision_tenants(db, {"alpha": {}})["alpha"]
        clean_env.setenv("GUARDPOST_SECRET", V2_SECRET)
        with TestClient(create_app(db_path=str(db), purge_interval=0)) as client:
            assert client.post("/api/v2/check", json=signup("a1"), headers=h(key)).status_code == 200

    def test_changed_or_missing_secret_refuses_boot(self, tmp_path, clean_env):
        db = tmp_path / "gp.db"
        provision_tenants(db, {"alpha": {}})
        with TestClient(create_app(db_path=str(db), secret=V2_SECRET, purge_interval=0)):
            pass
        with pytest.raises(rekey.SecretMismatchError), \
                TestClient(create_app(db_path=str(db), secret="another-secret", purge_interval=0)):
            pass
        with pytest.raises(rekey.SecretMismatchError), TestClient(create_app(db_path=str(db), purge_interval=0)):
            pass

    def test_phase2_bans_are_rekeyed(self, tmp_path, clean_env):
        db = tmp_path / "gp.db"
        key = provision_tenants(db, {"alpha": {}}, scopes="check,lifecycle,dashboard")["alpha"]
        with TestClient(create_app(db_path=str(db), purge_interval=0)) as client:
            assert client.post("/api/v1/email/ban", json={"email": "banned.person@gmail.com"},
                               headers=h(key)).status_code == 200
        conn = sqlite3.connect(db)
        before = conn.execute("SELECT email_hash FROM bans").fetchall()
        conn.close()
        with TestClient(create_app(db_path=str(db), secret=V2_SECRET, purge_interval=0)) as client:
            conn = sqlite3.connect(db)
            after = conn.execute("SELECT email_hash FROM bans").fetchall()
            conn.close()
            assert len(after) == 1 and after != before
            # v1 still sees the ban through the HMAC; so does v2.
            r = client.post("/api/v1/check", json={"email": "Banned.Person+x@gmail.com"}, headers=h(key))
            assert r.json()["is_banned"] is True
            r = client.post("/api/v2/check", json=signup("a1", email="banned.person@gmail.com"), headers=h(key))
            assert r.json()["block_code"] == "EMAIL_BANNED"


# ---------------------------------------------------------------------------
# Check: evaluate / commit / idempotency
# ---------------------------------------------------------------------------


class TestCheck:
    def test_evaluate_is_read_only_until_committed(self, env):
        client, k, db = env
        r = client.post("/api/v2/check", json=signup(mode="evaluate"), headers=h(k["alpha"]))
        assert r.status_code == 200
        res = r.json()
        assert res["committed"] is False and res["decision"] == "allow" and res["mode"] == "evaluate"
        assert ip_row(db, "198.51.210.10") is None
        assert client.get("/api/v2/stats", headers=h(k["alpha"])).json()["pending_checks"] == 1

        r = client.post("/api/v2/accounts", json={"check_id": res["check_id"], "account_id": "a1"},
                        headers=h(k["alpha"]))
        assert r.status_code == 200
        assert r.json()["committed"] is True and r.json()["account_id"] == "a1"
        assert ip_row(db, "198.51.210.10")["total_registrations"] == 1
        assert ip_row(db, "198.51.210.0/24")["total_registrations"] == 1
        # Idempotent for the same account, 409 for another.
        again = client.post("/api/v2/accounts", json={"check_id": res["check_id"], "account_id": "a1"},
                            headers=h(k["alpha"]))
        assert again.json() == r.json()
        other = client.post("/api/v2/accounts", json={"check_id": res["check_id"], "account_id": "a2"},
                            headers=h(k["alpha"]))
        assert other.status_code == 409
        assert ip_row(db, "198.51.210.10")["total_registrations"] == 1

    def test_commit_must_match_the_evaluated_account(self, env):
        client, k, _ = env
        res = client.post("/api/v2/check", json=signup("a1", mode="evaluate"), headers=h(k["alpha"])).json()
        r = client.post("/api/v2/accounts", json={"check_id": res["check_id"], "account_id": "a2"},
                        headers=h(k["alpha"]))
        assert r.status_code == 409 and r.json()["detail"]["code"] == "account_mismatch"
        assert client.post("/api/v2/accounts", json={"check_id": res["check_id"], "account_id": "a1"},
                           headers=h(k["alpha"])).status_code == 200

    def test_commit_unknown_and_expired(self, env):
        client, k, db = env
        assert client.post("/api/v2/accounts", json={"check_id": "chk_nope", "account_id": "a1"},
                           headers=h(k["alpha"])).status_code == 404
        res = client.post("/api/v2/check", json=signup(mode="evaluate"), headers=h(k["alpha"])).json()
        conn = sqlite3.connect(db)
        conn.execute("UPDATE checks SET pending_until = ?", (time.time() - 1,))
        conn.commit()
        conn.close()
        r = client.post("/api/v2/accounts", json={"check_id": res["check_id"], "account_id": "a1"},
                        headers=h(k["alpha"]))
        assert r.status_code == 410

    def test_commit_mode_needs_account_and_refuses_duplicates(self, env):
        client, k, _ = env
        r = client.post("/api/v2/check", json=signup(), headers=h(k["alpha"]))
        assert r.status_code == 422 and r.json()["detail"]["code"] == "account_required"
        assert client.post("/api/v2/check", json=signup("a1"), headers=h(k["alpha"])).status_code == 200
        r = client.post("/api/v2/check", json=signup("a1", email="other@gmail.com"), headers=h(k["alpha"]))
        assert r.status_code == 409

    @pytest.mark.gate
    def test_idempotent_replay_returns_identical_result(self, env):
        client, k, db = env
        body = signup("a1", idempotency_key="signup:a1")
        first = client.post("/api/v2/check", json=body, headers=h(k["alpha"]))
        second = client.post("/api/v2/check", json=body, headers=h(k["alpha"]))
        assert first.status_code == second.status_code == 200
        assert first.json() == second.json()
        assert ip_row(db, "198.51.210.10")["total_registrations"] == 1
        # The header form is the same key.
        body.pop("idempotency_key")
        third = client.post("/api/v2/check", json=body, headers={**h(k["alpha"]), "Idempotency-Key": "signup:a1"})
        assert third.json() == first.json()
        # A different request under the same key is refused.
        r = client.post("/api/v2/check", json=signup("a1", email="else@gmail.com", idempotency_key="signup:a1"),
                        headers=h(k["alpha"]))
        assert r.status_code == 422 and r.json()["detail"]["code"] == "idempotency_key_reused"
        r = client.post("/api/v2/check", json=signup("a9", idempotency_key="x"),
                        headers={**h(k["alpha"]), "Idempotency-Key": "y"})
        assert r.status_code == 422

    @pytest.mark.gate
    def test_idempotent_replay_of_evaluate(self, env):
        client, k, _ = env
        body = signup(mode="evaluate", idempotency_key="eval-1")
        first = client.post("/api/v2/check", json=body, headers=h(k["alpha"])).json()
        client.post("/api/v2/accounts", json={"check_id": first["check_id"], "account_id": "a1"},
                    headers=h(k["alpha"]))
        assert client.post("/api/v2/check", json=body, headers=h(k["alpha"])).json() == first

    def test_occurred_at_window_and_backfill_scope(self, env):
        client, k, _ = env
        old = signup("a1", occurred_at=now_iso(hours=-2))
        r = client.post("/api/v2/check", json=old, headers=h(k["alpha_check"]))
        assert r.status_code == 422 and r.json()["detail"]["code"] == "occurred_at_out_of_window"
        assert client.post("/api/v2/check", json=old, headers=h(k["alpha"])).status_code == 200
        assert client.post("/api/v2/check", json=signup("a2", occurred_at=now_iso(minutes=-10)),
                           headers=h(k["alpha_check"])).status_code == 200
        r = client.post("/api/v2/check", json=signup("a3", occurred_at=now_iso(hours=1)), headers=h(k["alpha"]))
        assert r.status_code == 422 and r.json()["detail"]["code"] == "occurred_at_in_future"

    def test_request_validation(self, env):
        client, k, _ = env
        bad = [
            {"ip": "198.51.210.10"},
            signup("a1", ip="999.1.1.1"),
            signup("bad@id"),
            {**signup("a1"), "email_sha256": "0" * 64},
            {**signup("a1"), "device": {"user_agent": "x", "fingerprint": "0" * 64}},
            {**signup("a1"), "unknown_field": 1},
        ]
        for body in bad:
            assert client.post("/api/v2/check", json=body, headers=h(k["alpha"])).status_code == 422, body

    def test_scopes(self, env):
        client, k, _ = env
        assert client.post("/api/v2/check", json=signup("a1"), headers={}).status_code == 401
        assert client.post("/api/v2/import/bans", json={"rows": [{"email": "x@gmail.com"}]},
                           headers=h(k["alpha_check"])).status_code == 403
        assert client.get("/api/v2/stats", headers=h(k["alpha_check"])).status_code == 403
        assert client.put("/api/v2/bans", json={"email": "x@gmail.com"},
                          headers=h(k["alpha_check"])).status_code == 403

    def test_email_sha256_and_fingerprint_forms(self, env):
        from guardpost.ledger.keys import normalized_email_sha256
        from guardpost.rules.device import registration_fingerprint

        client, k, _ = env
        client.post("/api/v2/check", json=signup("a1", email="first.person@gmail.com"), headers=h(k["alpha"]))
        body = {"mode": "commit", "email_sha256": normalized_email_sha256("First.Person+x@gmail.com"),
                "ip": "198.51.210.10", "device": {"fingerprint": registration_fingerprint(UA, "en")},
                "account": {"id": "a2"}}
        r = client.post("/api/v2/check", json=body, headers=h(k["alpha"])).json()
        assert r["block_code"] == "EMAIL_ALIAS_EXISTS"
        assert r["reasons"][-1]["evidence"] == {"account_id": "a1"}

    def test_typo_gate_suggests_domain_only(self, env):
        client, k, _ = env
        r = client.post("/api/v2/check", json=signup("a1", email="someone@gmail.con"), headers=h(k["alpha"])).json()
        assert r["decision"] == "block" and r["block_code"] == "EMAIL_TYPO_SUSPECTED"
        assert r["suggestion"] == "gmail.com" and r["signals"]["typo_source"] == "map"

    def test_tenant_can_demote_a_gate(self, tmp_path, v2_app):
        db = tmp_path / "gp.db"
        key = provision_tenants(db, {"soft": {"email": {"reason_tiers": {"typo_domain": "soft"}}}})["soft"]
        client = v2_app(db=db, dns={"mx": {"gmail.con": ["mx.provider-example.net"]}})
        r = client.post("/api/v2/check", json=signup("a1", email="someone@gmail.con"), headers=h(key)).json()
        assert r["decision"] == "degrade" and r["block_code"] is None
        assert "typo_domain:map" in r["soft_reasons"]


# ---------------------------------------------------------------------------
# Release gates
# ---------------------------------------------------------------------------


@pytest.mark.gate
def test_concurrent_commits_from_one_ip_count_twice(env):
    client, k, db = env
    results = []

    def go(n):
        results.append(client.post("/api/v2/check", json=signup(f"c{n}", email=f"racer{n}@gmail.com", ua=f"UA-{n}"),
                                   headers=h(k["alpha"])).status_code)

    threads = [threading.Thread(target=go, args=(n,)) for n in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == [200, 200]
    assert ip_row(db, "198.51.210.10")["total_registrations"] == 2
    assert ip_row(db, "198.51.210.0/24")["total_registrations"] == 2


@pytest.mark.gate
def test_concurrent_commits_through_the_service(tmp_path, clean_env):
    """Many signups racing through asyncio + worker threads: every one is counted."""
    from guardpost.api.v2 import CheckRequest
    from guardpost.email.validator import StubDnsResolver
    from guardpost.engine import Guardpost
    from guardpost.ledger.service import LedgerService
    from guardpost.storage.sqlite import SQLiteStorage

    async def go():
        storage = SQLiteStorage(tmp_path / "svc.db")
        engine = Guardpost(storage=storage, secret=V2_SECRET, dns_resolver=StubDnsResolver())
        await engine.initialize()
        tenant = await storage.ensure_tenant("alpha")
        service = LedgerService(engine)
        reqs = [CheckRequest.model_validate(signup(f"s{n}", email=f"svc{n}@gmail.com", ua=f"UA-{n}"))
                for n in range(20)]
        out = await asyncio.gather(*(service.check(tenant, r, idempotency_key=None, backfill=False) for r in reqs))
        record = await storage.get_ip_reputation("198.51.210.10")
        await engine.close()
        return out, record

    out, record = asyncio.run(go())
    assert len(out) == 20 and record.total_registrations == 20


@pytest.mark.gate
def test_tenant_isolation_of_the_ledger(env):
    client, k, db = env
    a = signup("acc1", email="shared.person@gmail.com", name={"first": "Ivan", "last": "Petrov"})
    assert client.post("/api/v2/check", json=a, headers=h(k["alpha"])).json()["decision"] == "allow"
    client.put("/api/v2/bans", json={"email": "banned.in.alpha@gmail.com"}, headers=h(k["alpha"]))

    # Same email, IP, device and name in beta: nothing of alpha's matches.
    b = client.post("/api/v2/check", json=signup("acc2", email="shared.person@gmail.com",
                                                 name={"first": "Ivan", "last": "Petrov"}),
                    headers=h(k["beta"])).json()
    assert b["decision"] == "allow" and b["reasons"] == []
    assert client.post("/api/v2/check", json=signup("acc3", email="banned.in.alpha@gmail.com", ip="198.51.211.1"),
                       headers=h(k["beta"])).json()["decision"] == "allow"
    assert client.get("/api/v2/accounts/acc1", headers=h(k["beta"])).status_code == 404
    assert client.post("/api/v2/accounts/acc1/events", json={"type": "deleted"},
                       headers=h(k["beta"])).status_code == 404
    assert client.get("/api/v2/stats", headers=h(k["beta"])).json()["bans"] == 0

    # Alpha still matches its own account.
    again = client.post("/api/v2/check", json=signup("acc4", email="shared.person+2@gmail.com"),
                        headers=h(k["alpha"])).json()
    assert again["block_code"] == "EMAIL_ALIAS_EXISTS"
    # The shared IP counters saw all of it (network intel is the one thing tenants share).
    assert ip_row(db, "198.51.210.10")["total_registrations"] == 3


@pytest.mark.gate
def test_no_email_in_evidence_or_ledger(env):
    client, k, db = env
    emails = [("leak.check@gmail.com", UA), ("leak.check+2@gmail.com", UA), ("admin@corp-example.com", UA),
              ("x.y.z.w.q@gmail.com", "Other/2.0")]
    results = []
    for n, (email, ua) in enumerate(emails):
        results.append(client.post("/api/v2/check", json=signup(f"L{n}", email=email, ua=ua,
                                                                ip="198.51.210.11" if n == 3 else "198.51.210.10",
                                                                name={"first": "Leak", "last": "Checker"}),
                                   headers=h(k["alpha"])).json())
    ev = client.post("/api/v2/check", json=signup(mode="evaluate", email="pending.leak@gmail.com"),
                     headers=h(k["alpha"])).json()
    client.post("/api/v2/accounts/L0/events", json={"type": "banned", "permanent_email_ban": True,
                                                    "reason": "test"}, headers=h(k["alpha"]))
    results.append(ev)
    kinds = {r["kind"] for res in results for r in res["reasons"]}
    assert {"alias_collision", "same_device", "same_name", "role_account", "dot_noise_local"} <= kinds
    blob = json.dumps(results)
    assert "@" not in blob
    conn = sqlite3.connect(db)
    try:
        dump = "\n".join(conn.iterdump())
    finally:
        conn.close()
    for needle in ["leak.check", "leakcheck", "corp-example", "pending.leak", "Leak", "198.51.210.10'", UA]:
        if needle == "198.51.210.10'":
            # Plaintext addresses live only in the shared reputation table.
            lines = [line for line in dump.splitlines() if needle[:-1] in line]
            assert lines and all("ip_reputation" in line for line in lines)
            continue
        assert needle not in dump, needle


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    def test_deleted_frees_the_address_keeps_signals(self, env):
        client, k, _ = env
        client.post("/api/v2/check", json=signup("a1", email="del.me@gmail.com"), headers=h(k["alpha"]))
        r = client.post("/api/v2/accounts/a1/events", json={"type": "deleted", "idempotency_key": "del:a1"},
                        headers=h(k["alpha"]))
        assert r.status_code == 200 and r.json()["applied"] is True
        dup = client.post("/api/v2/accounts/a1/events", json={"type": "deleted", "idempotency_key": "del:a1"},
                          headers=h(k["alpha"]))
        assert dup.json()["duplicate"] is True
        acc = client.get("/api/v2/accounts/a1", headers=h(k["alpha"])).json()
        assert acc["deleted_at"] and acc["signals"]["email"] is False and acc["signals"]["fingerprint"] is True
        r = client.post("/api/v2/check", json=signup("a2", email="del.me@gmail.com", ip="198.51.211.2", ua="other"),
                        headers=h(k["alpha"])).json()
        assert r["decision"] == "allow"

    def test_ban_events_and_bans_api(self, env):
        client, k, _ = env
        client.post("/api/v2/check", json=signup("a1", email="to.ban@gmail.com"), headers=h(k["alpha"]))
        r = client.post("/api/v2/accounts/a1/events", json={"type": "banned", "permanent_email_ban": True},
                        headers=h(k["alpha"]))
        assert r.json()["email_ban_created"] is True
        client.post("/api/v2/accounts/a1/events", json={"type": "unbanned"}, headers=h(k["alpha"]))
        # The email ban survives an unban (Factory v2).
        r = client.post("/api/v2/check", json=signup("a2", email="To.Ban+1@gmail.com", ip="198.51.211.3"),
                        headers=h(k["alpha"])).json()
        assert r["block_code"] == "EMAIL_BANNED"
        assert client.request("DELETE", "/api/v2/bans", json={"email": "to.ban@gmail.com"},
                              headers=h(k["alpha"])).json()["removed"] is True
        r = client.post("/api/v2/check", headers=h(k["alpha"]),
                        json=signup("a3", email="to.ban@gmail.com", ip="198.51.211.4", mode="evaluate")).json()
        assert r["block_code"] == "EMAIL_ALIAS_EXISTS"  # a1 is still live
        assert client.put("/api/v2/bans", json={"email": "fresh.ban@gmail.com", "reason": "r"},
                          headers=h(k["alpha"])).json() == {"banned": True, "created": True, "removed": None}
        r = client.post("/api/v2/check", json=signup("a4", email="fresh.ban@gmail.com", mode="evaluate",
                                                     signup={"method": "oauth"}), headers=h(k["alpha"])).json()
        assert r["block_code"] == "EMAIL_BANNED"

    def test_ban_without_email_on_record(self, env):
        client, k, _ = env
        client.post("/api/v2/check", json=signup("a1", email="gone@gmail.com"), headers=h(k["alpha"]))
        client.post("/api/v2/accounts/a1/events", json={"type": "deleted"}, headers=h(k["alpha"]))
        r = client.post("/api/v2/accounts/a1/events", json={"type": "banned", "permanent_email_ban": True},
                        headers=h(k["alpha"]))
        assert r.status_code == 422
        r = client.post("/api/v2/accounts/a1/events", json={"type": "banned", "permanent_email_ban": True,
                                                            "email": "gone@gmail.com"}, headers=h(k["alpha"]))
        assert r.status_code == 200

    def test_paid_flag_and_stats(self, env):
        client, k, _ = env
        client.post("/api/v2/check", json=signup("a1", email="admin@gmail.com"), headers=h(k["alpha"]))
        client.post("/api/v2/accounts/a1/events", json={"type": "paid"}, headers=h(k["alpha"]))
        client.post("/api/v2/accounts/a1/events", json={"type": "flagged"}, headers=h(k["alpha"]))
        stats = client.get("/api/v2/stats", headers=h(k["alpha"])).json()
        assert stats["decisions"]["degrade"] == 1 and stats["degraded_then_paid"] == 1
        assert stats["reasons"] == {"role_account": 1}
        assert stats["latency_ms"]["samples"] == 1
        acc = client.get("/api/v2/accounts/a1", headers=h(k["alpha"])).json()
        assert acc["paid_at"] and acc["flagged_at"]

    def test_created_event_and_unknown_account(self, env):
        client, k, _ = env
        assert client.post("/api/v2/accounts/zz/events", json={"type": "paid"},
                           headers=h(k["alpha"])).status_code == 404
        assert client.post("/api/v2/accounts/zz/events", json={"type": "created"},
                           headers=h(k["alpha"])).status_code == 200
        assert client.get("/api/v2/accounts/zz", headers=h(k["alpha"])).json()["source"] == "event"

    def test_retracted_code_stops_attribution(self, env):
        client, k, _ = env
        client.post("/api/v2/check", json=signup("ref", email="referrer@gmail.com", ip="198.51.212.1", ua="R"),
                    headers=h(k["alpha"]))
        client.post("/api/v2/accounts/ref/events", json={"type": "referral_code_retracted"}, headers=h(k["alpha"]))
        r = client.post("/api/v2/check", json=signup("new", email="new@gmail.com",
                                                     referral={"referrer_account_id": "ref"}),
                        headers=h(k["alpha"])).json()
        assert r["referral"] == {"attribute": False, "suspicious": False, "reason": "referrer_code_retracted"}
        client.post("/api/v2/accounts/ref/events", json={"type": "referral_code_restored"}, headers=h(k["alpha"]))
        r = client.post("/api/v2/check", json=signup("new2", email="new2@gmail.com", ua="other",
                                                     referral={"referrer_account_id": "ref"}),
                        headers=h(k["alpha"])).json()
        assert r["referral"]["attribute"] is True
        assert client.get("/api/v2/accounts/new2", headers=h(k["alpha"])).json()["referred_by"][
            "referrer_account_id"] == "ref"
        assert client.get("/api/v2/accounts/ref", headers=h(k["alpha"])).json()["referred_accounts"] == 1

    def test_self_referral_and_degraded_signups_are_not_attributed(self, env):
        client, k, _ = env
        r = client.post("/api/v2/check", json=signup("me", referral={"referrer_account_id": "me"}),
                        headers=h(k["alpha"])).json()
        assert r["referral"]["reason"] == "self_referral"
        r = client.post("/api/v2/check", json=signup("bad", email="admin@gmail.com", ip="198.51.212.9", ua="x",
                                                     referral={"referrer_account_id": "me"}),
                        headers=h(k["alpha"])).json()
        assert r["referral"] == {"attribute": False, "suspicious": False, "reason": "signup_degrade"}
        assert "no_referral_attribution" in r["actions"]


class TestOverrides:
    def test_block_and_allow(self, env):
        client, k, _ = env
        r = client.put("/api/v2/ip-overrides/198.51.213.7", json={"action": "block"}, headers=h(k["alpha"]))
        assert r.json() == {"target": "198.51.213.7", "kind": "ip", "action": "block", "removed": None}
        r = client.post("/api/v2/check", json=signup("a1", ip="198.51.213.7"), headers=h(k["alpha"])).json()
        assert r["block_code"] == "IP_BLACKLISTED" and r["signals"]["ip_override"] == "block"
        # Per tenant: beta is unaffected.
        assert client.post("/api/v2/check", json=signup("b1", ip="198.51.213.7"),
                           headers=h(k["beta"])).json()["decision"] == "allow"

        # A /24 allow override beats a graylisted shared /24.
        client.post("/api/v2/admin/ip-reputation/import", headers=h(k["alpha"]), json={"rows": [
            {"ip_address": "198.51.214.0/24", "total_registrations": 30, "status": "graylisted",
             "status_reason": "30 total registrations (elevated volume)"}]})
        r = client.post("/api/v2/check", json=signup("a2", ip="198.51.214.5", email="p2@gmail.com"),
                        headers=h(k["alpha"])).json()
        assert r["reasons"][0]["code"] == "subnet_burst:198.51.214.0/24"
        client.put("/api/v2/ip-overrides/198.51.214.0/24", json={"action": "allow"}, headers=h(k["alpha"]))
        r = client.post("/api/v2/check", json=signup("a3", ip="198.51.214.6", email="p3@gmail.com", ua="u3"),
                        headers=h(k["alpha"])).json()
        assert r["decision"] == "allow" and r["signals"]["ip_override"] == "allow"
        assert client.request("DELETE", "/api/v2/ip-overrides/198.51.214.0/24",
                              headers=h(k["alpha"])).json()["removed"] is True

    def test_invalid_targets(self, env):
        client, k, _ = env
        for target in ("198.51.0.0/16", "not-an-ip", "2001:db9::/64"):
            assert client.put(f"/api/v2/ip-overrides/{target}", json={"action": "block"},
                              headers=h(k["alpha"])).status_code == 422


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------


class TestImports:
    def test_imported_accounts_feed_the_rules(self, env):
        client, k, _ = env
        when = iso(datetime.now(UTC) - timedelta(hours=3))
        rows = [{"account_id": "old1", "created_at": when, "email": "imported@gmail.com", "ip": "198.51.215.1",
                 "device": {"user_agent": UA, "accept_language": "en"}, "name": {"first": "Ivan", "last": "Petrov"}},
                {"account_id": "old2", "created_at": when, "email_sha256": "a" * 64, "deleted_at": when}]
        r = client.post("/api/v2/import/accounts", json={"rows": rows}, headers=h(k["alpha"]))
        assert r.json() == {"received": 2, "inserted": 2, "updated": 0}
        assert client.post("/api/v2/import/accounts", json={"rows": rows[:1]},
                           headers=h(k["alpha"])).json()["updated"] == 1
        r = client.post("/api/v2/check", json=signup("new", email="fresh@gmail.com", ip="198.51.215.1"),
                        headers=h(k["alpha"])).json()
        assert r["reasons"][0]["code"] == "same_device:old1"
        assert client.get("/api/v2/accounts/old2", headers=h(k["alpha"])).json()["signals"]["email"] is False

    def test_import_bans_and_referrals(self, env):
        client, k, _ = env
        r = client.post("/api/v2/import/bans", json={"rows": [{"email": "old.ban@gmail.com", "reason": "x"},
                                                              {"email": "old.ban@gmail.com", "reason": "y"}]},
                        headers=h(k["alpha"]))
        assert r.json() == {"received": 2, "inserted": 1, "updated": 1}
        assert client.post("/api/v2/check", json=signup("a1", email="oldban@gmail.com", mode="evaluate"),
                           headers=h(k["alpha"])).json()["block_code"] == "EMAIL_BANNED"
        recent = iso(datetime.now(UTC) - timedelta(hours=2))
        rows = [{"referred_account_id": f"x{i}", "referrer_account_id": "boss", "created_at": recent,
                 "ip": f"198.51.216.{i}"} for i in range(3)]
        assert client.post("/api/v2/import/referrals", json={"rows": rows},
                           headers=h(k["alpha"])).json()["inserted"] == 3
        r = client.post("/api/v2/check", json=signup("x9", email="x9@gmail.com",
                                                     referral={"referrer_account_id": "boss"}),
                        headers=h(k["alpha"])).json()
        assert r["referral"]["reason"] == "referrer_velocity_24h (3 referrals in 24h)"

    def test_import_limits(self, env):
        client, k, _ = env
        rows = [{"email": f"b{i}@gmail.com"} for i in range(1001)]
        assert client.post("/api/v2/import/bans", json={"rows": rows}, headers=h(k["alpha"])).status_code == 422
        assert client.post("/api/v2/import/bans", json={"rows": []}, headers=h(k["alpha"])).status_code == 422

    def test_ip_reputation_merge(self, env):
        client, k, db = env
        first = {"ip_address": "198.51.217.1", "total_registrations": 10, "suspicious_registrations": 2,
                 "first_registration_at": "2026-09-10T00:00:00Z", "last_registration_at": "2026-09-12T00:00:00Z",
                 "status": "blacklisted", "status_reason": "manual"}
        second = {"ip_address": "198.51.217.1", "total_registrations": 4, "suspicious_registrations": 3,
                  "first_registration_at": "2026-09-01T00:00:00Z", "last_registration_at": "2026-09-20T00:00:00Z",
                  "status": "clean"}
        r = client.post("/api/v2/admin/ip-reputation/import", json={"rows": [first]}, headers=h(k["alpha"]))
        assert r.json()["inserted"] == 1
        client.post("/api/v2/admin/ip-reputation/import", json={"rows": [second]}, headers=h(k["alpha"]))
        row = ip_row(db, "198.51.217.1")
        assert (row["total_registrations"], row["suspicious_registrations"], row["status"]) == (10, 3, "blacklisted")
        assert row["first_registration_at"].startswith("2026-09-01")
        assert row["last_registration_at"].startswith("2026-09-20")
        assert client.post("/api/v2/admin/ip-reputation/import", json={"rows": [first]},
                           headers=h(k["alpha_check"])).status_code == 403


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------


def test_purge(env, tmp_path):
    client, k, db = env
    client.post("/api/v2/check", json=signup("a1", name={"first": "Old", "last": "Timer"}), headers=h(k["alpha"]))
    client.post("/api/v2/accounts/a1/events", json={"type": "paid"}, headers=h(k["alpha"]))
    client.post("/api/v2/admin/ip-reputation/import", headers=h(k["alpha"]), json={"rows": [
        {"ip_address": "198.51.218.1", "total_registrations": 1, "last_registration_at": "2026-01-01T00:00:00Z"},
        {"ip_address": "198.51.218.2", "total_registrations": 1, "status": "graylisted",
         "last_registration_at": "2026-01-01T00:00:00Z"}]})
    service = client.app.state.ledger
    later = time.time() + 36 * 86400
    counts = asyncio.run(service.purge(now=later))
    assert counts["signals"] == 1 and counts["checks"] == 1 and counts["ip_rows"] >= 1
    acc = client.get("/api/v2/accounts/a1", headers=h(k["alpha"])).json()
    assert acc["signals"]["email"] is True and acc["signals"]["fingerprint"] is False and acc["signals"]["purged_at"]
    assert ip_row(db, "198.51.218.1") is None and ip_row(db, "198.51.218.2") is not None
    assert asyncio.run(service.purge(now=time.time() + 401 * 86400))["events"] == 1
