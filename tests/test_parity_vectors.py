"""parity/vectors.json: Guardpost's rules give Factory v2's answers.

The function vectors hold values computed by running v2's TypeScript; the
scenarios replay signups through POST /api/v2/check on a fresh instance each.
Factory v2's own parity test runs the same file through assessSignup.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from conftest import provision_tenants

from guardpost.email.validator import (
    StubDnsResolver,
    check_registration_suspicion,
    classify_domain_typo,
    partition_reasons,
    validate_deliverability,
    validate_email_format,
)
from guardpost.ip.reputation import IPReputationEngine, IPReputationRecord
from guardpost.ledger.keys import normalized_email_sha256
from guardpost.rules import RULESET
from guardpost.rules.device import registration_fingerprint
from guardpost.rules.namekey import name_token, registration_name_key
from guardpost.rules.network import is_global_ip, network_key, subnet_key
from guardpost.storage.memory import MemoryStorage

VECTORS = json.loads((Path(__file__).resolve().parent.parent / "parity" / "vectors.json").read_text("utf-8"))
FN = VECTORS["functions"]
FACTORY_EXTRA_TRUSTED = ("factory.bot", "deleted.local")


def _id(case, *keys):
    return "|".join(repr(case.get(k)) for k in keys)[:80]


def test_ruleset_matches_engine():
    assert VECTORS["ruleset"] == RULESET


def test_known_divergences_are_documented():
    ids = [d["id"] for d in VECTORS["known_divergences"]]
    assert len(ids) == len(set(ids)) and all(d["description"] for d in VECTORS["known_divergences"])
    used = {c["guardpost"]["divergence"] for c in FN["network"] if "guardpost" in c}
    assert used <= set(ids)


@pytest.mark.parametrize("case", FN["name_token"], ids=lambda c: c["in"])
def test_name_token(case):
    assert name_token(case["in"]) == case["out"]


@pytest.mark.parametrize("case", FN["name_key"], ids=lambda c: _id(c, "first", "last", "display"))
def test_name_key(case):
    assert registration_name_key(case["first"], case["last"], case["display"], case["email"]) == case["out"]


def test_alina_name_keys_meet():
    keys = {registration_name_key("Alina", "Sinichkina"), registration_name_key("Алина", "Синичкина"),
            registration_name_key("Sinichkina", "Alina"), registration_name_key(None, None, "Alina Sinichkina")}
    assert keys == {"alina sinichkina"}


@pytest.mark.parametrize("case", FN["fingerprint"], ids=lambda c: _id(c, "user_agent", "accept_language"))
def test_fingerprint(case):
    assert registration_fingerprint(case["user_agent"], case["accept_language"]) == case["out"]


@pytest.mark.parametrize("case", FN["network"], ids=lambda c: c["ip"] or "<empty>")
def test_network(case):
    expected_key = case.get("guardpost", {}).get("network_key", case["network_key"])
    assert is_global_ip(case["ip"]) is case["is_global"]
    assert network_key(case["ip"]) == expected_key
    assert (subnet_key(case["ip"]) if case["ip"] else None) == case["subnet_key"]


@pytest.mark.parametrize("case", FN["normalize_email"], ids=lambda c: c["in"] or "<empty>")
def test_normalize_email(case):
    from guardpost.email.validator import normalize_email

    assert normalize_email(case["in"]) == case["out"]
    if case["in"]:
        assert normalized_email_sha256(case["in"]) == case["sha256"]


_DNS = StubDnsResolver(**FN["email_flags"]["dns"])


@pytest.mark.parametrize("case", FN["email_flags"]["cases"], ids=lambda c: f"{c['email']}|{c['region']}")
def test_email_flags(case):
    """Guardpost's hard and soft flags are v2's reasons (weak ones are Guardpost-only, score only)."""
    _, reasons = asyncio.run(check_registration_suspicion(
        case["email"], trusted_extra_domains=FACTORY_EXTRA_TRUSTED, flag_ua_domain=case["region"] == "ru",
        resolver=_DNS, include_typo=False))
    hard, soft, _weak = partition_reasons(reasons)
    assert hard + soft == case["reasons"]


@pytest.mark.parametrize("case", FN["email_gate"], ids=lambda c: repr(c["email"]))
def test_email_gate(case):
    email = case["email"]

    async def gate():
        if not validate_email_format(email)[0]:
            return "EMAIL_INVALID_FORMAT", None
        typo = classify_domain_typo(email)
        if typo:
            return "EMAIL_TYPO_SUSPECTED", typo[0]
        if not await validate_deliverability(email, trusted_extra_domains=FACTORY_EXTRA_TRUSTED, resolver=_DNS):
            return "EMAIL_DOMAIN_UNDELIVERABLE", None
        return None, None

    assert asyncio.run(gate()) == (case["block_code"], case["suggestion"])


@pytest.mark.parametrize("case", FN["ip_status"], ids=lambda c: f"{c['key']}|{c['total']}|{c['suspicious']}")
def test_ip_status(case):
    engine = IPReputationEngine(MemoryStorage())
    now = datetime.fromisoformat(case["now"].replace("Z", "+00:00"))
    record = IPReputationRecord(
        ip_address=case["key"], total_registrations=case["total"], suspicious_registrations=case["suspicious"],
        first_registration_at=now - timedelta(days=case["first_days_ago"]), status=case["status"],
        status_reason=case.get("status_reason"))
    thresholds = engine._subnet_thresholds if "/" in case["key"] else engine._ip_thresholds
    engine._evaluate_status(record, now, thresholds)
    assert (record.status, record.status_reason) == (case["expected_status"], case["expected_reason"])


# ---------------------------------------------------------------------------
# Scenarios, through the HTTP API
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario", VECTORS["scenarios"], ids=lambda s: s["name"])
def test_scenario(scenario, tmp_path, v2_app):
    db = tmp_path / "parity.db"
    key = provision_tenants(db, {"factory": {}})["factory"]
    client = v2_app(db=db, dns=scenario.get("dns"))
    headers = {"X-Api-Key": key}
    for n, step in enumerate(scenario["steps"]):
        where = f"{scenario['name']} step {n}"
        if step["op"] == "ip_reputation":
            r = client.post("/api/v2/admin/ip-reputation/import", json={"rows": step["rows"]}, headers=headers)
            assert r.status_code == 200, (where, r.text)
            continue
        if step["op"] == "event":
            r = client.post(f"/api/v2/accounts/{step['account_id']}/events",
                            json={**step["event"], "occurred_at": step["at"]}, headers=headers)
            assert r.status_code == 200, (where, r.text)
            continue
        assert step["op"] == "check"
        body = {"mode": "evaluate", **step["request"], "occurred_at": step["at"]}
        r = client.post("/api/v2/check", json=body, headers=headers)
        assert r.status_code == 200, (where, r.text)
        got = r.json()
        if got["decision"] != "block":  # like v2: a refused signup creates no account
            committed = client.post("/api/v2/accounts", headers=headers, json={
                "check_id": got["check_id"], "account_id": step["request"]["account"]["id"]})
            assert committed.status_code == 200, (where, committed.text)
            assert committed.json()["committed"] is True
            assert {k: v for k, v in committed.json().items() if k not in ("committed", "account_id")} == \
                {k: v for k, v in got.items() if k not in ("committed", "account_id")}
        expect = step["expect"]
        assert [x["code"] for x in got["reasons"] if x["tier"] != "weak"] == expect["reasons"], (where, got)
        assert got["decision"] == expect["decision"], (where, got)
        assert got["block_code"] == expect.get("block_code"), (where, got)
        assert got["actions"] == expect["actions"], (where, got)
        assert got["referral"] == expect.get("referral"), (where, got)
        if "suggestion" in expect:
            assert got["suggestion"] == expect["suggestion"], where
        for code, evidence in expect.get("evidence", {}).items():
            match = [x for x in got["reasons"] if x["code"] == code]
            assert match and match[0]["evidence"] == evidence, (where, got)
        assert "@" not in json.dumps(got), where
