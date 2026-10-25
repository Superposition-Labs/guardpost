"""guardpost/rules and the ledger's keyed hashes, below the API."""

from __future__ import annotations

import pytest
from conftest import provision_tenants

from guardpost.ledger.keys import TenantHasher
from guardpost.rules.device import device_repeat_reason
from guardpost.rules.policy import (
    ALLOW,
    BLOCK,
    DEGRADE,
    Reason,
    actions_for,
    block_code,
    decide,
    is_suspicious,
)
from guardpost.rules.referral import evaluate_referral
from guardpost.rules.same_person import find_same_person_reason
from guardpost.rules.signals import SignalKeys


class FakeIndex:
    def __init__(self, **answers):
        self.answers = answers
        self.calls = []

    def __getattr__(self, name):
        def call(*args, **kwargs):
            self.calls.append((name, kwargs))
            return self.answers.get(name)
        return call


class TestPolicy:
    def test_decision_is_the_highest_tier(self):
        assert decide([]) == ALLOW
        assert decide([Reason("gibberish_domain")]) == ALLOW
        assert decide([Reason("gibberish_domain"), Reason("role_account")]) == DEGRADE
        assert decide([Reason("role_account"), Reason("banned_email")]) == BLOCK

    def test_overrides(self):
        assert decide([Reason("typo_domain", "map")], {"typo_domain": "soft"}) == DEGRADE
        assert decide([Reason("device_repeat", "2")], {"device_repeat": "hard"}) == BLOCK
        assert block_code([Reason("device_repeat", "2")], {"device_repeat": "hard"}) == "POLICY_BLOCK"
        assert block_code([Reason("role_account"), Reason("alias_collision", "a1")]) == "EMAIL_ALIAS_EXISTS"
        assert not is_suspicious([Reason("null_mx")])
        assert is_suspicious([Reason("null_mx")], {"null_mx": "soft"})

    def test_actions(self):
        assert actions_for(ALLOW, [], returning_user=False) == []
        assert actions_for(BLOCK, [Reason("banned_email")], returning_user=True) == []
        assert actions_for(ALLOW, [], returning_user=True) == ["no_welcome_credits", "no_referral_attribution"]
        assert actions_for(DEGRADE, [Reason("same_name", "a1")], returning_user=False) == [
            "no_welcome_credits", "no_referral_attribution", "no_referral_payouts", "retract_referral_code"]

    def test_reason_code(self):
        assert Reason("subnet_burst", "203.0.114.0/24").code == "subnet_burst:203.0.114.0/24"
        assert Reason("role_account").code == "role_account"


class TestRuleGuards:
    def test_device_repeat_needs_fingerprint_and_global_network(self):
        index = FakeIndex(count_device=5)
        assert device_repeat_reason(index, SignalKeys(fp_key="f"), 0.0) is None
        assert device_repeat_reason(index, SignalKeys(net_key="n"), 0.0) is None
        assert index.calls == []
        reason = device_repeat_reason(index, SignalKeys(fp_key="f", net_key="n"), 1000.0)
        assert reason.code == "device_repeat:5"
        assert index.calls[0][1]["since"] == 1000.0 - 7 * 86400 and index.calls[0][1]["until"] == 1000.0

    def test_same_device_needs_fingerprint_and_global_network(self):
        index = FakeIndex(first_same_device="a1", first_same_name=None)
        # A non-global address: no net_key, so no same_device even with a fingerprint.
        assert find_same_person_reason(index, SignalKeys(ip_key="i", fp_key="f"), 0.0) is None
        assert find_same_person_reason(index, SignalKeys(ip_key="i", net_key="n", fp_key="f"), 0.0).code == \
            "same_device:a1"

    def test_same_name_needs_evidence(self):
        index = FakeIndex(first_same_device=None, first_same_name=("a1", ["fingerprint"]))
        assert find_same_person_reason(index, SignalKeys(name_key="k"), 0.0) is None
        reason = find_same_person_reason(index, SignalKeys(name_key="k", fp_key="f"), 0.0)
        assert reason.code == "same_name:a1" and reason.evidence == {"account_id": "a1", "matched_on": ["fingerprint"]}
        assert index.calls[-1][1]["since"] == -30 * 86400

    def test_referral_order(self):
        index = FakeIndex(count_referrals_from_ip=3, count_referrer_referrals=99, referrer_code_retracted=False)
        verdict = evaluate_referral(index, referrer_account_id="r", referred_account_id="n", ip_key="i", now=0.0)
        assert verdict.reason == "same_ip_4_in_24h" and verdict.attribute and verdict.suspicious
        index = FakeIndex(count_referrals_from_ip=0, count_referrer_referrals=2, referrer_code_retracted=False)
        verdict = evaluate_referral(index, referrer_account_id="r", referred_account_id="n", ip_key=None, now=0.0)
        assert verdict.suspicious is False
        assert evaluate_referral(index, referrer_account_id="n", referred_account_id="n", ip_key=None,
                                 now=0.0).reason == "self_referral"


class TestKeys:
    def test_tenant_separation_and_purposes(self):
        a, b = TenantHasher("s", "alpha"), TenantHasher("s", "beta")
        assert a.ip("203.0.114.7") != b.ip("203.0.114.7")
        assert a.ip("x") != a.net("x") != a.fingerprint("x")
        assert TenantHasher("s", "alpha", 2).ip("x") != a.ip("x")
        assert a.email("A" * 64) == a.email("a" * 64)

    def test_seal_roundtrip_and_tamper(self):
        hasher = TenantHasher("s", "alpha")
        sealed = hasher.seal("chk_1", "2001:db9::40")
        assert "2001" not in sealed
        assert hasher.unseal("chk_1", sealed) == "2001:db9::40"
        assert hasher.unseal("chk_2", sealed) is None
        assert TenantHasher("s", "beta").unseal("chk_1", sealed) is None
        flipped = ("0" if sealed[0] != "0" else "1") + sealed[1:]
        assert hasher.unseal("chk_1", flipped) is None


@pytest.mark.parametrize("ip", ["10.0.0.5", "100.64.3.3", "192.168.1.20"])
def test_non_global_addresses_never_match_device_rules(ip, tmp_path, v2_app):
    db = tmp_path / "gp.db"
    key = provision_tenants(db, {"t": {}})["t"]
    client = v2_app(db=db)
    for n in range(4):
        r = client.post("/api/v2/check", headers={"X-Api-Key": key}, json={
            "mode": "commit", "email": f"natted{n}@gmail.com", "ip": ip, "account": {"id": f"n{n}"},
            "device": {"user_agent": "Same/1.0"}, "name": {"first": "Same", "last": "Person"}}).json()
        if n == 0:
            assert r["reasons"] == []
        else:
            # Only the fingerprint backs the name match: same_name, never same_device or device_repeat.
            assert [x["code"] for x in r["reasons"]] == ["same_name:n0"]
        assert r["signals"]["global_ip"] is False


def test_ipv6_device_repeat_matches_the_exact_address(tmp_path, v2_app):
    db = tmp_path / "gp.db"
    key = provision_tenants(db, {"t": {}})["t"]
    client = v2_app(db=db)
    codes = []
    for n, ip in enumerate(["2001:db9::1", "2001:db9::2", "2001:db9::1", "2001:DB9:0::1"]):
        r = client.post("/api/v2/check", headers={"X-Api-Key": key}, json={
            "mode": "commit", "email": f"six{n}@gmail.com", "ip": ip, "account": {"id": f"s{n}"},
            "device": {"user_agent": "V6/1.0"}}).json()
        codes.append([x["code"] for x in r["reasons"]])
    # ::2 is another network; the third signup has one prior on ::1, the fourth two
    # (written differently, the same address: Guardpost canonicalizes).
    assert codes == [[], [], ["same_device:s0"], ["device_repeat:2", "same_device:s0"]]
