"""Shared IP reputation shows its status only: no tenant learns counts other tenants produced.

The status reason of a shared IP row ("5 suspicious registrations") counts every
tenant's signups. v2 responses name the status only (graylisted_ip:graylisted)
unless the tenant sets ip.reason_detail=full and is alone on the instance (or the
operator allows it). v1 keeps 0.2's exact strings for the legacy tenant.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from conftest import provision_tenants

from guardpost.engine import Guardpost
from guardpost.storage.memory import MemoryStorage
from guardpost.tenancy import keys
from guardpost.tenancy.config import TenantConfig
from guardpost.tenancy.models import Tenant

UA = "Mozilla/5.0 (X11; Linux x86_64) Test/1.0"
FARM_IP = "198.51.100.50"
ROLE_LOCALS = ["admin", "info", "support", "sales", "contact"]


def h(key):
    return {"X-Api-Key": key}


def signup(account, email, ip=FARM_IP, **extra):
    return {"mode": "commit", "email": email, "ip": ip, "account": {"id": account},
            "device": {"user_agent": UA, "accept_language": "en"}, **extra}


def graylist_from(client, key):
    """Tenant A's own traffic: five suspicious (degraded) signups from one IP graylist it."""
    for i, local in enumerate(ROLE_LOCALS):
        r = client.post("/api/v2/check", json=signup(f"a{i}", f"{local}@gmail.com"), headers=h(key))
        assert r.status_code == 200, r.text
        assert r.json()["decision"] == "degrade"


@pytest.fixture
def two_tenants(tmp_path, v2_app):
    def boot(beta_config=None, **kwargs):
        db = tmp_path / "gp.db"
        k = provision_tenants(db, {"alpha": {}, "beta": beta_config or {}})
        client = v2_app(db=db, api_key="legacy-key", legacy_tenant="alpha", **kwargs)
        graylist_from(client, k["alpha"])
        return client, k

    return boot


def no_counts(body: dict) -> bool:
    text = json.dumps(body)
    return "suspicious registrations" not in text and "total registrations" not in text


class TestV2StatusOnly:
    def test_other_tenant_sees_status_not_counts(self, two_tenants):
        client, k = two_tenants()
        r = client.post("/api/v2/check", json=signup("b1", "clean.person@gmail.com"), headers=h(k["beta"]))
        body = r.json()
        assert body["decision"] == "degrade"
        assert body["soft_reasons"] == ["graylisted_ip:graylisted"]
        assert [x["code"] for x in body["reasons"]] == ["graylisted_ip:graylisted"]
        assert body["signals"]["ip_status"] == "graylisted"
        assert body["signals"]["ip_reason"] is None and body["signals"]["subnet_reason"] is None
        assert no_counts(body)
        # The ledger keeps the same code, and the idempotent replay is identical.
        account = client.get("/api/v2/accounts/b1", headers=h(k["beta"])).json()
        assert account["reasons"] == ["graylisted_ip:graylisted"]

    def test_the_tenant_whose_traffic_it_was_sees_status_too(self, two_tenants):
        client, k = two_tenants()
        body = client.post("/api/v2/check", json=signup("a9", "clean.alpha@gmail.com"), headers=h(k["alpha"])).json()
        assert body["soft_reasons"] == ["graylisted_ip:graylisted"] and no_counts(body)

    def test_blacklisted_ip_is_status_only(self, two_tenants):
        client, k = two_tenants()
        for i in range(5, 8):  # 8 suspicious registrations blacklist the address
            client.post("/api/v2/check", json=signup(f"a{i}", f"role{i}@mailinator.com"), headers=h(k["alpha"]))
        body = client.post("/api/v2/check", json=signup("b2", "late.person@gmail.com"), headers=h(k["beta"])).json()
        assert body["decision"] == "block" and body["block_code"] == "IP_BLACKLISTED"
        assert body["hard_reasons"] == ["blacklisted_ip:blacklisted"] and no_counts(body)

    def test_full_is_ignored_while_other_tenants_are_active(self, two_tenants):
        client, k = two_tenants(beta_config={"ip": {"reason_detail": "full"}})
        body = client.post("/api/v2/check", json=signup("b1", "clean.person@gmail.com"), headers=h(k["beta"])).json()
        assert body["soft_reasons"] == ["graylisted_ip:graylisted"] and no_counts(body)

    def test_operator_override_honours_full(self, two_tenants, clean_env):
        clean_env.setenv("GUARDPOST_ALLOW_FULL_REASON_DETAIL", "1")
        client, k = two_tenants(beta_config={"ip": {"reason_detail": "full"}})
        body = client.post("/api/v2/check", json=signup("b1", "clean.person@gmail.com"), headers=h(k["beta"])).json()
        assert body["soft_reasons"] == ["graylisted_ip:5 suspicious registrations"]
        assert body["signals"]["ip_reason"] == "5 suspicious registrations"
        # Alpha did not ask for full detail: still status only.
        alpha = client.post("/api/v2/check", json=signup("a9", "clean.alpha@gmail.com"), headers=h(k["alpha"])).json()
        assert alpha["soft_reasons"] == ["graylisted_ip:graylisted"]

    def test_tenant_override_reason_is_the_tenants_own(self, two_tenants):
        client, k = two_tenants()
        r = client.put("/api/v2/ip-overrides/203.0.113.9", json={"action": "block"}, headers=h(k["beta"]))
        assert r.status_code == 200
        body = client.post("/api/v2/check", json=signup("b3", "x.person@gmail.com", ip="203.0.113.9"),
                           headers=h(k["beta"])).json()
        assert body["hard_reasons"] == ["blacklisted_ip:tenant override (ip)"]


class TestV1:
    def test_legacy_tenant_keeps_02_strings(self, two_tenants):
        client, _ = two_tenants()
        r = client.post("/api/v1/check", json={"email": "someone.else@gmail.com", "ip_address": FARM_IP,
                                               "record_ip": False}, headers=h("legacy-key"))
        assert r.status_code == 200
        assert r.json()["ip_status"] == "graylisted"
        assert r.json()["ip_reason"] == "5 suspicious registrations"
        ip = client.post("/api/v1/ip/check", json={"ip_address": FARM_IP}, headers=h("legacy-key")).json()
        assert ip == {"ip_address": FARM_IP, "status": "graylisted", "reason": "5 suspicious registrations"}

    def test_other_tenants_get_the_status_only(self, two_tenants):
        client, k = two_tenants()
        r = client.post("/api/v1/check", json={"email": "someone.else@gmail.com", "ip_address": FARM_IP,
                                               "record_ip": False}, headers=h(k["beta"])).json()
        assert r["ip_status"] == "graylisted" and r["ip_reason"] is None and r["subnet_reason"] is None
        ip = client.post("/api/v1/ip/check", json={"ip_address": FARM_IP}, headers=h(k["beta"])).json()
        assert ip == {"ip_address": FARM_IP, "status": "graylisted", "reason": None}


class TestPolicy:
    def _engine(self, tenants, *, override=None):
        async def go():
            storage = MemoryStorage(legacy_tenant="alpha")
            engine = Guardpost(storage=storage, allow_full_reason_detail=override)
            await engine.initialize()
            made = {}
            for tid, (config, status, with_key) in tenants.items():
                await storage.ensure_tenant(tid)
                tenant = await storage.get_tenant(tid)
                tenant.config = TenantConfig.model_validate(config)
                tenant.status = status
                await storage.save_tenant(tenant)
                if with_key:
                    await keys.create_key(storage, tid, "check", label="t")
                made[tid] = await storage.get_tenant(tid)
            return engine, made

        return asyncio.run(go())

    def detail(self, engine, tenant):
        return asyncio.run(engine.reason_detail(tenant))

    def test_default_is_status(self):
        engine, t = self._engine({"alpha": ({}, "active", True)})
        assert self.detail(engine, t["alpha"]) == "status"

    def test_full_for_a_lone_tenant(self):
        full = {"ip": {"reason_detail": "full"}}
        engine, t = self._engine({"alpha": (full, "active", True), "unused": ({}, "active", False),
                                  "gone": ({}, "suspended", True)})
        assert self.detail(engine, t["alpha"]) == "full"

    def test_status_when_another_keyed_tenant_is_active(self):
        full = {"ip": {"reason_detail": "full"}}
        engine, t = self._engine({"alpha": (full, "active", True), "beta": ({}, "active", True)})
        assert self.detail(engine, t["alpha"]) == "status"
        engine, t = self._engine({"alpha": (full, "active", True), "beta": ({}, "active", True)}, override=True)
        assert self.detail(engine, t["alpha"]) == "full"

    def test_config_rejects_other_values(self):
        with pytest.raises(ValueError):
            TenantConfig.model_validate({"ip": {"reason_detail": "counts"}})
        assert TenantConfig().ip.reason_detail == "status"
        assert Tenant(id="x", name="x").config.ip.reason_detail == "status"
