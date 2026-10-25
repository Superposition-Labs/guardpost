"""The v2 check and the ledger operations behind ``/api/v2``.

A check runs in two phases:

1. **email** (async, no database): Factory v2's format, typo and MX gates
   (email signups only) and the suspicion flags, with the injectable DNS;
2. **ledger** (sync, one ``BEGIN IMMEDIATE`` transaction): ban and
   alias-collision gates, shared IP and /24 reputation, device repeat,
   same person, referral flags — and, in commit mode, the writes: the ledger
   row, the shared IP and /24 counters, the referral row. Holding the write
   lock across the reads makes a commit see every earlier commit, so two
   signups from one IP always count +2 and race-free windows.

The rule order and short-circuits are Factory v2's ``register.ts`` (email)
and ``oauth.ts`` (oauth); see guardpost/rules for each rule.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from guardpost import __version__
from guardpost.email.validator import (
    ReasonTier,
    check_registration_suspicion,
    classify_domain_typo,
    validate_deliverability,
    validate_email_format,
)
from guardpost.engine import _compute_risk_score
from guardpost.ip.reputation import IPReputationEngine, IPReputationRecord
from guardpost.ledger import store
from guardpost.ledger.keys import TenantHasher, normalized_email_sha256
from guardpost.ledger.store import LedgerView
from guardpost.models import IMPORT_MAX_ROWS
from guardpost.rules import RULESET
from guardpost.rules.device import device_repeat_reason, registration_fingerprint
from guardpost.rules.namekey import registration_name_key
from guardpost.rules.network import canonical_ip, network_key, subnet_key
from guardpost.rules.policy import (
    ALLOW,
    BLOCK,
    GATES,
    Reason,
    actions_for,
    block_code,
    decide,
    is_suspicious,
    tier_of,
)
from guardpost.rules.referral import ReferralVerdict, evaluate_referral
from guardpost.rules.same_person import find_same_person_reason
from guardpost.rules.signals import SignalKeys

if TYPE_CHECKING:
    from guardpost.engine import Guardpost
    from guardpost.tenancy.models import Tenant

# occurred_at may differ from the server clock by this much without the backfill scope.
CLOCK_SKEW_SECONDS = 15 * 60
# An evaluate check can be committed for this long.
PENDING_SECONDS = 3600


class LedgerError(Exception):
    """A refusal the API maps to an HTTP status with a machine-readable code."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def epoch(value: datetime | None) -> float | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.timestamp()


def iso(value: float | None) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(value, UTC).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _reason_out(reason: Reason, overrides) -> dict:
    return {
        "code": reason.code,
        "kind": reason.kind,
        "tier": tier_of(reason.kind, overrides).value,
        "evidence": dict(reason.evidence) if reason.evidence else None,
    }


@dataclass
class _EmailPhase:
    gates: list[Reason] = field(default_factory=list)  # gates a tenant demoted below hard, in order
    block: Reason | None = None
    flags: list[Reason] = field(default_factory=list)
    suggestion: str | None = None
    typo_source: str | None = None


@dataclass
class _Prepared:
    """Everything the ledger phase needs; built outside the transaction."""

    tenant: Tenant
    hasher: TenantHasher
    mode: str
    idempotency_key: str | None
    request_hmac: str
    occurred: float
    now: float
    method: str
    returning: bool
    account_id: str | None
    ip: str | None
    keys: SignalKeys
    email_phase: _EmailPhase
    overrides: dict
    referrer_account_id: str | None
    started: float
    # The tenant's effective ip.reason_detail is "full" (see Guardpost.reason_detail).
    full_ip_detail: bool = False


class LedgerService:
    def __init__(self, engine: Guardpost) -> None:
        self.engine = engine

    # ------------------------------------------------------------------
    # Plumbing
    # ------------------------------------------------------------------

    @property
    def storage(self):
        return self.engine.storage

    async def _tx(self, fn):
        def run():
            with self.storage.transaction() as conn:
                return fn(conn)

        return await asyncio.to_thread(run)

    async def _read(self, fn):
        def run():
            with self.storage._lock:
                return fn(self.storage._get_conn())

        return await asyncio.to_thread(run)

    def _overrides(self, tenant: Tenant) -> dict:
        return dict(self.engine._scope(tenant).reason_tiers)

    def signal_keys(self, hasher: TenantHasher, *, email: str | None, email_sha256: str | None, ip: str | None,
                    device, name) -> tuple[SignalKeys, str | None]:
        """The keyed signals of one signup (and the canonical IP)."""
        sha = email_sha256.lower() if email_sha256 else (normalized_email_sha256(email) if email else None)
        fingerprint = None
        if device is not None:
            fingerprint = device.fingerprint or registration_fingerprint(device.user_agent, device.accept_language)
        name_key = None
        if name is not None:
            name_key = name.key or registration_name_key(name.first, name.last, name.display, email)
        canon = canonical_ip(ip)
        net = network_key(canon)
        return SignalKeys(
            email_key=hasher.email(sha) if sha else None,
            ip_key=hasher.ip(canon) if canon else None,
            net_key=hasher.net(net) if net else None,
            fp_key=hasher.fingerprint(fingerprint) if fingerprint else None,
            name_key=hasher.name(name_key) if name_key else None,
        ), canon

    # ------------------------------------------------------------------
    # POST /api/v2/check
    # ------------------------------------------------------------------

    async def check(self, tenant: Tenant, req, *, idempotency_key: str | None, backfill: bool) -> dict:
        started = time.perf_counter()
        now = time.time()
        occurred = epoch(req.occurred_at) if req.occurred_at is not None else now
        if occurred > now + CLOCK_SKEW_SECONDS:
            raise LedgerError(422, "occurred_at_in_future", "occurred_at is more than 15 minutes in the future")
        if occurred < now - CLOCK_SKEW_SECONDS and not backfill:
            raise LedgerError(422, "occurred_at_out_of_window",
                              "occurred_at must be within 15 minutes of the server clock; "
                              "replaying older signups needs a key with the backfill scope")
        account_id = req.account.id if req.account else None
        if req.mode == "commit" and account_id is None:
            raise LedgerError(422, "account_required", "mode 'commit' needs account.id")

        hasher = self.engine.hasher(tenant)
        body = req.model_dump(mode="json", exclude={"idempotency_key"})
        request_hmac = hasher.request(canonical_json(body))
        if idempotency_key:
            replay = await self._read(lambda conn: self._replay(LedgerView(conn, tenant.id), idempotency_key,
                                                                request_hmac))
            if replay is not None:
                return replay

        overrides = self._overrides(tenant)
        email_phase = await self._email_phase(tenant, req, overrides)
        keys, ip = self.signal_keys(hasher, email=req.email, email_sha256=req.email_sha256, ip=req.ip,
                                    device=req.device, name=req.name)
        prepared = _Prepared(
            tenant=tenant, hasher=hasher, mode=req.mode, idempotency_key=idempotency_key,
            request_hmac=request_hmac, occurred=occurred, now=now, method=req.signup.method,
            returning=req.signup.returning_user, account_id=account_id, ip=ip, keys=keys,
            email_phase=email_phase, overrides=overrides,
            referrer_account_id=req.referral.referrer_account_id if req.referral else None,
            started=started,
            full_ip_detail=await self.engine.reason_detail(tenant) == "full",
        )
        return await self._tx(lambda conn: self._ledger_phase(conn, prepared))

    def _replay(self, view: LedgerView, idempotency_key: str, request_hmac: str) -> dict | None:
        row = view.check_by_key(idempotency_key)
        if row is None:
            return None
        if row["request_hmac"] != request_hmac:
            raise LedgerError(422, "idempotency_key_reused",
                              "This Idempotency-Key was used with a different request")
        return json.loads(row["result_json"])

    def _flag_ua_domain(self, tenant: Tenant, region: str | None) -> bool:
        rules = tenant.config.region_rules
        if rules.ua_domain is not None:
            return rules.ua_domain
        return (tenant.config.region or region) == "ru"

    async def _email_phase(self, tenant: Tenant, req, overrides) -> _EmailPhase:
        out = _EmailPhase()
        email = req.email
        if not email:
            return out
        scope = self.engine._scope(tenant)
        resolver = self.engine.dns_resolver

        def gate(reason: Reason) -> bool:
            if tier_of(reason.kind, overrides) is ReasonTier.HARD:
                out.block = reason
                return True
            out.gates.append(reason)
            return False

        if req.signup.method == "email":
            # Factory v2 validateNewEmailOrRaise: format, typo, MX (OAuth skips all three:
            # the provider verified the mailbox).
            if not validate_email_format(email)[0]:
                if gate(Reason("invalid_format")):
                    return out
            else:
                typo = classify_domain_typo(email)
                if typo:
                    out.suggestion, out.typo_source = typo
                    if gate(Reason("typo_domain", typo[1], evidence={"suggested_domain": typo[0]})):
                        return out
                if not await validate_deliverability(email, trusted_extra_domains=scope.trusted_extra_domains,
                                                     resolver=resolver):
                    if gate(Reason("undeliverable_domain")):
                        return out
        _, codes = await check_registration_suspicion(
            email, trusted_extra_domains=scope.trusted_extra_domains,
            flag_ua_domain=self._flag_ua_domain(tenant, req.region), resolver=resolver, include_typo=False)
        seen = {g.kind for g in out.gates}
        out.flags = [Reason(code) for code in codes if code not in seen]
        return out

    def _ip_status(self, view: LedgerView, p: _Prepared) -> tuple[str, str | None, str, str | None, str | None]:
        """(ip_status, ip_reason, subnet_status, subnet_reason, override) for the signup's address."""
        cidr = subnet_key(p.ip)
        override = view.ip_override(p.hasher.override("ip", p.ip),
                                    p.hasher.override("net24", cidr) if cidr else None)
        if override is not None:
            action, kind = override
            if action == "block":
                return "blacklisted", f"tenant override ({kind})", "clean", None, "block"
            return "clean", None, "clean", None, "allow"
        ip_record = view.load_ip(p.ip)
        ip_status, ip_reason = IPReputationEngine.status_of(ip_record)
        subnet_status, subnet_reason = "clean", None
        if cidr and not (ip_record is not None and ip_record.manually_whitelisted):
            subnet_status, subnet_reason = IPReputationEngine.status_of(view.load_ip(cidr))
        return ip_status, ip_reason, subnet_status, subnet_reason, None

    def _ledger_phase(self, conn, p: _Prepared) -> dict:
        view = LedgerView(conn, p.tenant.id)
        if p.idempotency_key:
            replay = self._replay(view, p.idempotency_key, p.request_hmac)
            if replay is not None:
                return replay
        if p.mode == "commit" and view.account(p.account_id) is not None:
            raise LedgerError(409, "account_exists", f"Account {p.account_id!r} is already in the ledger")

        cfg = p.tenant.config
        keys = p.keys
        reasons: list[Reason] = list(p.email_phase.gates)
        blocked: Reason | None = p.email_phase.block
        ip_status, ip_reason, subnet_status, subnet_reason, override = "clean", None, "clean", None, None

        def gate(reason: Reason) -> bool:
            nonlocal blocked
            if tier_of(reason.kind, p.overrides) is ReasonTier.HARD:
                blocked = reason
                return True
            reasons.append(reason)
            return False

        def alias_gate() -> bool:
            if not keys.email_key:
                return False
            other = view.alias_collision(keys.email_key, until=p.occurred, exclude=p.account_id)
            return other is not None and gate(Reason("alias_collision", other, evidence={"account_id": other}))

        if blocked is None:
            stop = bool(keys.email_key and view.is_banned(keys.email_key)) and gate(Reason("banned_email"))
            if not stop:
                if p.method == "email":  # register.ts: flags, then the alias collision
                    reasons.extend(p.email_phase.flags)
                    alias_gate()
                elif not alias_gate():  # oauth.ts: the alias collision, then flags
                    reasons.extend(p.email_phase.flags)

        if blocked is None and p.ip:
            ip_status, ip_reason, subnet_status, subnet_reason, override = self._ip_status(view, p)
            # The shared table's status reasons count every tenant's signups: by default a
            # response names the status only. A tenant override's reason is the tenant's own.
            ip_detail = ip_reason
            if not p.full_ip_detail:
                subnet_reason = None
                if override is None:
                    ip_reason = None
                    ip_detail = ip_status
            if ip_status == "blacklisted":
                gate(Reason("blacklisted_ip", ip_detail))
            else:
                if ip_status == "graylisted" and not is_suspicious(reasons, p.overrides):
                    reasons.append(Reason("graylisted_ip", ip_detail))
                if ip_status == "clean" and subnet_status != "clean" and not is_suspicious(reasons, p.overrides):
                    reasons.append(Reason("subnet_burst", subnet_key(p.ip)))

        if blocked is None:
            new_account = p.method == "email" or not p.returning
            # Device repeat: clean signups only; OAuth also skips returning users.
            if new_account and not is_suspicious(reasons, p.overrides):
                reason = device_repeat_reason(view, keys, p.occurred, window_days=cfg.device_repeat.window_days,
                                              threshold=cfg.device_repeat.prior_threshold, exclude=p.account_id)
                if reason:
                    reasons.append(reason)
            # Same person: always on the email path (even when already flagged, so the
            # code is retracted); OAuth skips returning users.
            if new_account:
                reason = find_same_person_reason(
                    view, keys, p.occurred, device_window_days=cfg.same_person.device_window_days,
                    name_window_days=cfg.same_person.name_window_days, exclude=p.account_id)
                if reason:
                    reasons.append(reason)
        else:
            reasons.append(blocked)

        decision = decide(reasons, p.overrides)
        referral = self._referral(view, p, decision)
        result = self._result(p, reasons, decision, referral, ip_status, ip_reason, subnet_status, subnet_reason,
                              override)
        commit_data = {
            "keys": {"email_key": keys.email_key, "fp_key": keys.fp_key, "ip_key": keys.ip_key,
                     "net_key": keys.net_key, "name_key_h": keys.name_key},
            "occurred": p.occurred,
            "decision": decision,
            "reasons": [r.code for r in reasons],
            "method": p.method,
            "returning": p.returning,
            "referrer_account_id": p.referrer_account_id,
            "referral": referral.to_dict() if referral else None,
            # evaluate: the account the app announced (it was excluded from the matches).
            "account_hint": p.account_id,
        }
        latency = (time.perf_counter() - p.started) * 1000.0
        if p.mode == "commit":
            self._write_commit(view, p.hasher, commit_data, p.ip, p.account_id, result["check_id"], p.now)
        view.insert_check(
            check_id=result["check_id"], idempotency_key=p.idempotency_key, request_hmac=p.request_hmac,
            mode=p.mode, created_at=p.now, occurred_at=p.occurred,
            pending_until=p.now + PENDING_SECONDS if p.mode == "evaluate" else None,
            committed_at=p.now if p.mode == "commit" else None,
            account_id=p.account_id if p.mode == "commit" else None,
            ip_sealed=p.hasher.seal(result["check_id"], p.ip) if p.mode == "evaluate" and p.ip else None,
            commit_json=json.dumps(commit_data), result_json=json.dumps(result), latency_ms=latency,
        )
        return result

    def _referral(self, view: LedgerView, p: _Prepared, decision: str) -> ReferralVerdict | None:
        if p.referrer_account_id is None:
            return None
        if p.returning:
            return ReferralVerdict(False, reason="returning_user")
        if decision != ALLOW:
            return ReferralVerdict(False, reason=f"signup_{decision}")
        cfg = p.tenant.config.referral
        return evaluate_referral(
            view, referrer_account_id=p.referrer_account_id, referred_account_id=p.account_id,
            ip_key=p.keys.ip_key, now=p.occurred, same_ip_limit=cfg.same_ip_limit,
            velocity_24h=cfg.velocity_24h, velocity_7d=cfg.velocity_7d)

    def _result(self, p: _Prepared, reasons, decision, referral, ip_status, ip_reason, subnet_status,
                subnet_reason, override) -> dict:
        tiers: dict[str, list[str]] = {t.value: [] for t in ReasonTier}
        for r in reasons:
            tiers[tier_of(r.kind, p.overrides).value].append(r.code)
        codes = [r.code for r in reasons]
        banned = any(r.kind == "banned_email" for r in reasons)
        return {
            "check_id": "chk_" + secrets.token_hex(12),
            "decision": decision,
            "block_code": block_code(reasons, p.overrides) if decision == BLOCK else None,
            "risk_score": _compute_risk_score(codes, ip_status, banned, subnet_status),
            "reasons": [_reason_out(r, p.overrides) for r in reasons],
            "hard_reasons": tiers["hard"],
            "soft_reasons": tiers["soft"],
            "weak_reasons": tiers["weak"],
            "actions": actions_for(decision, reasons, returning_user=p.returning),
            "referral": referral.to_dict() if referral else None,
            "suggestion": p.email_phase.suggestion,
            "signals": {
                "method": p.method,
                "returning_user": p.returning,
                "ip_status": ip_status,
                "ip_reason": ip_reason,
                "subnet_status": subnet_status,
                "subnet_reason": subnet_reason,
                "ip_override": override,
                "global_ip": p.keys.net_key is not None,
                "fingerprint": p.keys.fp_key is not None,
                "name_key": p.keys.name_key is not None,
                "typo_source": p.email_phase.typo_source,
            },
            "mode": p.mode,
            "committed": p.mode == "commit",
            "account_id": p.account_id if p.mode == "commit" else None,
            "occurred_at": iso(p.occurred),
            "ruleset": RULESET,
            "engine_version": __version__,
        }

    def _bump_ip(self, view: LedgerView, ip: str, suspicious: bool, at: float) -> IPReputationRecord:
        when = datetime.fromtimestamp(at, UTC)
        engine = self.engine.ip_engine
        record = engine.apply_registration(view.load_ip(ip), ip, suspicious, when)
        view.store_ip(record)
        cidr = subnet_key(ip)
        if cidr and engine.track_subnets:
            view.store_ip(engine.apply_registration(view.load_ip(cidr), cidr, suspicious, when))
        return record

    def _write_commit(self, view: LedgerView, hasher: TenantHasher, data: dict, ip: str | None,
                      account_id: str, check_id: str, now: float) -> dict | None:
        """The commit writes, in the caller's transaction. Returns the referral actually written."""
        keys = data["keys"]
        occurred = data["occurred"]
        suspicious = data["decision"] != ALLOW
        view.insert_account(
            account_id=account_id, created_at=occurred, now=now, email_key=keys["email_key"],
            fp_key=keys["fp_key"], ip_key=keys["ip_key"], net_key=keys["net_key"], name_key_h=keys["name_key_h"],
            decision=data["decision"], reasons=data["reasons"], method=data["method"],
            returning_user=data["returning"], source="check", check_id=check_id)
        referral = data.get("referral")
        if referral and referral["attribute"]:
            if data["referrer_account_id"] == account_id:
                referral = {"attribute": False, "suspicious": False, "reason": "self_referral"}
            else:
                view.upsert_referral(referred_account_id=account_id, referrer_account_id=data["referrer_account_id"],
                                     ip_key=keys["ip_key"], created_at=occurred, suspicious=referral["suspicious"],
                                     reason=referral["reason"])
        ip_status = None
        if ip:
            record = self._bump_ip(view, ip, suspicious, occurred)
            ip_status = "whitelisted" if record.manually_whitelisted else record.status
        view.record_registration_event(ts=occurred, suspicious=suspicious, ip_key=keys["ip_key"],
                                       ip_status=ip_status)
        return referral

    # ------------------------------------------------------------------
    # POST /api/v2/accounts (commit an evaluated check)
    # ------------------------------------------------------------------

    async def commit(self, tenant: Tenant, check_id: str, account_id: str) -> dict:
        hasher = self.engine.hasher(tenant)

        def run(conn):
            view = LedgerView(conn, tenant.id)
            row = view.check_by_id(check_id)
            if row is None:
                raise LedgerError(404, "check_not_found", "No such check (checks are kept for 24 hours)")
            data = json.loads(row["commit_json"])
            if row["committed_at"] is not None:
                if row["account_id"] == account_id:
                    return data.get("committed_result") or json.loads(row["result_json"])
                raise LedgerError(409, "check_already_committed",
                                  "This check was committed for another account")
            now = time.time()
            if row["pending_until"] is None or row["pending_until"] < now:
                raise LedgerError(410, "check_expired", "An evaluated check can be committed for 1 hour")
            if data.get("account_hint") not in (None, account_id):
                raise LedgerError(409, "account_mismatch",
                                  "The check was evaluated for another account.id; evaluate again")
            if view.account(account_id) is not None:
                raise LedgerError(409, "account_exists", f"Account {account_id!r} is already in the ledger")
            ip = hasher.unseal(check_id, row["ip_sealed"]) if row["ip_sealed"] else None
            referral = self._write_commit(view, hasher, data, ip, account_id, check_id, now)
            result = json.loads(row["result_json"])
            result.update(committed=True, account_id=account_id)
            if result.get("referral") is not None:
                result["referral"] = referral
            data["committed_result"] = result
            view.mark_committed(check_id, account_id, now)
            conn.execute("UPDATE checks SET commit_json = ? WHERE tenant_id = ? AND check_id = ?",
                         (json.dumps(data), tenant.id, check_id))
            return result

        return await self._tx(run)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _email_key(self, hasher: TenantHasher, email: str | None, email_sha256: str | None) -> str | None:
        if email_sha256:
            return hasher.email(email_sha256)
        if email:
            return hasher.email(normalized_email_sha256(email))
        return None

    async def event(self, tenant: Tenant, account_id: str, ev) -> dict:
        hasher = self.engine.hasher(tenant)
        now = time.time()
        at = epoch(ev.occurred_at) if ev.occurred_at is not None else now
        given_key = self._email_key(hasher, ev.email, ev.email_sha256)

        def run(conn):
            view = LedgerView(conn, tenant.id)
            if ev.idempotency_key:
                prior = view.event_by_key(ev.idempotency_key)
                if prior is not None:
                    if prior["account_id"] != account_id or prior["type"] != ev.type:
                        raise LedgerError(422, "idempotency_key_reused",
                                          "This idempotency key was used for another event")
                    return {"account_id": account_id, "type": ev.type, "applied": False, "duplicate": True,
                            "event_id": prior["id"]}
            row = view.account(account_id)
            if row is None:
                if ev.type != "created":
                    raise LedgerError(404, "account_not_found", f"No account {account_id!r} in the ledger")
                view.insert_account(account_id=account_id, created_at=at, now=now, email_key=given_key,
                                    source="event")
            extra: dict[str, Any] = {}
            if ev.type == "deleted":
                view.set_account(account_id, now, deleted_at=at, email_key=None)
            elif ev.type == "banned":
                view.set_account(account_id, now, banned_at=at)
                if ev.permanent_email_ban:
                    key = given_key or (row["email_key"] if row is not None else None)
                    if key is None:
                        raise LedgerError(422, "email_unknown",
                                          "The account has no email on record (deleted?): send email or "
                                          "email_sha256 with a permanent_email_ban")
                    extra["email_ban_created"] = view.put_ban(key, banned_at=at, banned_by=ev.actor,
                                                              reason=ev.reason)
            elif ev.type == "unbanned":
                # A permanent email ban stays (Factory v2 unban); DELETE /api/v2/bans lifts it.
                view.set_account(account_id, now, banned_at=None)
            elif ev.type == "paid":
                if row is None or row["paid_at"] is None:
                    view.set_account(account_id, now, paid_at=at)
            elif ev.type == "flagged":
                view.set_account(account_id, now, flagged_at=at)
            elif ev.type == "unflagged":
                view.set_account(account_id, now, flagged_at=None)
            elif ev.type == "referral_code_retracted":
                view.set_account(account_id, now, referral_code_retracted_at=at)
            elif ev.type == "referral_code_restored":
                view.set_account(account_id, now, referral_code_retracted_at=None)
            data = {k: v for k, v in (("reason", ev.reason), ("actor", ev.actor),
                                      ("permanent_email_ban", ev.permanent_email_ban or None)) if v}
            event_id = view.insert_event(account_id=account_id, type=ev.type, occurred_at=at, now=now,
                                         idempotency_key=ev.idempotency_key, data=data)
            return {"account_id": account_id, "type": ev.type, "applied": True, "duplicate": False,
                    "event_id": event_id, **extra}

        return await self._tx(run)

    async def put_ban(self, tenant: Tenant, body) -> dict:
        key = self._email_key(self.engine.hasher(tenant), body.email, body.email_sha256)
        at = epoch(body.banned_at) if getattr(body, "banned_at", None) else time.time()
        created = await self._tx(lambda conn: LedgerView(conn, tenant.id).put_ban(
            key, banned_at=at, banned_by=body.banned_by, reason=body.reason))
        return {"banned": True, "created": created}

    async def delete_ban(self, tenant: Tenant, body) -> dict:
        key = self._email_key(self.engine.hasher(tenant), body.email, body.email_sha256)
        removed = await self._tx(lambda conn: LedgerView(conn, tenant.id).delete_ban(key))
        return {"banned": False, "removed": removed}

    async def put_override(self, tenant: Tenant, kind: str, target: str, body) -> dict:
        hasher = self.engine.hasher(tenant)
        now = time.time()
        await self._tx(lambda conn: LedgerView(conn, tenant.id).put_override(
            target_key=hasher.override(kind, target), kind=kind, action=body.action, reason=body.reason,
            created_by=body.created_by, now=now))
        return {"target": target, "kind": kind, "action": body.action}

    async def delete_override(self, tenant: Tenant, kind: str, target: str) -> dict:
        hasher = self.engine.hasher(tenant)
        removed = await self._tx(lambda conn: LedgerView(conn, tenant.id).delete_override(
            hasher.override(kind, target)))
        return {"target": target, "kind": kind, "removed": removed}

    # ------------------------------------------------------------------
    # Imports (backfill)
    # ------------------------------------------------------------------

    async def import_accounts(self, tenant: Tenant, rows) -> dict:
        hasher = self.engine.hasher(tenant)
        now = time.time()
        prepared = []
        for row in rows:
            keys, _ = self.signal_keys(hasher, email=row.email, email_sha256=row.email_sha256, ip=row.ip,
                                       device=row.device, name=row.name)
            flags = {f: epoch(getattr(row, f)) for f in store.ACCOUNT_FLAGS}
            prepared.append((row, keys, flags))

        def run(conn):
            view = LedgerView(conn, tenant.id)
            inserted = 0
            for row, keys, flags in prepared:
                inserted += view.upsert_imported_account(
                    account_id=row.account_id, created_at=epoch(row.created_at), now=now,
                    keys={"email_key": keys.email_key, "fp_key": keys.fp_key, "ip_key": keys.ip_key,
                          "net_key": keys.net_key, "name_key_h": keys.name_key},
                    flags=flags, decision=row.decision, reasons=list(row.reasons or []))
            return {"received": len(prepared), "inserted": inserted, "updated": len(prepared) - inserted}

        return await self._tx(run)

    async def import_bans(self, tenant: Tenant, rows) -> dict:
        hasher = self.engine.hasher(tenant)
        now = time.time()
        items = [(self._email_key(hasher, r.email, r.email_sha256),
                  epoch(r.banned_at) if r.banned_at else now, r.banned_by, r.reason) for r in rows]

        def run(conn):
            view = LedgerView(conn, tenant.id)
            inserted = 0
            for key, at, by, reason in items:
                if view.put_ban(key, banned_at=at, banned_by=by, reason=reason):
                    inserted += 1
                else:
                    conn.execute("UPDATE bans SET banned_by = ?, reason = ? WHERE tenant_id = ? AND email_hash = ?",
                                 (by, reason, tenant.id, key))
            return {"received": len(items), "inserted": inserted, "updated": len(items) - inserted}

        return await self._tx(run)

    async def import_referrals(self, tenant: Tenant, rows) -> dict:
        hasher = self.engine.hasher(tenant)
        items = []
        for r in rows:
            canon = canonical_ip(r.ip)
            items.append((r, hasher.ip(canon) if canon else None))

        def run(conn):
            view = LedgerView(conn, tenant.id)
            inserted = 0
            for r, ip_key in items:
                inserted += view.upsert_referral(
                    referred_account_id=r.referred_account_id, referrer_account_id=r.referrer_account_id,
                    ip_key=ip_key, created_at=epoch(r.created_at), suspicious=r.suspicious, reason=r.reason)
            return {"received": len(items), "inserted": inserted, "updated": len(items) - inserted}

        return await self._tx(run)

    async def import_ip_reputation(self, rows) -> dict:
        """Merge rows into the SHARED reputation table (admin): higher counters win,
        the earliest first and latest last registration win, the worse status wins
        (blacklisted > graylisted > clean), a whitelist is kept."""
        incoming = [ip_record_from_import(r) for r in rows]

        def run(conn):
            view = LedgerView(conn, "")
            inserted = 0
            for record in incoming:
                existing = view.load_ip(record.ip_address)
                inserted += existing is None
                view.store_ip(merge_ip_records(existing, record))
            return {"received": len(incoming), "inserted": inserted, "updated": len(incoming) - inserted}

        return await self._tx(run)

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    async def stats(self, tenant: Tenant, days: int) -> dict:
        now = time.time()
        out = await self._read(lambda conn: LedgerView(conn, tenant.id).stats(since=now - days * store.DAY, now=now))
        return {"tenant_id": tenant.id, "days": days, "ruleset": RULESET, **out}

    async def account(self, tenant: Tenant, account_id: str) -> dict:
        def run(conn):
            view = LedgerView(conn, tenant.id)
            row = view.account(account_id)
            if row is None:
                raise LedgerError(404, "account_not_found", f"No account {account_id!r} in the ledger")
            referral = view.referral_of(account_id)
            return {
                "account_id": account_id,
                "created_at": iso(row["created_at"]),
                "source": row["source"],
                "method": row["method"],
                "decision": row["decision"],
                "reasons": json.loads(row["reasons_json"] or "[]"),
                "returning_user": bool(row["returning_user"]),
                "check_id": row["check_id"],
                "signals": {
                    "email": row["email_key"] is not None,
                    "fingerprint": row["fp_key"] is not None,
                    "ip": row["ip_key"] is not None,
                    "global_ip": row["net_key"] is not None,
                    "name_key": row["name_key_h"] is not None,
                    "purged_at": iso(row["signals_purged_at"]),
                },
                **{f: iso(row[f]) for f in store.ACCOUNT_FLAGS},
                "referred_by": None if referral is None else {
                    "referrer_account_id": referral["referrer_account_id"],
                    "created_at": iso(referral["created_at"]),
                    "suspicious": bool(referral["suspicious"]),
                    "reason": referral["reason"],
                },
                "referred_accounts": view.referred_count(account_id),
            }

        return await self._read(run)

    # ------------------------------------------------------------------
    # Retention
    # ------------------------------------------------------------------

    async def purge(self, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        tenants = await self.storage.list_tenants()
        retention = {t.id: (t.config.retention.signals_days, t.config.retention.events_days) for t in tenants}
        return await self._tx(lambda conn: store.purge(conn, now=now, tenant_retention=retention))


_STATUS_RANK = {"clean": 0, "graylisted": 1, "blacklisted": 2}


def _aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def ip_record_from_import(row) -> IPReputationRecord:
    return IPReputationRecord(
        ip_address=row.ip_address,
        total_registrations=row.total_registrations,
        suspicious_registrations=row.suspicious_registrations,
        first_registration_at=_aware(row.first_registration_at),
        last_registration_at=_aware(row.last_registration_at),
        status=row.status,
        status_reason=row.status_reason,
        status_changed_at=_aware(row.status_changed_at),
        manually_whitelisted=row.manually_whitelisted,
        whitelisted_by="import" if row.manually_whitelisted else None,
        whitelist_reason="imported" if row.manually_whitelisted else None,
    )


def merge_ip_records(existing: IPReputationRecord | None, incoming: IPReputationRecord) -> IPReputationRecord:
    if existing is None:
        return incoming
    firsts = [d for d in (_aware(existing.first_registration_at), incoming.first_registration_at) if d]
    lasts = [d for d in (_aware(existing.last_registration_at), incoming.last_registration_at) if d]
    worse = incoming if _STATUS_RANK.get(incoming.status, 0) > _STATUS_RANK.get(existing.status, 0) else existing
    whitelisted = existing.manually_whitelisted or incoming.manually_whitelisted
    keeper = existing if existing.manually_whitelisted else incoming
    return IPReputationRecord(
        ip_address=existing.ip_address,
        total_registrations=max(existing.total_registrations, incoming.total_registrations),
        suspicious_registrations=max(existing.suspicious_registrations, incoming.suspicious_registrations),
        first_registration_at=min(firsts) if firsts else None,
        last_registration_at=max(lasts) if lasts else None,
        status=worse.status,
        status_reason=worse.status_reason,
        status_changed_at=_aware(worse.status_changed_at),
        manually_whitelisted=whitelisted,
        whitelisted_by=keeper.whitelisted_by if whitelisted else None,
        whitelist_reason=keeper.whitelist_reason if whitelisted else None,
    )


__all__ = ["GATES", "IMPORT_MAX_ROWS", "LedgerError", "LedgerService", "merge_ip_records"]
