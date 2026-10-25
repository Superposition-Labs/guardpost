"""The v2 REST API (``/api/v2/*``): the server-side signup check and its ledger.

Every route acts as the tenant of the request's API key and needs a real
``GUARDPOST_SECRET`` (503 otherwise; see :meth:`Guardpost.ledger_refusal`).
Scopes (the v1 ``legacy`` scope grants none of them):

- ``check``: POST /check, POST /accounts (commit an evaluated check)
- ``lifecycle``: account events, bans, IP overrides
- ``dashboard``: GET /stats, GET /accounts/{id}
- ``backfill``: POST /import/*, and occurred_at older than 15 minutes on /check
- ``admin``: POST /admin/ip-reputation/import (the shared, all-tenant table)

Nothing a v2 route returns carries an email or an IP: evidence names the
tenant's own opaque account ids.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from guardpost.api.deps import get_engine, require_scope
from guardpost.ledger.service import IMPORT_MAX_ROWS, LedgerError, LedgerService
from guardpost.ledger.store import EVENT_TYPES
from guardpost.rules.network import canonical_ip
from guardpost.tenancy.models import TenantContext

ACCOUNT_ID_PATTERN = r"^[A-Za-z0-9._:-]{1,128}$"
SHA256_PATTERN = r"^[0-9a-f]{64}$"


def _ledger_service(request: Request) -> LedgerService:
    engine = get_engine(request)
    refusal = engine.ledger_refusal()
    if refusal:
        raise HTTPException(status_code=503, detail=refusal)
    service = getattr(request.app.state, "ledger", None)
    if service is None or service.engine is not engine:
        service = request.app.state.ledger = LedgerService(engine)
    return service


def _scoped(scope: str):
    return Depends(require_scope(scope, v1=False))


LedgerDep = Annotated[LedgerService, Depends(_ledger_service)]
CheckCtx = Annotated[TenantContext, _scoped("check")]
LifecycleCtx = Annotated[TenantContext, _scoped("lifecycle")]
DashboardCtx = Annotated[TenantContext, _scoped("dashboard")]
BackfillCtx = Annotated[TenantContext, _scoped("backfill")]
AdminCtx = Annotated[TenantContext, _scoped("admin")]

_ERRORS = {
    401: {"description": "Invalid or missing API key"},
    403: {"description": "The key lacks the scope, or the tenant is suspended"},
    503: {"description": "No GUARDPOST_SECRET (or no SQLite storage): the v2 ledger is disabled"},
}


def _raise(exc: LedgerError):
    raise HTTPException(status_code=exc.status, detail={"code": exc.code, "message": exc.message}) from exc


router = APIRouter(prefix="/api/v2", tags=["v2"], responses=_ERRORS)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _validate_ip(value: str | None) -> str | None:
    if value is not None and canonical_ip(value) is None:
        raise ValueError("invalid IP address")
    return value


class Signup(_In):
    method: Literal["email", "oauth"] = Field(
        default="email", description="email: the format, typo and MX gates run; oauth: they are skipped")
    oauth_provider: str | None = Field(default=None, max_length=32, pattern=r"^[a-z0-9_-]+$")
    returning_user: bool = Field(
        default=False,
        description="The address belonged to a deleted account. No welcome credits or referral; OAuth also "
                    "skips the device and same-person rules")


class Device(_In):
    user_agent: str | None = Field(default=None, max_length=2048)
    accept_language: str | None = Field(default=None, max_length=512)
    fingerprint: str | None = Field(
        default=None, pattern=SHA256_PATTERN,
        description="sha256(User-Agent|Accept-Language), lowercase hex, instead of the headers")

    @model_validator(mode="after")
    def _one_form(self):
        if self.fingerprint and (self.user_agent or self.accept_language):
            raise ValueError("send either fingerprint or user_agent/accept_language")
        return self


class Name(_In):
    first: str | None = Field(default=None, max_length=256)
    last: str | None = Field(default=None, max_length=256)
    display: str | None = Field(default=None, max_length=256)
    key: str | None = Field(default=None, max_length=512, description="A precomputed name key instead")

    @model_validator(mode="after")
    def _one_form(self):
        if self.key and (self.first or self.last or self.display):
            raise ValueError("send either key or first/last/display")
        return self


class ReferralIn(_In):
    referrer_account_id: str = Field(pattern=ACCOUNT_ID_PATTERN)
    code: str | None = Field(default=None, max_length=64)


class AccountRef(_In):
    id: str = Field(pattern=ACCOUNT_ID_PATTERN, description="The tenant's own opaque account id (no '@')")


class _EmailOrHash(_In):
    email: str | None = Field(default=None, max_length=254)
    email_sha256: str | None = Field(
        default=None, pattern=SHA256_PATTERN,
        description="sha256 hex of the alias-normalized address (Factory v2 normalized_email_hash)")

    @model_validator(mode="after")
    def _exclusive(self):
        if self.email and self.email_sha256:
            raise ValueError("send either email or email_sha256")
        return self


class CheckRequest(_EmailOrHash):
    mode: Literal["evaluate", "commit"] = Field(
        default="evaluate",
        description="evaluate: read-only, keeps a pending check for 1 hour (commit it with POST /api/v2/accounts); "
                    "commit: evaluate and record the account in one call")
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200,
                                        description="Or the Idempotency-Key header")
    occurred_at: datetime | None = Field(
        default=None, description="When the signup happened (default: now). More than 15 minutes in the past "
                                  "needs the backfill scope")
    signup: Signup = Field(default_factory=Signup)
    ip: str | None = Field(default=None, max_length=64)
    device: Device | None = None
    name: Name | None = None
    referral: ReferralIn | None = None
    account: AccountRef | None = None
    region: str | None = Field(default=None, pattern=r"^[a-z]{2,16}$",
                               description="Region rules when the tenant config sets none (ru: ua_domain)")

    _ip = field_validator("ip")(_validate_ip)

    @model_validator(mode="after")
    def _needs_identity(self):
        if not self.email and not self.email_sha256:
            raise ValueError("email or email_sha256 is required")
        return self


class CommitRequest(_In):
    check_id: str = Field(min_length=1, max_length=64)
    account_id: str = Field(pattern=ACCOUNT_ID_PATTERN)


class EventRequest(_EmailOrHash):
    type: Literal[EVENT_TYPES]  # type: ignore[valid-type]
    occurred_at: datetime | None = None
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)
    permanent_email_ban: bool = Field(default=False, description="banned: also ban the address for this tenant")
    reason: str | None = Field(default=None, max_length=500)
    actor: str | None = Field(default=None, max_length=128)


class BanRequest(_EmailOrHash):
    reason: str | None = Field(default=None, max_length=500)
    banned_by: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def _needs_identity(self):
        if not self.email and not self.email_sha256:
            raise ValueError("email or email_sha256 is required")
        return self


class UnbanRequest(_EmailOrHash):
    @model_validator(mode="after")
    def _needs_identity(self):
        if not self.email and not self.email_sha256:
            raise ValueError("email or email_sha256 is required")
        return self


class OverrideRequest(_In):
    action: Literal["allow", "block"] = Field(
        description="allow: the address (or /24) is clean for this tenant; block: refused (IP_BLACKLISTED)")
    reason: str | None = Field(default=None, max_length=500)
    created_by: str | None = Field(default=None, max_length=128)


class AccountImport(_EmailOrHash):
    account_id: str = Field(pattern=ACCOUNT_ID_PATTERN)
    created_at: datetime
    ip: str | None = Field(default=None, max_length=64)
    device: Device | None = None
    name: Name | None = None
    deleted_at: datetime | None = None
    banned_at: datetime | None = None
    paid_at: datetime | None = None
    flagged_at: datetime | None = None
    referral_code_retracted_at: datetime | None = None
    decision: Literal["allow", "degrade", "block"] | None = None
    reasons: list[str] | None = Field(default=None, max_length=50)

    _ip = field_validator("ip")(_validate_ip)


class BanImport(_EmailOrHash):
    banned_at: datetime | None = None
    banned_by: str | None = Field(default=None, max_length=128)
    reason: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _needs_identity(self):
        if not self.email and not self.email_sha256:
            raise ValueError("email or email_sha256 is required")
        return self


class ReferralImport(_In):
    referred_account_id: str = Field(pattern=ACCOUNT_ID_PATTERN)
    referrer_account_id: str = Field(pattern=ACCOUNT_ID_PATTERN)
    created_at: datetime
    ip: str | None = Field(default=None, max_length=64)
    suspicious: bool = False
    reason: str | None = Field(default=None, max_length=200)

    _ip = field_validator("ip")(_validate_ip)


class IPReputationImport(_In):
    ip_address: str = Field(max_length=64, description="An address, or an IPv4 /24 such as 203.0.113.0/24")
    total_registrations: int = Field(ge=0)
    suspicious_registrations: int = Field(default=0, ge=0)
    first_registration_at: datetime | None = None
    last_registration_at: datetime | None = None
    status: Literal["clean", "graylisted", "blacklisted"] = "clean"
    status_reason: str | None = Field(default=None, max_length=200)
    status_changed_at: datetime | None = None
    manually_whitelisted: bool = False

    @field_validator("ip_address")
    @classmethod
    def _key(cls, v: str) -> str:
        return ip_reputation_key(v)


def ip_reputation_key(value: str) -> str:
    """The shared table's key: a canonical address, or a canonical IPv4 /24."""
    value = value.strip()
    if "/" in value:
        net = ipaddress.ip_network(value, strict=False)
        if net.version != 4 or net.prefixlen != 24:
            raise ValueError("only single addresses and IPv4 /24 networks are tracked")
        return str(net)
    canon = canonical_ip(value)
    if canon is None:
        raise ValueError("invalid IP address")
    return canon


_ROWS = Field(min_length=1, max_length=IMPORT_MAX_ROWS, description=f"1 to {IMPORT_MAX_ROWS} rows")


class AccountsImportRequest(_In):
    rows: list[AccountImport] = _ROWS


class BansImportRequest(_In):
    rows: list[BanImport] = _ROWS


class ReferralsImportRequest(_In):
    rows: list[ReferralImport] = _ROWS


class IPReputationImportRequest(_In):
    rows: list[IPReputationImport] = _ROWS


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class ReasonOut(BaseModel):
    code: str = Field(description="Factory's kind:detail form, e.g. subnet_burst:203.0.114.0/24, same_device:acc1")
    kind: str
    tier: Literal["hard", "soft", "weak"]
    evidence: dict | None = Field(default=None, description="Opaque facts: the tenant's own account ids, counts")


class ReferralOut(BaseModel):
    attribute: bool = Field(description="Record the referral (false: no attribution at all)")
    suspicious: bool = Field(description="Attribute it, but flagged: the referee gets no referral bonus")
    reason: str | None = None


class SignalsOut(BaseModel):
    method: str
    returning_user: bool
    ip_status: str
    ip_reason: str | None
    subnet_status: str
    subnet_reason: str | None
    ip_override: Literal["allow", "block"] | None
    global_ip: bool
    fingerprint: bool
    name_key: bool
    typo_source: str | None


class CheckResponse(BaseModel):
    check_id: str
    decision: Literal["allow", "degrade", "block"]
    block_code: str | None = Field(
        description="On block, the Factory v2 refusal it reproduces: EMAIL_INVALID_FORMAT, EMAIL_TYPO_SUSPECTED, "
                    "EMAIL_DOMAIN_UNDELIVERABLE, EMAIL_BANNED, EMAIL_ALIAS_EXISTS, IP_BLACKLISTED, POLICY_BLOCK")
    risk_score: int
    reasons: list[ReasonOut]
    hard_reasons: list[str]
    soft_reasons: list[str]
    weak_reasons: list[str]
    actions: list[Literal["no_welcome_credits", "no_referral_attribution", "no_referral_payouts",
                          "retract_referral_code"]]
    referral: ReferralOut | None
    suggestion: str | None = Field(description="EMAIL_TYPO_SUSPECTED: the domain the user probably meant")
    signals: SignalsOut
    mode: Literal["evaluate", "commit"]
    committed: bool
    account_id: str | None
    occurred_at: str
    ruleset: str
    engine_version: str


class EventResponse(BaseModel):
    account_id: str
    type: str
    applied: bool
    duplicate: bool
    event_id: int
    email_ban_created: bool | None = None


class BanResponse(BaseModel):
    banned: bool
    created: bool | None = None
    removed: bool | None = None


class OverrideResponse(BaseModel):
    target: str
    kind: Literal["ip", "net24"]
    action: Literal["allow", "block"] | None = None
    removed: bool | None = None


class ImportResponse(BaseModel):
    received: int
    inserted: int
    updated: int


class LatencyOut(BaseModel):
    samples: int
    p50: float | None
    p95: float | None


class ReferralStatsOut(BaseModel):
    total: int
    suspicious: int


class StatsResponse(BaseModel):
    tenant_id: str
    days: int
    ruleset: str
    accounts: int
    decisions: dict[str, int]
    reasons: dict[str, int] = Field(description="Reason kind -> committed accounts carrying it")
    degraded: int
    degraded_then_paid: int
    referrals: ReferralStatsOut
    bans: int
    pending_checks: int
    latency_ms: LatencyOut = Field(description="Check latency over the last 24 hours (checks retention)")


class AccountSignalsOut(BaseModel):
    email: bool
    fingerprint: bool
    ip: bool
    global_ip: bool
    name_key: bool
    purged_at: str | None


class ReferredByOut(BaseModel):
    referrer_account_id: str
    created_at: str
    suspicious: bool
    reason: str | None


class AccountResponse(BaseModel):
    account_id: str
    created_at: str
    source: str
    method: str | None
    decision: str | None
    reasons: list[str]
    returning_user: bool
    check_id: str | None
    signals: AccountSignalsOut
    deleted_at: str | None
    banned_at: str | None
    paid_at: str | None
    flagged_at: str | None
    referral_code_retracted_at: str | None
    referred_by: ReferredByOut | None
    referred_accounts: int


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/check", response_model=CheckResponse, summary="Evaluate (and optionally commit) a signup")
async def check(
    body: CheckRequest,
    ctx: CheckCtx,
    service: LedgerDep,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key", max_length=200)] = None,
):
    """The server-side signup rules, in Factory v2's order.

    Replaying an idempotency key with the same request returns the identical
    result (for 24 hours); with a different request it is a 422.
    """
    if idempotency_key and body.idempotency_key and idempotency_key != body.idempotency_key:
        raise HTTPException(status_code=422, detail="Idempotency-Key header and body idempotency_key differ")
    try:
        return await service.check(ctx.tenant, body, idempotency_key=idempotency_key or body.idempotency_key,
                                   backfill=ctx.allows("backfill", v1=False))
    except LedgerError as exc:
        _raise(exc)


@router.post("/accounts", response_model=CheckResponse, summary="Commit an evaluated check as an account")
async def commit_account(body: CommitRequest, ctx: CheckCtx, service: LedgerDep):
    """Idempotent: committing the same check for the same account again returns the same result."""
    try:
        return await service.commit(ctx.tenant, body.check_id, body.account_id)
    except LedgerError as exc:
        _raise(exc)


@router.get("/accounts/{account_id}", response_model=AccountResponse, summary="One account's ledger state")
async def get_account(
    account_id: Annotated[str, Path(pattern=ACCOUNT_ID_PATTERN)], ctx: DashboardCtx, service: LedgerDep,
):
    try:
        return await service.account(ctx.tenant, account_id)
    except LedgerError as exc:
        _raise(exc)


@router.post("/accounts/{account_id}/events", response_model=EventResponse, summary="Record a lifecycle event")
async def account_event(
    account_id: Annotated[str, Path(pattern=ACCOUNT_ID_PATTERN)],
    body: EventRequest,
    ctx: LifecycleCtx,
    service: LedgerDep,
):
    """deleted nulls the email key (signals stay until retention); banned with
    permanent_email_ban also bans the address; unbanned keeps an email ban."""
    try:
        return await service.event(ctx.tenant, account_id, body)
    except LedgerError as exc:
        _raise(exc)


@router.put("/bans", response_model=BanResponse, summary="Ban an address for this tenant")
async def put_ban(body: BanRequest, ctx: LifecycleCtx, service: LedgerDep):
    return await service.put_ban(ctx.tenant, body)


@router.delete("/bans", response_model=BanResponse, summary="Lift a ban")
async def delete_ban(body: UnbanRequest, ctx: LifecycleCtx, service: LedgerDep):
    return await service.delete_ban(ctx.tenant, body)


def _override_target(raw: str) -> tuple[str, str]:
    try:
        key = ip_reputation_key(raw)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"{exc}: use an address or an IPv4 /24") from exc
    return ("net24" if "/" in key else "ip"), key


@router.put("/ip-overrides/{target:path}", response_model=OverrideResponse, summary="Set a per-tenant IP override")
async def put_override(target: str, body: OverrideRequest, ctx: LifecycleCtx, service: LedgerDep):
    """``target`` is an address or an IPv4 /24 (``203.0.113.0/24``). The
    override is stored keyed (HMAC), so it is matched, never listed."""
    kind, key = _override_target(target)
    return await service.put_override(ctx.tenant, kind, key, body)


@router.delete("/ip-overrides/{target:path}", response_model=OverrideResponse, summary="Remove an IP override")
async def delete_override(target: str, ctx: LifecycleCtx, service: LedgerDep):
    kind, key = _override_target(target)
    return await service.delete_override(ctx.tenant, kind, key)


@router.post("/import/accounts", response_model=ImportResponse, summary="Backfill accounts (upsert)")
async def import_accounts(body: AccountsImportRequest, ctx: BackfillCtx, service: LedgerDep):
    return await service.import_accounts(ctx.tenant, body.rows)


@router.post("/import/bans", response_model=ImportResponse, summary="Backfill bans (upsert)")
async def import_bans(body: BansImportRequest, ctx: BackfillCtx, service: LedgerDep):
    return await service.import_bans(ctx.tenant, body.rows)


@router.post("/import/referrals", response_model=ImportResponse, summary="Backfill referrals (upsert)")
async def import_referrals(body: ReferralsImportRequest, ctx: BackfillCtx, service: LedgerDep):
    return await service.import_referrals(ctx.tenant, body.rows)


@router.post("/admin/ip-reputation/import", response_model=ImportResponse,
             summary="Merge rows into the shared IP reputation table")
async def import_ip_reputation(body: IPReputationImportRequest, ctx: AdminCtx, service: LedgerDep):
    """Shared by every tenant. Merge: higher counters win, the earliest first
    and latest last registration win, the worse status wins, a whitelist stays."""
    return await service.import_ip_reputation(body.rows)


@router.get("/stats", response_model=StatsResponse, summary="This tenant's v2 numbers")
async def stats(ctx: DashboardCtx, service: LedgerDep, days: Annotated[int, Query(ge=1, le=400)] = 30):
    return await service.stats(ctx.tenant, days)
