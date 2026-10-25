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

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query, Request

from guardpost.api.deps import get_engine, require_scope
from guardpost.ledger.service import LedgerError, LedgerService
from guardpost.models import (
    ACCOUNT_ID_PATTERN,
    SHA256_PATTERN,
    AccountImport,
    AccountRef,
    AccountResponse,
    AccountSignalsOut,
    AccountsImportRequest,
    BanImport,
    BansImportRequest,
    BanV2Request,
    BanV2Response,
    CheckV2Request,
    CheckV2Response,
    CommitRequest,
    Device,
    EventRequest,
    EventResponse,
    ImportResponse,
    IPReputationImport,
    IPReputationImportRequest,
    LatencyOut,
    Name,
    OverrideRequest,
    OverrideResponse,
    ReasonOut,
    ReferralImport,
    ReferralIn,
    ReferralOut,
    ReferralsImportRequest,
    ReferralStatsOut,
    ReferredByOut,
    SignalsOut,
    Signup,
    StatsV2Response,
    UnbanV2Request,
    ip_reputation_key,
)
from guardpost.tenancy.models import TenantContext

# The models live in guardpost.models (shared with guardpost.client). The
# names v1 also uses carry a V2 there; the 0.3 names stay importable here.
CheckRequest = CheckV2Request
CheckResponse = CheckV2Response
BanRequest = BanV2Request
UnbanRequest = UnbanV2Request
BanResponse = BanV2Response
StatsResponse = StatsV2Response

__all__ = [
    "ACCOUNT_ID_PATTERN", "SHA256_PATTERN", "AccountImport", "AccountRef", "AccountResponse", "AccountSignalsOut",
    "AccountsImportRequest", "BanImport", "BanRequest", "BanResponse", "BansImportRequest", "CheckRequest",
    "CheckResponse", "CommitRequest", "Device", "EventRequest", "EventResponse", "IPReputationImport",
    "IPReputationImportRequest", "ImportResponse", "LatencyOut", "Name", "OverrideRequest", "OverrideResponse",
    "ReasonOut", "ReferralImport", "ReferralIn", "ReferralOut", "ReferralStatsOut", "ReferralsImportRequest",
    "ReferredByOut", "SignalsOut", "Signup", "StatsResponse", "UnbanRequest", "ip_reputation_key", "router",
]


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
# Routes
# ---------------------------------------------------------------------------


@router.post("/check", response_model=CheckV2Response, summary="Evaluate (and optionally commit) a signup")
async def check(
    body: CheckV2Request,
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


@router.post("/accounts", response_model=CheckV2Response, summary="Commit an evaluated check as an account")
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


@router.put("/bans", response_model=BanV2Response, summary="Ban an address for this tenant")
async def put_ban(body: BanV2Request, ctx: LifecycleCtx, service: LedgerDep):
    return await service.put_ban(ctx.tenant, body)


@router.delete("/bans", response_model=BanV2Response, summary="Lift a ban")
async def delete_ban(body: UnbanV2Request, ctx: LifecycleCtx, service: LedgerDep):
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


@router.get("/stats", response_model=StatsV2Response, summary="This tenant's v2 numbers")
async def stats(ctx: DashboardCtx, service: LedgerDep, days: Annotated[int, Query(ge=1, le=400)] = 30):
    return await service.stats(ctx.tenant, days)
