"""The v1 REST API (``/api/v1/*``).

Every route keeps its 0.2 path, request and response shape; changes are
additive only. Each route acts as the tenant of the request's API key:
bans, stats, timeline and pattern report are that tenant's own; IP
reputation is shared by all tenants.

Scopes: health needs any valid key; ``check`` for evaluation routes,
``lifecycle`` for bans and /ip/record, ``dashboard`` for stats, timeline and
the pattern report. The legacy key's ``legacy`` scope covers all of them.
"""

from __future__ import annotations

import ipaddress
import time

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, field_validator

from guardpost import __version__
from guardpost.api.deps import CheckScope, DashboardScope, EngineDep, LifecycleScope, TenantDep
from guardpost.email.validator import classify_domain_typo
from guardpost.models import HealthResponse

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class CheckRequest(BaseModel):
    email: str = Field(max_length=254, description="Email address to check")
    ip_address: str | None = Field(
        default=None, max_length=45, description="IP address of the registrant")
    record_ip: bool = Field(
        default=True, description="Whether to record this as a registration for IP tracking")
    smtp_verify: bool = Field(
        default=False, description="Run SMTP verification (requires port 25)")
    check_proxy: bool = Field(
        default=False, description="Check if IP is VPN/proxy/datacenter")
    ai_score: bool = Field(
        default=False, description="Run AI email scoring (requires OpenRouter key)")
    enrich: bool = Field(
        default=False, description="Run enrichment lookups (Gravatar, HIBP)")

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str | None) -> str | None:
        if v is not None:
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError("Invalid IP address format")
        return v


class CheckResponse(BaseModel):
    email: str
    ip_address: str | None
    is_suspicious: bool
    risk_score: int
    reasons: list[str]
    # `reasons` split by tier (guardpost/email/validator.py, ReasonTier):
    # weak only raised the score; soft degrade (is_suspicious); hard block.
    # is_suspicious == bool(hard_reasons or soft_reasons) or banned / bad IP.
    weak_reasons: list[str] = []
    soft_reasons: list[str] = []
    hard_reasons: list[str] = []
    ip_status: str
    ip_reason: str | None
    subnet_status: str = "clean"
    subnet_reason: str | None = None
    is_banned: bool
    normalized_email: str
    # Set when typo_domain fired. typo_source: "map" | "tld" | "numeric".
    suggested_domain: str | None = None
    typo_source: str | None = None
    smtp_status: str | None = None
    smtp_catch_all: bool = False
    ip_type: str | None = None
    is_datacenter: bool = False
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    ip_provider: str | None = None
    ai_risk_score: int | None = None
    ai_confidence: float | None = None
    ai_reasons: list[str] = []
    ai_analysis: str = ""
    is_b2c: bool = False
    gravatar_url: str | None = None
    breach_count: int = 0


class EmailValidateRequest(BaseModel):
    email: str = Field(max_length=254)


class EmailValidateResponse(BaseModel):
    email: str
    normalized_email: str
    is_valid: bool
    format_error: str | None
    is_disposable: bool
    is_role_account: bool
    is_b2c: bool
    is_suspicious: bool
    reasons: list[str]
    suggested_domain: str | None = None
    typo_source: str | None = None


class SMTPVerifyRequest(BaseModel):
    email: str = Field(max_length=254)


class SMTPVerifyResponse(BaseModel):
    email: str
    status: str
    smtp_code: int | None = None
    smtp_message: str | None = None
    is_catch_all: bool = False
    mx_host: str | None = None
    reasons: list[str]


class IPCheckRequest(BaseModel):
    ip_address: str = Field(max_length=45)

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("Invalid IP address format")
        return v


class IPCheckResponse(BaseModel):
    ip_address: str
    status: str
    reason: str | None


class IPRecordRequest(BaseModel):
    ip_address: str = Field(max_length=45)
    is_suspicious: bool = False

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("Invalid IP address format")
        return v


class ProxyCheckRequest(BaseModel):
    ip_address: str = Field(max_length=45)

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("Invalid IP address format")
        return v


class ProxyCheckResponse(BaseModel):
    ip_address: str
    ip_type: str
    is_datacenter: bool = False
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    provider: str | None = None
    reasons: list[str]


class BanRequest(BaseModel):
    email: str = Field(max_length=254)
    banned_by: str | None = Field(default=None, max_length=200)
    reason: str | None = Field(default=None, max_length=500)


class BanResponse(BaseModel):
    email: str
    normalized_email_hash: str
    banned: bool


class UnbanRequest(BaseModel):
    email: str = Field(max_length=254)


class AIScoreRequest(BaseModel):
    email: str = Field(max_length=254)


class AIScoreResponse(BaseModel):
    email: str
    risk_score: int
    confidence: float
    reasons: list[str]
    analysis: str
    model: str
    cached: bool


class AIBatchRequest(BaseModel):
    emails: list[str] = Field(max_length=100)


class AIBatchResponse(BaseModel):
    results: list[AIScoreResponse]


class StatsResponse(BaseModel):
    total_ips: int
    graylisted_ips: int
    blacklisted_ips: int
    whitelisted_ips: int
    total_banned_emails: int
    total_registrations: int
    total_suspicious_registrations: int


class TimelineBucket(BaseModel):
    t: float
    count: int


class TimelineResponse(BaseModel):
    buckets: list[TimelineBucket]
    bucket_seconds: int


class PatternReportResponse(BaseModel):
    total_registrations: int
    suspicious_count: int
    risk_level: str
    velocity_per_minute: float
    clusters: list[dict]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/api/v1/health", response_model=HealthResponse)
async def health(ctx: TenantDep):
    return HealthResponse(version=__version__)


@router.get(
    "/api/v1/stats",
    response_model=StatsResponse,
)
async def stats(ctx: DashboardScope, engine: EngineDep):
    """Aggregate statistics: IP counts, ban counts, registration totals."""
    data = await engine.get_stats(tenant=ctx.tenant)
    return StatsResponse(**data)

@router.get(
    "/api/v1/stats/timeline",
    response_model=TimelineResponse,
)
async def stats_timeline(ctx: DashboardScope, engine: EngineDep, hours: int = 24, bucket_minutes: int = 60):
    """Registration activity over time, grouped into buckets."""
    hours = min(hours, 168)  # cap at 7 days
    bucket_minutes = max(1, min(bucket_minutes, 1440))
    since = time.time() - hours * 3600
    buckets = await engine.get_registration_timeline(since, bucket_minutes * 60, tenant=ctx.tenant)
    return TimelineResponse(buckets=buckets, bucket_seconds=bucket_minutes * 60)

@router.post(
    "/api/v1/check",
    response_model=CheckResponse,
)
async def check_registration(ctx: CheckScope, engine: EngineDep, req: CheckRequest):
    """Full registration suspicion check (email + IP + optional SMTP/proxy)."""
    result = await engine.check(
        req.email,
        ip_address=req.ip_address,
        record_ip=req.record_ip,
        smtp_verify=req.smtp_verify,
        check_proxy=req.check_proxy,
        ai_score=req.ai_score,
        enrich=req.enrich,
        tenant=ctx.tenant,
    )

    # Record Prometheus metrics if enabled
    try:
        from guardpost.metrics import record_check

        record_check(result)
    except ImportError:
        pass

    data = result.to_dict()
    if not await engine.shows_full_ip_detail_v1(ctx.tenant):
        # Shared IP status reasons count other tenants' signups (see Guardpost.reason_detail).
        data["ip_reason"] = data["subnet_reason"] = None
    return CheckResponse(**data)

@router.post(
    "/api/v1/email/validate",
    response_model=EmailValidateResponse,
)
async def validate_email(ctx: CheckScope, engine: EngineDep, req: EmailValidateRequest):
    """Email-only validation (no IP, no storage)."""
    is_valid, format_error = engine.validate_format(req.email)
    is_disposable = engine.is_disposable(req.email)
    is_role = engine.is_role_account(req.email)
    is_b2c = engine.is_b2c(req.email)
    is_suspicious, reasons = await engine.is_suspicious(req.email, tenant=ctx.tenant)
    normalized = engine.normalize_email(req.email)
    typo = classify_domain_typo(req.email) if "typo_domain" in reasons else None

    return EmailValidateResponse(
        email=req.email,
        normalized_email=normalized,
        is_valid=is_valid,
        format_error=format_error,
        is_disposable=is_disposable,
        is_role_account=is_role,
        is_b2c=is_b2c,
        is_suspicious=is_suspicious,
        reasons=reasons,
        suggested_domain=typo[0] if typo else None,
        typo_source=typo[1] if typo else None,
    )

@router.post(
    "/api/v1/email/smtp",
    response_model=SMTPVerifyResponse,
)
async def smtp_verify(ctx: CheckScope, engine: EngineDep, req: SMTPVerifyRequest):
    """SMTP mailbox verification (requires port 25 access)."""
    if not engine.smtp_verifier:
        raise HTTPException(
            status_code=501,
            detail="SMTP verification not enabled. Set GUARDPOST_ENABLE_SMTP=1",
        )
    result = await engine.smtp_verifier.verify(req.email)
    return SMTPVerifyResponse(**result.to_dict())

@router.post(
    "/api/v1/ip/check",
    response_model=IPCheckResponse,
)
async def check_ip(ctx: CheckScope, engine: EngineDep, req: IPCheckRequest):
    """Check IP reputation."""
    status, reason = await engine.check_ip(req.ip_address)
    if not await engine.shows_full_ip_detail_v1(ctx.tenant):
        reason = None
    return IPCheckResponse(ip_address=req.ip_address, status=status, reason=reason)

@router.post(
    "/api/v1/ip/record",
    response_model=IPCheckResponse,
)
async def record_ip(ctx: LifecycleScope, engine: EngineDep, req: IPRecordRequest):
    """Record a registration from an IP."""
    record = await engine.record_ip_registration(req.ip_address, req.is_suspicious, tenant=ctx.tenant)
    full = await engine.shows_full_ip_detail_v1(ctx.tenant)
    return IPCheckResponse(
        ip_address=req.ip_address,
        status=record.status,
        reason=record.status_reason if full else None,
    )

@router.post(
    "/api/v1/ip/proxy",
    response_model=ProxyCheckResponse,
)
async def check_proxy(ctx: CheckScope, engine: EngineDep, req: ProxyCheckRequest):
    """Check if an IP is a VPN, proxy, datacenter, or Tor exit node."""
    if not engine.proxy_detector:
        raise HTTPException(
            status_code=501,
            detail="Proxy detection not enabled. Set GUARDPOST_ENABLE_PROXY_DETECTION=1",
        )
    result = await engine.proxy_detector.check(req.ip_address)
    return ProxyCheckResponse(**result.to_dict())

@router.post(
    "/api/v1/email/ban",
    response_model=BanResponse,
)
async def ban_email(ctx: LifecycleScope, engine: EngineDep, req: BanRequest):
    """Add email to permanent ban list."""
    record = await engine.ban_email(req.email, req.banned_by, req.reason, tenant=ctx.tenant)
    return BanResponse(
        email=req.email,
        normalized_email_hash=record.normalized_email_hash,
        banned=True,
    )

@router.delete(
    "/api/v1/email/ban",
    response_model=BanResponse,
)
async def unban_email(ctx: LifecycleScope, engine: EngineDep, req: UnbanRequest):
    """Remove email from ban list."""
    was_banned = await engine.unban_email(req.email, tenant=ctx.tenant)
    return BanResponse(
        email=req.email,
        normalized_email_hash="",
        banned=not was_banned,
    )

@router.post(
    "/api/v1/ai/score",
    response_model=AIScoreResponse,
)
async def ai_score_email(ctx: CheckScope, engine: EngineDep, req: AIScoreRequest):
    """AI-powered email risk scoring (hosted feature)."""
    if not engine.ai_scorer:
        raise HTTPException(
            status_code=501,
            detail="AI scoring not enabled. Set GUARDPOST_ENABLE_AI=1 and OPENROUTER_API_KEY",
        )
    result = await engine.ai_scorer.score(req.email)
    return AIScoreResponse(**result.to_dict())

@router.post(
    "/api/v1/ai/score/batch",
    response_model=AIBatchResponse,
)
async def ai_score_batch(ctx: CheckScope, engine: EngineDep, req: AIBatchRequest):
    """Batch AI email scoring (hosted feature)."""
    if not engine.ai_scorer:
        raise HTTPException(
            status_code=501,
            detail="AI scoring not enabled. Set GUARDPOST_ENABLE_AI=1 and OPENROUTER_API_KEY",
        )
    results = await engine.ai_scorer.score_batch(req.emails)
    return AIBatchResponse(
        results=[AIScoreResponse(**r.to_dict()) for r in results],
    )

@router.get(
    "/api/v1/patterns/report",
    response_model=PatternReportResponse,
)
async def pattern_report(ctx: DashboardScope, engine: EngineDep):
    """Get registration pattern analysis report."""
    report = engine.pattern_report(tenant=ctx.tenant)
    if report is None:
        raise HTTPException(
            status_code=501,
            detail="Pattern detection not enabled. Set GUARDPOST_ENABLE_PATTERNS=1",
        )
    return PatternReportResponse(**report.to_dict())
