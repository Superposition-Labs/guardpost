"""FastAPI REST API server for Guardpost.

Start with:
    guardpost serve
    # or
    uvicorn guardpost.api.server:create_app --factory
"""

from __future__ import annotations

import base64
import hmac
import ipaddress
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field, field_validator

from guardpost.engine import Guardpost
from guardpost.storage.sqlite import SQLiteStorage

logger = logging.getLogger(__name__)

# Global engine instance (set during lifespan)
_engine: Guardpost | None = None

# API key (optional — set GUARDPOST_API_KEY env var to enable)
_api_key: str | None = None

# Rate limiter (optional — set GUARDPOST_RATE_LIMIT env var to enable)
_rate_limit: int = 0  # 0 = disabled

# Redis storage reference (set when --redis-url is provided)
_redis_storage: object | None = None


class _TokenBucket:
    """Simple per-IP token-bucket rate limiter (in-memory)."""

    def __init__(self, rate: int, period: float = 60.0) -> None:
        self.rate = rate  # tokens per period
        self.period = period
        # ip -> (tokens, last_refill)
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        tokens, last = self._buckets.get(key, (float(self.rate), now))
        elapsed = now - last
        tokens = min(self.rate, tokens + elapsed * (self.rate / self.period))
        if tokens >= 1.0:
            self._buckets[key] = (tokens - 1.0, now)
            return True
        self._buckets[key] = (tokens, now)
        return False


_limiter = _TokenBucket(rate=60)


def _get_engine() -> Guardpost:
    if _engine is None:
        raise HTTPException(
            status_code=503, detail="Guardpost not initialized")
    return _engine


def _extract_basic_auth_password(request: Request) -> str | None:
    """Extract password from HTTP Basic Auth header, if present."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
        _, _, password = decoded.partition(":")
        return password
    except Exception:
        return None


def _check_api_key(
    request: Request,
    x_api_key: Annotated[str | None, Header()] = None,
) -> None:
    """Verify API access via X-Api-Key header or HTTP Basic Auth password."""
    if not _api_key:
        return  # No key configured — API is open

    # Try X-Api-Key header first (programmatic clients)
    if x_api_key and hmac.compare_digest(x_api_key, _api_key):
        return

    # Fall back to Basic Auth password (browser dashboard)
    basic_password = _extract_basic_auth_password(request)
    if basic_password and hmac.compare_digest(basic_password, _api_key):
        return

    raise HTTPException(
        status_code=401, detail="Invalid or missing API key")


def _check_dashboard_auth(request: Request) -> None:
    """Verify dashboard access via HTTP Basic Auth (password = API key).

    When GUARDPOST_API_KEY is set, browsers will show a native login prompt.
    Username is ignored; password must match the API key.
    """
    if not _api_key:
        return  # No key configured — dashboard is open

    basic_password = _extract_basic_auth_password(request)
    if basic_password and hmac.compare_digest(basic_password, _api_key):
        return

    raise HTTPException(
        status_code=401,
        detail="Authentication required",
        headers={"WWW-Authenticate": 'Basic realm="Guardpost Dashboard"'},
    )


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
    ip_status: str
    ip_reason: str | None
    is_banned: bool
    normalized_email: str
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


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str


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
# App factory
# ---------------------------------------------------------------------------


def create_app(
    db_path: str | None = None,
    api_key: str | None = None,
    *,
    redis_url: str | None = None,
    enable_smtp: bool = False,
    smtp_timeout: float = 10.0,
    enable_proxy_detection: bool = False,
    ipinfo_token: str | None = None,
    enable_ai: bool = False,
    openrouter_api_key: str | None = None,
    ai_model: str | None = None,
    enable_patterns: bool = False,
    enable_enrichment: bool = False,
    hibp_api_key: str | None = None,
    rate_limit: int = 0,
    maxmind_db_path: str | None = None,
    enable_metrics: bool = False,
) -> FastAPI:
    """Create the FastAPI application."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        global _engine, _api_key, _redis_storage  # noqa: PLW0603

        # --- Storage backend selection ---
        resolved_redis = redis_url or os.environ.get("GUARDPOST_REDIS_URL")
        if resolved_redis:
            from guardpost.storage.redis import RedisStorage

            storage = RedisStorage(resolved_redis)
            _redis_storage = storage
            logger.info("Using Redis 8 storage backend (%s)", resolved_redis)
        else:
            resolved_db = db_path or os.environ.get("GUARDPOST_DB_PATH")
            storage = SQLiteStorage(
                resolved_db) if resolved_db else SQLiteStorage()
            _redis_storage = None

        # SMTP verifier (opt-in)
        smtp_verifier = None
        if enable_smtp or os.environ.get("GUARDPOST_ENABLE_SMTP"):
            from guardpost.email.smtp import SMTPVerifier

            smtp_verifier = SMTPVerifier(timeout=smtp_timeout)

        # Proxy detector (opt-in)
        proxy_detector = None
        resolved_ipinfo = ipinfo_token or os.environ.get("IPINFO_TOKEN")
        resolved_maxmind = maxmind_db_path or os.environ.get(
            "GUARDPOST_MAXMIND_DB")
        if enable_proxy_detection or os.environ.get("GUARDPOST_ENABLE_PROXY_DETECTION"):
            from guardpost.ip.proxy import ProxyDetector

            proxy_detector = ProxyDetector(
                ipinfo_token=resolved_ipinfo,
                maxmind_db_path=resolved_maxmind,
            )

        # AI scorer (opt-in — hosted service feature)
        ai_scorer = None
        resolved_ai_key = openrouter_api_key or os.environ.get(
            "OPENROUTER_API_KEY")
        if (enable_ai or os.environ.get("GUARDPOST_ENABLE_AI")) and resolved_ai_key:
            from guardpost.ai.scorer import AIScorer

            resolved_model = ai_model or os.environ.get(
                "GUARDPOST_AI_MODEL", "openai/gpt-4o-mini")
            ai_scorer = AIScorer(
                api_key=resolved_ai_key,
                model=resolved_model,
                cache_backend=_redis_storage,
            )
            logger.info("AI email scoring enabled (model: %s)", resolved_model)

        # Pattern detector (opt-in)
        pattern_detector = None
        if enable_patterns or os.environ.get("GUARDPOST_ENABLE_PATTERNS"):
            from guardpost.fraud.patterns import PatternDetector

            pattern_detector = PatternDetector()
            logger.info("Pattern detection enabled")

        # Email enrichment (opt-in — Gravatar + HIBP)
        enrichment = None
        resolved_hibp_key = hibp_api_key or os.environ.get("HIBP_API_KEY")
        if enable_enrichment or os.environ.get("GUARDPOST_ENABLE_ENRICHMENT"):
            from guardpost.email.enrichment import EmailEnrichment

            enrichment = EmailEnrichment(hibp_api_key=resolved_hibp_key)
            logger.info("Email enrichment enabled (Gravatar + HIBP)")

        _engine = Guardpost(
            storage=storage,
            smtp_verifier=smtp_verifier,
            proxy_detector=proxy_detector,
            ai_scorer=ai_scorer,
            pattern_detector=pattern_detector,
            enrichment=enrichment,
        )
        await _engine.initialize()

        _api_key = api_key or os.environ.get("GUARDPOST_API_KEY")
        if _api_key:
            logger.info("API key authentication enabled")
        else:
            logger.warning("No API key set — API is unauthenticated")

        global _rate_limit, _limiter  # noqa: PLW0603
        _rate_limit = rate_limit or int(
            os.environ.get("GUARDPOST_RATE_LIMIT", "0"))
        if _rate_limit:
            if _redis_storage:
                logger.info(
                    "Distributed rate limiting enabled via Redis: "
                    "%d requests/min per IP", _rate_limit)
            else:
                _limiter = _TokenBucket(rate=_rate_limit)
                logger.info(
                    "Rate limiting enabled: %d requests/min per IP", _rate_limit)

        yield

        await _engine.close()
        _engine = None

    app = FastAPI(
        title="Guardpost",
        description="Self-hosted registration abuse detection API",
        version="0.1.0",
        lifespan=lifespan,
    )

    # CORS — restrictive by default; users can override via env vars
    cors_origins = [o.strip() for o in os.environ.get(
        "GUARDPOST_CORS_ORIGINS", "").split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["X-Api-Key", "Content-Type"],
    )

    # Prometheus metrics (opt-in)
    if enable_metrics or os.environ.get("GUARDPOST_ENABLE_METRICS"):
        from guardpost.metrics import instrument_app

        instrument_app(app)
        logger.info("Prometheus metrics enabled at /metrics")

    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        if _rate_limit:
            # Support X-Forwarded-For for clients behind a reverse proxy
            forwarded = request.headers.get("x-forwarded-for")
            if forwarded:
                client_ip = forwarded.split(",")[0].strip()
            else:
                client_ip = request.client.host if request.client else "unknown"
            if _redis_storage:
                allowed = await _redis_storage.rate_limit_check(
                    client_ip, _rate_limit,
                )
            else:
                allowed = _limiter.allow(client_ip)
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded"},
                )
        return await call_next(request)

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    # Root redirect to dashboard
    @app.get("/", include_in_schema=False,
             dependencies=[Depends(_check_dashboard_auth)])
    async def root():
        return RedirectResponse(url="/dashboard")

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        return JSONResponse(content={}, status_code=204)

    # Built-in dashboard (HTTP Basic Auth when API key is configured)
    _dashboard_html: str | None = None

    @app.get("/dashboard", response_class=HTMLResponse,
             dependencies=[Depends(_check_dashboard_auth)],
             include_in_schema=False)
    async def dashboard():
        nonlocal _dashboard_html
        if _dashboard_html is None:
            from pathlib import Path

            html_path = Path(__file__).resolve().parent / "dashboard.html"
            _dashboard_html = html_path.read_text()
        return HTMLResponse(_dashboard_html)

    @app.get("/api/v1/health", response_model=HealthResponse,
             dependencies=[Depends(_check_api_key)])
    async def health():
        from guardpost import __version__

        return HealthResponse(version=__version__)

    # -- Kubernetes / Docker health probes (unauthenticated) ---------------

    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        """Liveness probe — returns 200 if the process is alive."""
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    async def readyz():
        """Readiness probe — returns 200 only if the storage backend is reachable."""
        try:
            engine = _get_engine()
            # Lightweight storage connectivity check
            await engine.storage.get_ip_reputation("__readyz__")
            return {"status": "ok"}
        except Exception as exc:
            return JSONResponse(
                status_code=503,
                content={"status": "unavailable", "detail": str(exc)},
            )

    @app.get(
        "/api/v1/stats",
        response_model=StatsResponse,
        dependencies=[Depends(_check_api_key)],
    )
    async def stats():
        """Aggregate statistics: IP counts, ban counts, registration totals."""
        engine = _get_engine()
        data = await engine.get_stats()
        return StatsResponse(**data)

    @app.get(
        "/api/v1/stats/timeline",
        response_model=TimelineResponse,
        dependencies=[Depends(_check_api_key)],
    )
    async def stats_timeline(hours: int = 24, bucket_minutes: int = 60):
        """Registration activity over time, grouped into buckets."""
        hours = min(hours, 168)  # cap at 7 days
        bucket_minutes = max(1, min(bucket_minutes, 1440))
        engine = _get_engine()
        since = time.time() - hours * 3600
        buckets = await engine.get_registration_timeline(since, bucket_minutes * 60)
        return TimelineResponse(buckets=buckets, bucket_seconds=bucket_minutes * 60)

    @app.post(
        "/api/v1/check",
        response_model=CheckResponse,
        dependencies=[Depends(_check_api_key)],
    )
    async def check_registration(req: CheckRequest):
        """Full registration suspicion check (email + IP + optional SMTP/proxy)."""
        engine = _get_engine()
        result = await engine.check(
            req.email,
            ip_address=req.ip_address,
            record_ip=req.record_ip,
            smtp_verify=req.smtp_verify,
            check_proxy=req.check_proxy,
            ai_score=req.ai_score,
            enrich=req.enrich,
        )

        # Record Prometheus metrics if enabled
        try:
            from guardpost.metrics import record_check

            record_check(result)
        except ImportError:
            pass

        return CheckResponse(**result.to_dict())

    @app.post(
        "/api/v1/email/validate",
        response_model=EmailValidateResponse,
        dependencies=[Depends(_check_api_key)],
    )
    async def validate_email(req: EmailValidateRequest):
        """Email-only validation (no IP, no storage)."""
        engine = _get_engine()
        is_valid, format_error = engine.validate_format(req.email)
        is_disposable = engine.is_disposable(req.email)
        is_role = engine.is_role_account(req.email)
        is_b2c = engine.is_b2c(req.email)
        is_suspicious, reasons = await engine.is_suspicious(req.email)
        normalized = engine.normalize_email(req.email)

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
        )

    @app.post(
        "/api/v1/email/smtp",
        response_model=SMTPVerifyResponse,
        dependencies=[Depends(_check_api_key)],
    )
    async def smtp_verify(req: SMTPVerifyRequest):
        """SMTP mailbox verification (requires port 25 access)."""
        engine = _get_engine()
        if not engine.smtp_verifier:
            raise HTTPException(
                status_code=501,
                detail="SMTP verification not enabled. Set GUARDPOST_ENABLE_SMTP=1",
            )
        result = await engine.smtp_verifier.verify(req.email)
        return SMTPVerifyResponse(**result.to_dict())

    @app.post(
        "/api/v1/ip/check",
        response_model=IPCheckResponse,
        dependencies=[Depends(_check_api_key)],
    )
    async def check_ip(req: IPCheckRequest):
        """Check IP reputation."""
        engine = _get_engine()
        status, reason = await engine.check_ip(req.ip_address)
        return IPCheckResponse(ip_address=req.ip_address, status=status, reason=reason)

    @app.post(
        "/api/v1/ip/record",
        response_model=IPCheckResponse,
        dependencies=[Depends(_check_api_key)],
    )
    async def record_ip(req: IPRecordRequest):
        """Record a registration from an IP."""
        engine = _get_engine()
        record = await engine.ip_engine.record_registration(req.ip_address, req.is_suspicious)
        return IPCheckResponse(
            ip_address=req.ip_address,
            status=record.status,
            reason=record.status_reason,
        )

    @app.post(
        "/api/v1/ip/proxy",
        response_model=ProxyCheckResponse,
        dependencies=[Depends(_check_api_key)],
    )
    async def check_proxy(req: ProxyCheckRequest):
        """Check if an IP is a VPN, proxy, datacenter, or Tor exit node."""
        engine = _get_engine()
        if not engine.proxy_detector:
            raise HTTPException(
                status_code=501,
                detail="Proxy detection not enabled. Set GUARDPOST_ENABLE_PROXY_DETECTION=1",
            )
        result = await engine.proxy_detector.check(req.ip_address)
        return ProxyCheckResponse(**result.to_dict())

    @app.post(
        "/api/v1/email/ban",
        response_model=BanResponse,
        dependencies=[Depends(_check_api_key)],
    )
    async def ban_email(req: BanRequest):
        """Add email to permanent ban list."""
        engine = _get_engine()
        record = await engine.ban_email(req.email, req.banned_by, req.reason)
        return BanResponse(
            email=req.email,
            normalized_email_hash=record.normalized_email_hash,
            banned=True,
        )

    @app.delete(
        "/api/v1/email/ban",
        response_model=BanResponse,
        dependencies=[Depends(_check_api_key)],
    )
    async def unban_email(req: UnbanRequest):
        """Remove email from ban list."""
        engine = _get_engine()
        was_banned = await engine.unban_email(req.email)
        return BanResponse(
            email=req.email,
            normalized_email_hash="",
            banned=not was_banned,
        )

    @app.post(
        "/api/v1/ai/score",
        response_model=AIScoreResponse,
        dependencies=[Depends(_check_api_key)],
    )
    async def ai_score_email(req: AIScoreRequest):
        """AI-powered email risk scoring (hosted feature)."""
        engine = _get_engine()
        if not engine.ai_scorer:
            raise HTTPException(
                status_code=501,
                detail="AI scoring not enabled. Set GUARDPOST_ENABLE_AI=1 and OPENROUTER_API_KEY",
            )
        result = await engine.ai_scorer.score(req.email)
        return AIScoreResponse(**result.to_dict())

    @app.post(
        "/api/v1/ai/score/batch",
        response_model=AIBatchResponse,
        dependencies=[Depends(_check_api_key)],
    )
    async def ai_score_batch(req: AIBatchRequest):
        """Batch AI email scoring (hosted feature)."""
        engine = _get_engine()
        if not engine.ai_scorer:
            raise HTTPException(
                status_code=501,
                detail="AI scoring not enabled. Set GUARDPOST_ENABLE_AI=1 and OPENROUTER_API_KEY",
            )
        results = await engine.ai_scorer.score_batch(req.emails)
        return AIBatchResponse(
            results=[AIScoreResponse(**r.to_dict()) for r in results],
        )

    @app.get(
        "/api/v1/patterns/report",
        response_model=PatternReportResponse,
        dependencies=[Depends(_check_api_key)],
    )
    async def pattern_report():
        """Get registration pattern analysis report."""
        engine = _get_engine()
        if not engine.pattern_detector:
            raise HTTPException(
                status_code=501,
                detail="Pattern detection not enabled. Set GUARDPOST_ENABLE_PATTERNS=1",
            )
        report = engine.pattern_detector.analyze()
        return PatternReportResponse(**report.to_dict())

    return app
