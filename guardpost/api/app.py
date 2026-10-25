"""FastAPI application factory.

All runtime state lives on ``app.state`` (no module globals), so several apps
can coexist in one process — tests build one per case.

Start with:
    guardpost serve
    # or
    uvicorn guardpost.api.server:create_app --factory
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from guardpost import __version__
from guardpost.api import v1, v2
from guardpost.api.auth import EnvAuthenticator, StoreAuthenticator, extract_credentials
from guardpost.api.deps import get_engine, require_dashboard
from guardpost.api.proxies import parse_trusted_proxies, request_client_ip, trusted_proxies_from_env
from guardpost.engine import Guardpost
from guardpost.storage.sqlite import DEFAULT_LEGACY_TENANT, SQLiteStorage
from guardpost.tenancy.keys import SCOPES, sync_legacy_key
from guardpost.tenancy.models import Tenant, TenantContext, validate_tenant_id

logger = logging.getLogger(__name__)

_DASHBOARD_PATH = Path(__file__).resolve().parent / "dashboard.html"

_TRUTHY = {"1", "true", "yes", "on"}


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUTHY


def open_mode_refusal(legacy_tenant: str) -> str:
    return (
        "Guardpost refuses to serve: no API keys are configured, so every route would be "
        "unauthenticated. Do one of:\n"
        f"  - set GUARDPOST_API_KEY (the single legacy key, acting as tenant {legacy_tenant!r});\n"
        "  - create a tenant key: guardpost tenant create <id> && "
        "guardpost key create --tenant <id> --label <name> --scopes check,lifecycle,dashboard;\n"
        "  - or set GUARDPOST_ALLOW_OPEN=1 to run without authentication (local development only)."
    )


def multi_tenant_refusal(backend: str) -> str:
    return (
        f"Guardpost refuses to start: GUARDPOST_MULTI_TENANT=1 needs the SQLite storage backend, "
        f"and {backend!r} keeps a single global ban list. Set GUARDPOST_STORAGE=sqlite "
        "(GUARDPOST_REDIS_URL then serves rate limiting only), or unset GUARDPOST_MULTI_TENANT."
    )


class TokenBucket:
    """In-memory token-bucket rate limiter, one bucket per key."""

    def __init__(self, rate: int, period: float = 60.0) -> None:
        self.rate = rate  # tokens per period
        self.period = period
        # key -> (tokens, last_refill)
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, key: str, rate: int | None = None) -> bool:
        rate = self.rate if rate is None else rate
        now = time.monotonic()
        tokens, last = self._buckets.get(key, (float(rate), now))
        elapsed = now - last
        tokens = min(rate, tokens + elapsed * (rate / self.period))
        if tokens >= 1.0:
            self._buckets[key] = (tokens - 1.0, now)
            return True
        self._buckets[key] = (tokens, now)
        return False


# Backward-compatible alias (0.2 name).
_TokenBucket = TokenBucket


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
    trusted_extra_domains: list[str] | str | None = None,
    trusted_proxies: list[str] | str | None = None,
    metrics_port: int | None = None,
    metrics_host: str | None = None,
    allow_open: bool | None = None,
    legacy_tenant: str | None = None,
    secret: str | None = None,
    storage_backend: str | None = None,
    multi_tenant: bool | None = None,
    storage=None,
    dns_resolver=None,
    allow_db_secret: bool | None = None,
    purge_interval: float | None = None,
) -> FastAPI:
    """Create the FastAPI application.

    Args:
        api_key: the legacy single key (else GUARDPOST_API_KEY). With SQLite
            it is hashed into ``api_keys`` as key id ``legacy`` for
            ``legacy_tenant`` (else GUARDPOST_LEGACY_TENANT, else "default").
        allow_open: serve without authentication when no key exists at all
            (else GUARDPOST_ALLOW_OPEN). Without it, that case refuses to boot.
        secret: instance secret for per-tenant keyed hashes (else GUARDPOST_SECRET).
        storage_backend: "sqlite" or "redis" (else GUARDPOST_STORAGE; default
            "redis" when a Redis URL is given, for 0.2 compatibility). With
            "sqlite" a Redis URL is used for rate limiting only.
        multi_tenant: refuse to boot on a backend without tenancy (else
            GUARDPOST_MULTI_TENANT). SQLite is always multi-tenant.
        storage: a storage object to use instead (tests).
        dns_resolver: a guardpost.email.validator.DnsResolver for the v2
            check (tests, parity runs); None uses dnspython.
        allow_db_secret: let the v2 ledger run on the generated
            database-stored secret (else GUARDPOST_ALLOW_DB_SECRET; tests only).
        purge_interval: seconds between in-process retention purges of the v2
            ledger (else GUARDPOST_PURGE_INTERVAL, default 3600; 0 disables).
        trusted_proxies: CIDRs/addresses of reverse proxies allowed to set
            X-Forwarded-For. ``None`` reads GUARDPOST_TRUSTED_PROXIES. Without
            any, the header is ignored and the TCP peer is the client.
        enable_metrics: serve Prometheus metrics (also GUARDPOST_ENABLE_METRICS)
            on ``metrics_port`` (GUARDPOST_METRICS_PORT, default 9100) and
            ``metrics_host`` (GUARDPOST_METRICS_HOST, default 127.0.0.1) —
            a separate listener, never a route on this app.
    """
    # Parsed up front so a bad CIDR fails at startup, not on the first request.
    resolved_proxies = (
        trusted_proxies_from_env() if trusted_proxies is None
        else parse_trusted_proxies(trusted_proxies)
    )
    metrics_enabled = bool(enable_metrics or os.environ.get("GUARDPOST_ENABLE_METRICS"))
    resolved_metrics_port = metrics_port if metrics_port is not None else int(
        os.environ.get("GUARDPOST_METRICS_PORT", "9100"))
    resolved_metrics_host = metrics_host or os.environ.get("GUARDPOST_METRICS_HOST", "127.0.0.1")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        state = app.state

        resolved_legacy = validate_tenant_id(
            legacy_tenant or os.environ.get("GUARDPOST_LEGACY_TENANT") or DEFAULT_LEGACY_TENANT)
        state.allow_open = _env_flag("GUARDPOST_ALLOW_OPEN") if allow_open is None else allow_open
        require_tenancy = _env_flag("GUARDPOST_MULTI_TENANT") if multi_tenant is None else multi_tenant

        # --- Storage backend selection ---
        resolved_redis = redis_url or os.environ.get("GUARDPOST_REDIS_URL")
        backend = (storage_backend or os.environ.get("GUARDPOST_STORAGE")
                   or ("redis" if resolved_redis else "sqlite")).strip().lower()
        state.redis = None
        if storage is not None:
            resolved_storage = storage
            backend = type(storage).__name__
        elif backend == "redis":
            if not resolved_redis:
                raise RuntimeError("GUARDPOST_STORAGE=redis needs GUARDPOST_REDIS_URL")
            from guardpost.storage.redis import RedisStorage

            resolved_storage = state.redis = RedisStorage(resolved_redis)
            logger.info("Using Redis 8 storage backend (%s)", resolved_redis)
        elif backend == "sqlite":
            resolved_db = db_path or os.environ.get("GUARDPOST_DB_PATH")
            resolved_storage = SQLiteStorage(resolved_db, legacy_tenant=resolved_legacy)
            if resolved_redis:
                from guardpost.storage.redis import RedisStorage

                state.redis = RedisStorage(resolved_redis)
                await state.redis.initialize()
                logger.info("Redis (%s) used for rate limiting only", resolved_redis)
        else:
            raise RuntimeError(f"unknown GUARDPOST_STORAGE {backend!r}: use sqlite or redis")

        tenancy = bool(getattr(resolved_storage, "supports_tenancy", False))
        if require_tenancy and not tenancy:
            raise RuntimeError(multi_tenant_refusal(backend))
        if not tenancy:
            logger.warning("Storage %r has no tenancy: single-tenant mode (one key, one ban list)", backend)

        engine = Guardpost(
            storage=resolved_storage,
            smtp_verifier=_smtp_verifier(enable_smtp, smtp_timeout),
            proxy_detector=_proxy_detector(enable_proxy_detection, ipinfo_token, maxmind_db_path),
            ai_scorer=_ai_scorer(enable_ai, openrouter_api_key, ai_model, state.redis),
            pattern_detector=_pattern_detector(enable_patterns),
            enrichment=_enrichment(enable_enrichment, hibp_api_key),
            # None -> GUARDPOST_TRUSTED_EXTRA_DOMAINS
            trusted_extra_domains=trusted_extra_domains,
            secret=secret,
            dns_resolver=dns_resolver,
            allow_db_secret=allow_db_secret,
        )
        if engine.trusted_extra_domains:
            logger.info("Extra trusted domains: %s", ", ".join(sorted(engine.trusted_extra_domains)))
        await engine.initialize()

        # --- Authentication ---
        env_key = api_key or os.environ.get("GUARDPOST_API_KEY")
        if tenancy:
            legacy = await resolved_storage.ensure_tenant(resolved_legacy)
            await sync_legacy_key(resolved_storage, env_key, resolved_legacy)
            state.authenticator = StoreAuthenticator(resolved_storage)
        else:
            legacy = Tenant(id=resolved_legacy, name=resolved_legacy)
            state.authenticator = EnvAuthenticator(env_key, legacy)
        state.open_context = TenantContext(tenant=legacy, scopes=SCOPES, key_id=None)
        if not await state.authenticator.has_usable_keys():
            if not state.allow_open:
                await engine.close()
                raise RuntimeError(open_mode_refusal(resolved_legacy))
            logger.warning("No API keys and GUARDPOST_ALLOW_OPEN=1: the API is UNAUTHENTICATED "
                           "(every request acts as tenant %r)", resolved_legacy)
        state.engine = engine

        # Instance default: per tenant for authenticated traffic (a tenant's
        # rate_limit_per_minute overrides it), per IP for everything else.
        state.rate_limit = rate_limit or int(os.environ.get("GUARDPOST_RATE_LIMIT", "0"))
        if state.rate_limit:
            where = "via Redis" if state.redis else "in memory"
            logger.info("Rate limiting enabled (%s): %d requests/min per tenant, and per IP for "
                        "unauthenticated traffic", where, state.rate_limit)

        metrics_server = None
        if metrics_enabled:
            from guardpost.metrics import start_metrics_server

            metrics_server, _ = start_metrics_server(resolved_metrics_port, resolved_metrics_host)
            state.metrics_port = metrics_server.server_port
            logger.info("Prometheus metrics on http://%s:%d/metrics (separate listener)",
                        resolved_metrics_host, metrics_server.server_port)

        purge_task = None
        refusal = engine.ledger_refusal()
        if refusal is None:
            state.ledger = v2.LedgerService(engine)
            interval = purge_interval if purge_interval is not None else float(
                os.environ.get("GUARDPOST_PURGE_INTERVAL", "3600"))
            if interval > 0:
                purge_task = asyncio.create_task(_purge_loop(state.ledger, interval))
        elif tenancy:
            logger.warning("/api/v2 disabled: %s", refusal)

        try:
            yield
        finally:
            if purge_task is not None:
                purge_task.cancel()
                try:
                    await purge_task
                except asyncio.CancelledError:
                    pass
            if metrics_server is not None:
                metrics_server.shutdown()
                metrics_server.server_close()
            await engine.close()
            if state.redis is not None and state.redis is not resolved_storage:
                await state.redis.close()
            state.engine = None
            state.ledger = None

    app = FastAPI(
        title="Guardpost",
        description="Self-hosted registration abuse detection API",
        version=__version__,
        lifespan=lifespan,
    )
    # Set before the lifespan runs, so a request that arrives without it
    # (a TestClient used outside its context) fails cleanly with 503.
    app.state.engine = None
    app.state.authenticator = None
    app.state.allow_open = False
    app.state.open_context = None
    app.state.rate_limit = 0
    app.state.redis = None
    app.state.ledger = None
    app.state.limiter = TokenBucket(rate=60)
    app.state.trusted_proxies = resolved_proxies

    # CORS — restrictive by default; users can override via env vars
    cors_origins = [o.strip() for o in os.environ.get(
        "GUARDPOST_CORS_ORIGINS", "").split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["X-Api-Key", "Authorization", "Content-Type", "Idempotency-Key"],
    )

    if resolved_proxies:
        logger.info("Trusting X-Forwarded-For from: %s", ", ".join(map(str, resolved_proxies)))

    @app.middleware("http")
    async def auth_and_rate_limit(request: Request, call_next):
        """Resolve the API key once, then rate-limit per tenant or per IP.

        Authenticated traffic is limited per tenant (all of its keys share one
        bucket); only unauthenticated or rejected (401) traffic is limited per
        client IP. The resolved TenantContext is left on request.state for the
        route dependencies.
        """
        state = request.app.state
        ctx = None
        authenticator = state.authenticator
        if authenticator is not None:
            for presented in extract_credentials(request):
                ctx = await authenticator.authenticate(presented)
                if ctx is not None:
                    break
        request.state.tenant_context = ctx

        if ctx is not None:
            limit = ctx.tenant.config.rate_limit_per_minute
            limit = state.rate_limit if limit is None else limit
            bucket = f"tenant:{ctx.tenant.id}"
        else:
            limit = state.rate_limit
            # X-Forwarded-For counts only when the peer is a trusted proxy;
            # otherwise any caller could pick the key it is limited under.
            bucket = f"ip:{request_client_ip(request, state.trusted_proxies)}"
        if limit:
            if state.redis:
                allowed = await state.redis.rate_limit_check(bucket, limit)
            else:
                allowed = state.limiter.allow(bucket, limit)
            if not allowed:
                return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
        return await call_next(request)

    # Prometheus request metrics (opt-in). Registered after the rate limiter so
    # it is the outer middleware and also sees the limiter's 429s.
    if metrics_enabled:
        from guardpost.metrics import instrument_app

        instrument_app(app)

    _add_shell_routes(app)
    app.include_router(v1.router)
    app.include_router(v2.router)
    return app


async def _purge_loop(service, interval: float) -> None:
    """Retention for the v2 ledger, in process: now, then every ``interval`` seconds."""
    while True:
        try:
            counts = await service.purge()
            if any(counts.values()):
                logger.info("Retention purge: %s", counts)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("Retention purge failed", exc_info=True)
        await asyncio.sleep(interval)


def _add_shell_routes(app: FastAPI) -> None:
    """Dashboard, favicon and the unauthenticated health probes."""

    @app.get("/", include_in_schema=False, dependencies=[Depends(require_dashboard)])
    async def root():
        return RedirectResponse(url="/dashboard")

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        return JSONResponse(content={}, status_code=204)

    @app.get("/dashboard", response_class=HTMLResponse,
             dependencies=[Depends(require_dashboard)], include_in_schema=False)
    async def dashboard(request: Request):
        html = getattr(request.app.state, "dashboard_html", None)
        if html is None:
            html = request.app.state.dashboard_html = _DASHBOARD_PATH.read_text()
        return HTMLResponse(html)

    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        """Liveness probe — returns 200 if the process is alive."""
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    async def readyz(request: Request):
        """Readiness probe — returns 200 only if the storage backend is reachable."""
        try:
            engine = get_engine(request)
            await engine.storage.get_ip_reputation("__readyz__")
            return {"status": "ok"}
        except Exception as exc:
            return JSONResponse(status_code=503, content={"status": "unavailable", "detail": str(exc)})


# ---------------------------------------------------------------------------
# Optional engine components (each opt-in by argument or environment)
# ---------------------------------------------------------------------------


def _smtp_verifier(enabled: bool, timeout: float):
    if not (enabled or os.environ.get("GUARDPOST_ENABLE_SMTP")):
        return None
    from guardpost.email.smtp import SMTPVerifier

    return SMTPVerifier(timeout=timeout)


def _proxy_detector(enabled: bool, ipinfo_token: str | None, maxmind_db_path: str | None):
    if not (enabled or os.environ.get("GUARDPOST_ENABLE_PROXY_DETECTION")):
        return None
    from guardpost.ip.proxy import ProxyDetector

    return ProxyDetector(
        ipinfo_token=ipinfo_token or os.environ.get("IPINFO_TOKEN"),
        maxmind_db_path=maxmind_db_path or os.environ.get("GUARDPOST_MAXMIND_DB"),
    )


def _ai_scorer(enabled: bool, api_key: str | None, model: str | None, cache_backend):
    resolved_key = api_key or os.environ.get("OPENROUTER_API_KEY")
    if not ((enabled or os.environ.get("GUARDPOST_ENABLE_AI")) and resolved_key):
        return None
    from guardpost.ai.scorer import AIScorer

    resolved_model = model or os.environ.get("GUARDPOST_AI_MODEL", "openai/gpt-4o-mini")
    logger.info("AI email scoring enabled (model: %s)", resolved_model)
    return AIScorer(api_key=resolved_key, model=resolved_model, cache_backend=cache_backend)


def _pattern_detector(enabled: bool):
    if not (enabled or os.environ.get("GUARDPOST_ENABLE_PATTERNS")):
        return None
    from guardpost.fraud.patterns import PatternDetector

    logger.info("Pattern detection enabled")
    return PatternDetector()


def _enrichment(enabled: bool, hibp_api_key: str | None):
    if not (enabled or os.environ.get("GUARDPOST_ENABLE_ENRICHMENT")):
        return None
    from guardpost.email.enrichment import EmailEnrichment

    logger.info("Email enrichment enabled (Gravatar + HIBP)")
    return EmailEnrichment(hibp_api_key=hibp_api_key or os.environ.get("HIBP_API_KEY"))
