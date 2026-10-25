"""FastAPI application factory.

All runtime state lives on ``app.state`` (no module globals), so several apps
can coexist in one process — tests build one per case.

Start with:
    guardpost serve
    # or
    uvicorn guardpost.api.server:create_app --factory
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from guardpost import __version__
from guardpost.api import v1
from guardpost.api.auth import require_dashboard_auth
from guardpost.api.deps import get_engine
from guardpost.api.proxies import parse_trusted_proxies, request_client_ip, trusted_proxies_from_env
from guardpost.engine import Guardpost
from guardpost.storage.sqlite import SQLiteStorage

logger = logging.getLogger(__name__)

_DASHBOARD_PATH = Path(__file__).resolve().parent / "dashboard.html"


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
) -> FastAPI:
    """Create the FastAPI application.

    Args:
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

        # --- Storage backend selection ---
        resolved_redis = redis_url or os.environ.get("GUARDPOST_REDIS_URL")
        if resolved_redis:
            from guardpost.storage.redis import RedisStorage

            storage = RedisStorage(resolved_redis)
            state.redis = storage
            logger.info("Using Redis 8 storage backend (%s)", resolved_redis)
        else:
            resolved_db = db_path or os.environ.get("GUARDPOST_DB_PATH")
            storage = SQLiteStorage(resolved_db) if resolved_db else SQLiteStorage()
            state.redis = None

        engine = Guardpost(
            storage=storage,
            smtp_verifier=_smtp_verifier(enable_smtp, smtp_timeout),
            proxy_detector=_proxy_detector(enable_proxy_detection, ipinfo_token, maxmind_db_path),
            ai_scorer=_ai_scorer(enable_ai, openrouter_api_key, ai_model, state.redis),
            pattern_detector=_pattern_detector(enable_patterns),
            enrichment=_enrichment(enable_enrichment, hibp_api_key),
            # None -> GUARDPOST_TRUSTED_EXTRA_DOMAINS
            trusted_extra_domains=trusted_extra_domains,
        )
        if engine.trusted_extra_domains:
            logger.info("Extra trusted domains: %s", ", ".join(sorted(engine.trusted_extra_domains)))
        await engine.initialize()
        state.engine = engine

        state.api_key = api_key or os.environ.get("GUARDPOST_API_KEY")
        if state.api_key:
            logger.info("API key authentication enabled")
        else:
            logger.warning("No API key set — API is unauthenticated")

        state.rate_limit = rate_limit or int(os.environ.get("GUARDPOST_RATE_LIMIT", "0"))
        state.limiter = TokenBucket(rate=state.rate_limit or 60)
        if state.rate_limit:
            where = "via Redis" if state.redis else "in memory"
            logger.info("Rate limiting enabled (%s): %d requests/min per IP", where, state.rate_limit)

        metrics_server = None
        if metrics_enabled:
            from guardpost.metrics import start_metrics_server

            metrics_server, _ = start_metrics_server(resolved_metrics_port, resolved_metrics_host)
            state.metrics_port = metrics_server.server_port
            logger.info("Prometheus metrics on http://%s:%d/metrics (separate listener)",
                        resolved_metrics_host, metrics_server.server_port)

        try:
            yield
        finally:
            if metrics_server is not None:
                metrics_server.shutdown()
                metrics_server.server_close()
            await engine.close()
            state.engine = None

    app = FastAPI(
        title="Guardpost",
        description="Self-hosted registration abuse detection API",
        version=__version__,
        lifespan=lifespan,
    )
    # Set before the lifespan runs, so a request that arrives without it
    # (a TestClient used outside its context) fails cleanly with 503.
    app.state.engine = None
    app.state.api_key = None
    app.state.rate_limit = 0
    app.state.redis = None
    app.state.limiter = TokenBucket(rate=60)
    app.state.trusted_proxies = resolved_proxies

    # CORS — restrictive by default; users can override via env vars
    cors_origins = [o.strip() for o in os.environ.get(
        "GUARDPOST_CORS_ORIGINS", "").split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["X-Api-Key", "Content-Type"],
    )

    if resolved_proxies:
        logger.info("Trusting X-Forwarded-For from: %s", ", ".join(map(str, resolved_proxies)))

    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        state = request.app.state
        if state.rate_limit:
            # X-Forwarded-For counts only when the peer is a trusted proxy;
            # otherwise any caller could pick the key it is limited under.
            client_ip = request_client_ip(request, state.trusted_proxies)
            if state.redis:
                allowed = await state.redis.rate_limit_check(client_ip, state.rate_limit)
            else:
                allowed = state.limiter.allow(client_ip)
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
    return app


def _add_shell_routes(app: FastAPI) -> None:
    """Dashboard, favicon and the unauthenticated health probes."""

    @app.get("/", include_in_schema=False, dependencies=[Depends(require_dashboard_auth)])
    async def root():
        return RedirectResponse(url="/dashboard")

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        return JSONResponse(content={}, status_code=204)

    @app.get("/dashboard", response_class=HTMLResponse,
             dependencies=[Depends(require_dashboard_auth)], include_in_schema=False)
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
