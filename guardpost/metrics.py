"""Prometheus metrics for Guardpost.

Enable by setting GUARDPOST_ENABLE_METRICS=1 or passing enable_metrics=True
to create_app(). Metrics are served on a SEPARATE port (GUARDPOST_METRICS_PORT,
default 9100) by prometheus_client's own HTTP server, never by the API app, so
publishing the API port does not publish the metrics.
"""

from __future__ import annotations

import time

from fastapi import FastAPI, Request
from prometheus_client import (
    REGISTRY,
    Counter,
    Gauge,
    Histogram,
    start_http_server,
)

# ---------------------------------------------------------------------------
# Metric definitions
# ---------------------------------------------------------------------------

# Row 1: Overview
CHECKS_TOTAL = Counter(
    "guardpost_checks_total",
    "Total registration checks performed",
)
CHECKS_SUSPICIOUS = Counter(
    "guardpost_checks_suspicious_total",
    "Registration checks flagged as suspicious",
)
RISK_SCORE = Histogram(
    "guardpost_risk_score",
    "Overall risk score distribution",
    buckets=[0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100],
)

# Row 2: Detection signals
DETECTION_REASONS = Counter(
    "guardpost_detection_reason_total",
    "Detection reasons triggered",
    ["reason"],
)

# Row 3: IP intelligence
IP_STATUS_GAUGE = Gauge(
    "guardpost_ip_status",
    "Current IP reputation distribution",
    ["status"],
)
PROXY_DETECTIONS = Counter(
    "guardpost_proxy_detection_total",
    "Proxy/VPN/Tor detections",
    ["type"],
)

# Row 4: Email intelligence
EMAIL_TYPE = Counter(
    "guardpost_email_type_total",
    "Email classifications",
    ["type"],
)
DISPOSABLE_DOMAIN = Counter(
    "guardpost_disposable_domain_total",
    "Disposable domain hits",
    ["domain"],
)
BANNED_EMAILS = Gauge(
    "guardpost_banned_emails_total",
    "Current total banned emails",
)

# Row 5: Enrichment & AI
AI_RISK_HISTOGRAM = Histogram(
    "guardpost_ai_risk_score",
    "AI risk score distribution",
    buckets=[0, 20, 40, 60, 80, 100],
)
BREACH_HISTOGRAM = Histogram(
    "guardpost_breach_count",
    "Data breach count per email",
    buckets=[0, 1, 3, 5, 10, 20],
)
GRAVATAR_FOUND = Counter(
    "guardpost_gravatar_found_total",
    "Emails with Gravatar",
)
GRAVATAR_CHECKED = Counter(
    "guardpost_gravatar_checked_total",
    "Emails checked for Gravatar",
)

# Row 6: Operations
REQUEST_DURATION = Histogram(
    "guardpost_request_duration_seconds",
    "API request latency",
    ["method", "endpoint", "status_code"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5],
)
RATE_LIMIT_HITS = Counter(
    "guardpost_rate_limit_hits_total",
    "Rate limit 429 responses",
)
STORAGE_IPS = Gauge("guardpost_storage_ips_total", "Total IPs tracked")
STORAGE_BANNED = Gauge("guardpost_storage_banned_total", "Total banned emails")
STORAGE_REGS = Gauge("guardpost_storage_registrations_total", "Total registrations")


# ---------------------------------------------------------------------------
# Helper: record metrics from a CheckResult
# ---------------------------------------------------------------------------


def record_check(result) -> None:
    """Record Prometheus metrics from a CheckResult."""
    CHECKS_TOTAL.inc()
    RISK_SCORE.observe(result.risk_score)

    if result.is_suspicious:
        CHECKS_SUSPICIOUS.inc()

    for reason in result.reasons:
        DETECTION_REASONS.labels(reason=reason).inc()

    # Email type classification
    if result.is_banned:
        pass  # already tracked via banned gauge
    elif hasattr(result, "is_b2c") and result.is_b2c:
        EMAIL_TYPE.labels(type="b2c").inc()
    else:
        EMAIL_TYPE.labels(type="business").inc()

    # Disposable domain tracking (extract domain, limit cardinality)
    email_parts = result.email.split("@")
    if len(email_parts) == 2:
        domain = email_parts[1].lower()
        if "disposable_domain" in result.reasons:
            DISPOSABLE_DOMAIN.labels(domain=domain).inc()

    # Role account
    if "role_account" in result.reasons:
        EMAIL_TYPE.labels(type="role").inc()

    # IP status
    if result.ip_address and result.ip_status:
        IP_STATUS_GAUGE.labels(status=result.ip_status).inc()

    # Proxy/VPN detection
    if result.is_datacenter:
        PROXY_DETECTIONS.labels(type="datacenter").inc()
    if result.is_vpn:
        PROXY_DETECTIONS.labels(type="vpn").inc()
    if result.is_proxy:
        PROXY_DETECTIONS.labels(type="proxy").inc()
    if result.is_tor:
        PROXY_DETECTIONS.labels(type="tor").inc()

    # AI scoring
    if result.ai_risk_score is not None:
        AI_RISK_HISTOGRAM.observe(result.ai_risk_score)

    # Enrichment
    if result.breach_count:
        BREACH_HISTOGRAM.observe(result.breach_count)
    if result.gravatar_url is not None:
        GRAVATAR_CHECKED.inc()
        GRAVATAR_FOUND.inc()
    elif hasattr(result, "gravatar_url"):
        # Was checked but not found
        GRAVATAR_CHECKED.inc()


# ---------------------------------------------------------------------------
# FastAPI integration
# ---------------------------------------------------------------------------

DEFAULT_METRICS_PORT = 9100
UNMATCHED_ROUTE = "<unmatched>"


def route_template(request: Request) -> str:
    """The matched route's path template ("/api/v1/check"), never the raw path.

    Raw paths are attacker-chosen, so labelling by them lets any client mint
    unbounded label values. Requests that match no route share one label.
    """
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    return path if isinstance(path, str) else UNMATCHED_ROUTE


def instrument_app(app: FastAPI) -> None:
    """Add request-duration / rate-limit middleware to the API app.

    The metrics themselves are NOT served by this app: call
    start_metrics_server() to expose them on a separate, unpublished port.
    """

    @app.middleware("http")
    async def metrics_middleware(request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - start

        REQUEST_DURATION.labels(
            method=request.method,
            endpoint=route_template(request),
            status_code=str(response.status_code),
        ).observe(elapsed)

        if response.status_code == 429:
            RATE_LIMIT_HITS.inc()

        return response


def start_metrics_server(port: int = DEFAULT_METRICS_PORT, addr: str = "127.0.0.1"):
    """Serve /metrics on its own port (daemon thread). Returns (server, thread).

    Keep this port off the public interface: in Docker, bind 0.0.0.0 inside the
    container but never publish it, so only Prometheus on the internal network
    can scrape it.
    """
    return start_http_server(port, addr=addr, registry=REGISTRY)

