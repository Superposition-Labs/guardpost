"""Main Guardpost engine — unified interface for all detection layers."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from guardpost.email.banned import BannedEmailEngine
from guardpost.email.validator import (
    DnsResolver,
    ReasonTier,
    check_registration_suspicion,
    classify_domain_typo,
    has_suspicious_reason,
    is_b2c_email,
    is_disposable_email,
    is_role_account,
    is_suspicious_email,
    normalize_email,
    parse_domain_list,
    partition_reasons,
    split_reason,
    trusted_extra_domains_from_env,
    validate_email_format,
)
from guardpost.ip.reputation import IPReputationEngine, subnet_key
from guardpost.ledger.keys import TenantHasher
from guardpost.storage.memory import MemoryStorage

if TYPE_CHECKING:
    from guardpost.ai.scorer import AIScorer
    from guardpost.email.enrichment import EmailEnrichment
    from guardpost.email.smtp import SMTPVerifier
    from guardpost.fraud.patterns import PatternDetector
    from guardpost.ip.proxy import ProxyDetector
    from guardpost.storage.base import StorageBackend
    from guardpost.tenancy.models import Tenant

logger = logging.getLogger(__name__)


@dataclass
class CheckResult:
    """Result of a full registration check."""

    email: str
    ip_address: str | None
    is_suspicious: bool
    risk_score: int  # 0–100
    reasons: list[str] = field(default_factory=list)
    # `reasons` split by tier (see ReasonTier). Every reason is in exactly one
    # of the three lists. `is_suspicious` is hard OR soft, so a caller that
    # acts on the verdict alone never punishes an address on a weak signal.
    #   hard -> block (empty by default), soft -> degrade, weak -> score only.
    weak_reasons: list[str] = field(default_factory=list)
    soft_reasons: list[str] = field(default_factory=list)
    hard_reasons: list[str] = field(default_factory=list)
    ip_status: str = "clean"
    ip_reason: str | None = None
    subnet_status: str = "clean"
    subnet_reason: str | None = None
    is_banned: bool = False
    normalized_email: str = ""
    # Set when `typo_domain` fired: the domain the user probably meant, and the
    # rule that matched ("map", "tld" or "numeric"; see classify_domain_typo).
    suggested_domain: str | None = None
    typo_source: str | None = None
    # SMTP verification (Phase 2)
    smtp_status: str | None = None
    smtp_catch_all: bool = False
    # Proxy/VPN/Datacenter detection (Phase 2)
    ip_type: str | None = None
    is_datacenter: bool = False
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    ip_provider: str | None = None
    # AI scoring (Phase 3)
    ai_risk_score: int | None = None
    ai_confidence: float | None = None
    ai_reasons: list[str] = field(default_factory=list)
    ai_analysis: str = ""
    # Enrichment
    is_b2c: bool = False
    gravatar_url: str | None = None
    breach_count: int = 0

    def to_dict(self) -> dict:
        return {
            "email": self.email,
            "ip_address": self.ip_address,
            "is_suspicious": self.is_suspicious,
            "risk_score": self.risk_score,
            "reasons": self.reasons,
            "weak_reasons": self.weak_reasons,
            "soft_reasons": self.soft_reasons,
            "hard_reasons": self.hard_reasons,
            "ip_status": self.ip_status,
            "ip_reason": self.ip_reason,
            "subnet_status": self.subnet_status,
            "subnet_reason": self.subnet_reason,
            "is_banned": self.is_banned,
            "normalized_email": self.normalized_email,
            "suggested_domain": self.suggested_domain,
            "typo_source": self.typo_source,
            "smtp_status": self.smtp_status,
            "smtp_catch_all": self.smtp_catch_all,
            "ip_type": self.ip_type,
            "is_datacenter": self.is_datacenter,
            "is_vpn": self.is_vpn,
            "is_proxy": self.is_proxy,
            "is_tor": self.is_tor,
            "ip_provider": self.ip_provider,
            "ai_risk_score": self.ai_risk_score,
            "ai_confidence": self.ai_confidence,
            "ai_reasons": self.ai_reasons,
            "ai_analysis": self.ai_analysis,
            "is_b2c": self.is_b2c,
            "gravatar_url": self.gravatar_url,
            "breach_count": self.breach_count,
        }


def _compute_risk_score(
    reasons: list[str],
    ip_status: str,
    is_banned: bool,
    subnet_status: str = "clean",
) -> int:
    """Compute a 0–100 risk score from detection signals."""
    if is_banned:
        return 100

    score = 0
    weights = {
        "disposable_domain": 40,
        "disposable_mx_infrastructure": 35,
        "no_mx_records": 30,
        "null_mx": 30,
        "suspicious_domain_keyword": 40,
        "gibberish_username": 25,
        "numeric_domain": 15,
        "very_short_domain": 10,
        "multiple_aliases": 10,
        "role_account": 5,
        "role_account_extended": 5,
        "invalid_format": 50,
        # Aug 2026 signals — see guardpost/email/validator.py for the evidence
        # behind each. dot_noise_local scored 71 hits and 0 paying users on the
        # factory_ru corpus, so it sits just under the disposable-domain tier.
        "dot_noise_local": 30,
        "typo_domain": 20,
        "homograph_domain": 40,
        "subnet_burst": 20,
        # Weak tier: score only, never a verdict (see WEAK_REASONS).
        "gibberish_domain": 10,
        "relay_domain": 10,
        # SMTP reasons
        "smtp_undeliverable": 40,
        "smtp_risky": 15,
        "smtp_catch_all": 10,
        # Proxy/VPN reasons
        "datacenter_ip": 25,
        "vpn_ip": 20,
        "proxy_ip": 20,
        "tor_ip": 30,
        # AI reasons
        "ai_high_risk": 25,
    }
    for reason in reasons:
        # Handle dynamic reasons like "datacenter_range:AWS"
        score += weights.get(split_reason(reason), 10)

    if ip_status == "blacklisted":
        score += 30
    elif ip_status == "graylisted":
        score += 15

    # A bad /24 counts for less than a bad IP: the block is shared, so some of
    # its neighbours are innocent. When the subnet_burst reason fired it has
    # already scored this same /24 above, so the status bonus is not added
    # again (counted once, as the Factory does).
    has_subnet_reason = any(split_reason(r) == "subnet_burst" for r in reasons)
    if not has_subnet_reason:
        if subnet_status == "blacklisted":
            score += 20
        elif subnet_status == "graylisted":
            score += 10

    return min(score, 100)


@dataclass(frozen=True)
class _Scope:
    """The tenant-dependent settings one call runs with."""

    # None on backends without tenancy (Redis, Mongo, Postgres).
    tenant_id: str | None
    key_version: int
    trusted_extra_domains: frozenset[str]
    reason_tiers: Mapping[str, ReasonTier]
    flag_ua_domain: bool
    signals_days: int


# Hashed registration events are kept this long when no tenant config says otherwise.
DEFAULT_SIGNALS_DAYS = 35

# Tests/dev only: let keyed data use the database-stored generated secret.
ALLOW_DB_SECRET_ENV = "GUARDPOST_ALLOW_DB_SECRET"
# Operator override: honour a tenant's ip.reason_detail = "full" even when other
# tenants share the instance (their signups move the counters it would reveal).
ALLOW_FULL_REASON_DETAIL_ENV = "GUARDPOST_ALLOW_FULL_REASON_DETAIL"


class Guardpost:
    """Unified registration abuse detection engine.

    Usage::

        from guardpost.engine import Guardpost

        gp = Guardpost()  # uses in-memory storage by default
        await gp.initialize()

        result = await gp.check("user@example.com", ip_address="1.2.3.4")
        if result.is_suspicious:
            # silently deny bonuses
            ...
    """

    def __init__(
        self,
        storage: StorageBackend | None = None,
        *,
        smtp_verifier: SMTPVerifier | None = None,
        proxy_detector: ProxyDetector | None = None,
        ai_scorer: AIScorer | None = None,
        pattern_detector: PatternDetector | None = None,
        enrichment: EmailEnrichment | None = None,
        trusted_extra_domains: Iterable[str] | str | None = None,
        reason_tiers: Mapping[str, ReasonTier | str] | None = None,
        secret: str | None = None,
        dns_resolver: DnsResolver | None = None,
        allow_db_secret: bool | None = None,
        allow_full_reason_detail: bool | None = None,
        **ip_kwargs,
    ) -> None:
        """
        Args:
            trusted_extra_domains: deployment-specific domains to trust on top
                of the shared TRUSTED_EMAIL_DOMAINS (e.g. the Factory's
                ``factory.bot`` and ``deleted.local``). ``None`` reads
                GUARDPOST_TRUSTED_EXTRA_DOMAINS from the environment.
            reason_tiers: per-reason-kind tier overrides on top of
                DEFAULT_REASON_TIERS (e.g. ``{"typo_domain": "hard"}``).
            secret: the instance secret per-tenant keyed hashes derive from.
                ``None`` reads GUARDPOST_SECRET, else a random secret is
                generated once and kept in the storage backend.
            dns_resolver: the DNS the v2 check asks (None: dnspython, cached).
            allow_db_secret: let keyed data (the v2 ledger, HMAC bans) use the
                generated database-stored secret (else GUARDPOST_ALLOW_DB_SECRET;
                tests and development only: a secret stored next to the data
                protects nothing).
            allow_full_reason_detail: honour ``ip.reason_detail = "full"`` for a
                tenant that is not alone on the instance (else
                GUARDPOST_ALLOW_FULL_REASON_DETAIL).

        Tenancy: every method that touches tenant data takes ``tenant``. On a
        backend with tenancy (SQLite, memory) bans, stats, timeline and
        pattern analysis are scoped to it (``None`` = the backend's legacy
        tenant); the tenant's config also selects trusted domains, reason
        tiers and region rules. IP reputation is shared by all tenants.
        """
        self.storage: StorageBackend = storage or MemoryStorage()
        self.ip_engine = IPReputationEngine(self.storage, **ip_kwargs)
        self.ban_engine = BannedEmailEngine(self.storage)
        self.smtp_verifier = smtp_verifier
        self.proxy_detector = proxy_detector
        self.ai_scorer = ai_scorer
        self.pattern_detector = pattern_detector
        self.enrichment = enrichment
        self.trusted_extra_domains: frozenset[str] = (
            trusted_extra_domains_from_env() if trusted_extra_domains is None
            else parse_domain_list(trusted_extra_domains)
        )
        self.reason_tiers: dict[str, ReasonTier] = {
            kind: ReasonTier(tier) for kind, tier in (reason_tiers or {}).items()
        }
        self.secret = secret
        self.dns_resolver = dns_resolver
        # "argument", "env" or "database" once initialize() resolved the secret.
        self.secret_source: str | None = None
        self._allow_db_secret = (
            os.environ.get(ALLOW_DB_SECRET_ENV, "").strip().lower() in {"1", "true", "yes", "on"}
            if allow_db_secret is None else allow_db_secret
        )
        self._allow_full_reason_detail = (
            os.environ.get(ALLOW_FULL_REASON_DETAIL_ENV, "").strip().lower() in {"1", "true", "yes", "on"}
            if allow_full_reason_detail is None else allow_full_reason_detail
        )
        self._tenant_keys: dict[tuple[str, int], bytes] = {}
        self._hashers: dict[tuple[str, int], TenantHasher] = {}
        # Per-tenant pattern detectors (in memory only; see _detector_for).
        self._pattern_detectors: dict[str, PatternDetector] = {}
        self._last_purge: float = 0.0
        self._last_purge_by_tenant: dict[str, float] = {}
        self._purge_interval: float = 3600.0  # purge old registrations every hour
        self._registration_ttl: float = 86400.0  # keep registrations for 24 hours

    @property
    def tenancy(self) -> bool:
        """True when the storage backend keeps per-tenant data."""
        return bool(getattr(self.storage, "supports_tenancy", False))

    async def reason_detail(self, tenant: Tenant | None) -> str:
        """How much shared IP reputation ``tenant`` may see: "status" or "full".

        The shared table's status reasons ("5 suspicious registrations") count
        every tenant's signups, so by default a response shows the status only.
        A tenant's ``ip.reason_detail = "full"`` is honoured while no other
        active tenant (one that has held an API key) shares the instance, or
        with GUARDPOST_ALLOW_FULL_REASON_DETAIL.
        """
        if tenant is None or tenant.config.ip.reason_detail != "full":
            return "status"
        if self._allow_full_reason_detail:
            return "full"
        others = await self.other_active_tenants(tenant.id)
        if not others:
            return "full"
        logger.debug("ip.reason_detail=full for tenant %r ignored: tenants %s share the instance",
                     tenant.id, ", ".join(others))
        return "status"

    async def other_active_tenants(self, tenant_id: str) -> list[str]:
        """Active tenants other than ``tenant_id`` that have ever held an API key.

        A tenant that never had a key (the auto-created legacy tenant of an
        instance that set GUARDPOST_LEGACY_TENANT elsewhere) never sent a signup.
        """
        with_keys = {k.tenant_id for k in await self.storage.list_api_keys()}
        return sorted(t.id for t in await self.storage.list_tenants()
                      if t.active and t.id != tenant_id and t.id in with_keys)

    async def shows_full_ip_detail_v1(self, tenant: Tenant | None) -> bool:
        """v1 routes: the legacy tenant keeps 0.2's exact strings; others follow reason_detail."""
        if not self.tenancy or tenant is None or tenant.id == getattr(self.storage, "legacy_tenant", None):
            return True
        return await self.reason_detail(tenant) == "full"

    async def initialize(self) -> None:
        """Initialize storage (create tables/indexes)."""
        await self.storage.initialize()
        if self.tenancy:
            self.secret = await self._resolve_secret()
            await self._prepare_keyed_data()
        elif self.pattern_detector:
            # Hydrate the pattern detector from persisted registrations.
            # Tenancy backends persist no plaintext, so there is nothing to load.
            cutoff = time.time() - self.pattern_detector.window_seconds
            recent = await self.storage.get_recent_registrations(cutoff)
            for reg in recent:
                self.pattern_detector._registrations.append(reg)

    async def _resolve_secret(self) -> str:
        from guardpost.tenancy.crypto import INSTANCE_SECRET_META_KEY, SECRET_ENV, generate_secret

        if self.secret:
            self.secret_source = "argument"
            return self.secret
        if os.environ.get(SECRET_ENV):
            self.secret_source = "env"
            return os.environ[SECRET_ENV]
        self.secret_source = "database"
        if getattr(self.storage, "db_path", None) is not None:
            logger.warning(
                "%s is not set: using a generated secret stored in the database. Set %s (and back it "
                "up separately) so a copy of the database alone cannot re-identify hashed values.",
                SECRET_ENV, SECRET_ENV)
        return await self.storage.ensure_meta(INSTANCE_SECRET_META_KEY, generate_secret())

    @property
    def keyed(self) -> bool:
        """True when keyed data (HMAC bans, the v2 ledger) is in use.

        It needs a real secret: GUARDPOST_SECRET or the ``secret`` argument.
        The generated database-stored secret qualifies only with
        GUARDPOST_ALLOW_DB_SECRET=1 (tests and development).
        """
        return self.tenancy and self.secret is not None and (
            self.secret_source in ("argument", "env") or self._allow_db_secret)

    def ledger_refusal(self) -> str | None:
        """Why /api/v2 cannot serve on this instance, or None when it can."""
        if not self.tenancy or not hasattr(self.storage, "transaction"):
            return ("The v2 API needs the SQLite storage backend (GUARDPOST_STORAGE=sqlite): its ledger "
                    "lives in the same database as tenants and bans.")
        if not self.keyed:
            return ("The v2 ledger needs GUARDPOST_SECRET. This instance runs on the generated secret stored "
                    "in its own database, which would let anyone holding a copy of the database re-identify "
                    "the hashed emails, devices and addresses. Set GUARDPOST_SECRET (and back it up separately), "
                    f"or {ALLOW_DB_SECRET_ENV}=1 for tests and development only.")
        return None

    async def _prepare_keyed_data(self) -> None:
        """Re-key sha256 bans once a real secret exists; refuse a secret that does not fit the data."""
        from guardpost.ledger import rekey

        if not hasattr(self.storage, "transaction"):
            return
        if self.keyed:
            def run():
                with self.storage.transaction() as conn:
                    return rekey.ensure_keyed(conn, self.secret)

            rekeyed = await asyncio.to_thread(run)
            if rekeyed:
                logger.info("Re-keyed %d bans from sha256 to per-tenant HMAC", rekeyed)
            return
        if await self.storage.get_meta(rekey.FINGERPRINT_META_KEY) is not None:
            raise rekey.SecretMismatchError(
                "This database's bans and v2 ledger are keyed with GUARDPOST_SECRET, but it is not set "
                f"(or {ALLOW_DB_SECRET_ENV} was turned off). Set the secret the data was written with.")

    def hasher(self, tenant: Tenant | None) -> TenantHasher:
        """The tenant's keyed hasher (keyed mode only)."""
        scope = self._scope(tenant)
        cache_key = (scope.tenant_id, scope.key_version)
        hasher = self._hashers.get(cache_key)
        if hasher is None:
            hasher = self._hashers[cache_key] = TenantHasher(self.secret, scope.tenant_id, scope.key_version)
        return hasher

    def _ban_keyer(self, tenant: Tenant | None):
        """sha256 -> stored ban key: the tenant HMAC in keyed mode, else the sha256 itself."""
        if not self.keyed:
            return None
        return self.hasher(tenant).email

    def _scope(self, tenant: Tenant | None) -> _Scope:
        legacy = getattr(self.storage, "legacy_tenant", None) if self.tenancy else None
        if tenant is None:
            return _Scope(legacy, 1, self.trusted_extra_domains, self.reason_tiers, False, DEFAULT_SIGNALS_DAYS)
        cfg = tenant.config
        trusted = (
            self.trusted_extra_domains if cfg.email.trusted_extra_domains is None
            else frozenset(cfg.email.trusted_extra_domains)
        )
        tiers = {**self.reason_tiers, **{k: ReasonTier(v) for k, v in cfg.email.reason_tiers.items()}}
        return _Scope(
            tenant.id if self.tenancy else None, tenant.key_version, trusted, tiers,
            cfg.ua_domain_enabled, cfg.retention.signals_days,
        )

    def _ip_key(self, scope: _Scope, ip_address: str) -> str:
        from guardpost.tenancy.crypto import keyed_hash, tenant_key

        cache_key = (scope.tenant_id, scope.key_version)
        key = self._tenant_keys.get(cache_key)
        if key is None:
            key = self._tenant_keys[cache_key] = tenant_key(self.secret, scope.tenant_id, scope.key_version)
        return keyed_hash(key, ip_address, purpose="ip")

    def _detector_for(self, scope: _Scope) -> PatternDetector | None:
        """The pattern detector for a tenant.

        With tenancy, each tenant gets its own detector, cloned from the
        configured one. Analysis needs usernames, so it runs on an in-memory
        window only: nothing plaintext is written to disk, and the window
        starts empty after a restart.
        """
        if self.pattern_detector is None or scope.tenant_id is None:
            return self.pattern_detector
        detector = self._pattern_detectors.get(scope.tenant_id)
        if detector is None:
            from guardpost.fraud.patterns import PatternDetector

            template = self.pattern_detector
            detector = self._pattern_detectors[scope.tenant_id] = PatternDetector(
                window_seconds=template.window_seconds,
                similarity_threshold=template.similarity_threshold,
                velocity_threshold=template.velocity_threshold,
                ip_burst_threshold=template.ip_burst_threshold,
            )
        return detector

    async def _record_event(self, scope: _Scope, ip_address: str | None, ip_record, suspicious: bool) -> None:
        """Count a registration for the tenant: no email, a keyed hash of the IP."""
        ip_status = None
        if ip_record is not None:
            ip_status = "whitelisted" if ip_record.manually_whitelisted else ip_record.status
        await self.storage.record_registration_event(
            scope.tenant_id,
            ts=time.time(),
            suspicious=suspicious,
            ip_key=self._ip_key(scope, ip_address) if ip_address else None,
            ip_status=ip_status,
        )

    async def _maybe_purge(self, scope: _Scope) -> None:
        """Hourly retention purge (PII minimization)."""
        now = time.time()
        if scope.tenant_id is not None:
            if now - self._last_purge_by_tenant.get(scope.tenant_id, 0.0) <= self._purge_interval:
                return
            self._last_purge_by_tenant[scope.tenant_id] = now
            try:
                await self.storage.purge_registration_events(scope.tenant_id, now - scope.signals_days * 86400)
            except Exception:
                logger.debug("Registration event purge failed", exc_info=True)
            return
        if now - self._last_purge > self._purge_interval:
            self._last_purge = now
            try:
                await self.storage.purge_old_registrations(now - self._registration_ttl)
            except Exception:
                logger.debug("Registration purge failed", exc_info=True)

    async def close(self) -> None:
        """Release storage resources."""
        await self.storage.close()
        if self.enrichment:
            await self.enrichment.close()

    async def check(
        self,
        email: str,
        *,
        ip_address: str | None = None,
        record_ip: bool = True,
        smtp_verify: bool = False,
        check_proxy: bool = False,
        ai_score: bool = False,
        enrich: bool = False,
        tenant: Tenant | None = None,
    ) -> CheckResult:
        """Full registration suspicion check.

        Args:
            email: The email to validate.
            ip_address: Optional IP to check reputation.
            record_ip: Whether to record this check as a registration
                       for IP tracking purposes.
            smtp_verify: Whether to run SMTP verification (requires SMTPVerifier).
            check_proxy: Whether to run proxy/VPN/datacenter detection
                         (requires ProxyDetector).
            ai_score: Whether to run AI email scoring (requires AIScorer).
            enrich: Whether to run enrichment lookups (Gravatar, HIBP).
            tenant: whose bans, config and stats apply (None: legacy tenant).

        Returns:
            CheckResult with risk score, reasons, and status.
        """
        scope = self._scope(tenant)

        # Email checks (pure, no storage needed)
        is_suspicious, reasons = await check_registration_suspicion(
            email, trusted_extra_domains=scope.trusted_extra_domains, flag_ua_domain=scope.flag_ua_domain)
        typo = classify_domain_typo(email) if "typo_domain" in reasons else None

        # Banned email check (per tenant)
        is_banned = await self.ban_engine.is_banned(email, tenant_id=scope.tenant_id, keyer=self._ban_keyer(tenant))

        # SMTP verification
        smtp_status = None
        smtp_catch_all = False
        if smtp_verify and self.smtp_verifier:
            smtp_result = await self.smtp_verifier.verify(email)
            smtp_status = smtp_result.status.value
            smtp_catch_all = smtp_result.is_catch_all
            if smtp_result.status.value == "undeliverable":
                reasons.append("smtp_undeliverable")
                is_suspicious = True
            elif smtp_result.status.value == "risky":
                reasons.append("smtp_risky")
            if smtp_result.is_catch_all:
                reasons.append("smtp_catch_all")

        # IP check
        ip_status = "clean"
        ip_reason = None
        subnet_status = "clean"
        subnet_reason = None
        ip_type = None
        is_datacenter = False
        is_vpn = False
        is_proxy = False
        is_tor = False
        ip_provider = None
        ip_record = None

        if ip_address:
            ip_status, ip_reason = await self.ip_engine.check_ip(ip_address)
            # Read the /24 before recording, so this registration does not
            # contribute to the verdict passed on itself.
            subnet_status, subnet_reason = await self.ip_engine.check_subnet(ip_address)
            if record_ip:
                ip_record = await self.ip_engine.record_registration(ip_address, is_suspicious)

            # A dirty /24 whose individual IPs all look clean is the rotating
            # proxy pool signature — surface it as its own reason so the pattern
            # is visible in the logs, not just folded into the score.
            if subnet_status != "clean" and ip_status == "clean":
                cidr = subnet_key(ip_address)
                reasons.append(f"subnet_burst:{cidr}")

            # Proxy/VPN/datacenter detection
            if check_proxy and self.proxy_detector:
                proxy_result = await self.proxy_detector.check(ip_address)
                ip_type = proxy_result.ip_type.value
                is_datacenter = proxy_result.is_datacenter
                is_vpn = proxy_result.is_vpn
                is_proxy = proxy_result.is_proxy
                is_tor = proxy_result.is_tor
                ip_provider = proxy_result.provider
                if proxy_result.is_suspicious:
                    if proxy_result.is_tor:
                        reasons.append("tor_ip")
                    elif proxy_result.is_datacenter:
                        reasons.append("datacenter_ip")
                    elif proxy_result.is_vpn:
                        reasons.append("vpn_ip")
                    elif proxy_result.is_proxy:
                        reasons.append("proxy_ip")
                    is_suspicious = True

        # AI scoring
        ai_risk_score = None
        ai_confidence = None
        ai_reasons: list[str] = []
        ai_analysis = ""
        if ai_score and self.ai_scorer:
            try:
                ai_result = await self.ai_scorer.score(email)
                ai_risk_score = ai_result.risk_score
                ai_confidence = ai_result.confidence
                ai_reasons = ai_result.reasons
                ai_analysis = ai_result.analysis
                if ai_result.risk_score >= 60:
                    reasons.append("ai_high_risk")
                    is_suspicious = True
            except Exception:
                logger.warning("AI scoring failed for ***@%s",
                               email.split("@")[-1] if "@" in email else "unknown", exc_info=True)

        # Pattern tracking (always record if detector is available)
        detector = self._detector_for(scope)
        if detector:
            detector.add_registration(
                email,
                ip_address=ip_address,
            )
            # Pre-tenancy backends persist the registration (plaintext) for
            # hydration; tenancy backends never write the email anywhere.
            if not self.tenancy and detector._registrations:
                last_reg = detector._registrations[-1]
                try:
                    await self.storage.save_registration(last_reg)
                except Exception:
                    logger.debug(
                        "Failed to persist registration", exc_info=True)

        # B2C detection (always — pure lookup, no external call)
        email_is_b2c = is_b2c_email(email)

        # Enrichment (opt-in — external HTTP calls)
        gravatar_url = None
        breach_count = 0
        if enrich and self.enrichment:
            try:
                gravatar_url = await self.enrichment.gravatar_url(email)
            except Exception:
                logger.debug("Gravatar lookup failed for ***@%s",
                             email.split("@")[-1] if "@" in email else "unknown", exc_info=True)
            try:
                breach_count = await self.enrichment.hibp_breach_count(email)
            except Exception:
                logger.debug("HIBP lookup failed for ***@%s", email.split("@")
                             [-1] if "@" in email else "unknown", exc_info=True)

        # Combine. Hard and soft reasons decide the verdict — every reason
        # feeds the score. `is_suspicious` from the email layer is recomputed
        # here rather than reused, because reasons added since (SMTP, proxy,
        # subnet) have tiers of their own, and the tiers may be overridden.
        hard_reasons, soft_reasons, weak_reasons = partition_reasons(reasons, scope.reason_tiers)
        overall_suspicious = (
            bool(hard_reasons or soft_reasons) or is_banned or ip_status != "clean"
        )
        risk_score = _compute_risk_score(
            reasons, ip_status, is_banned, subnet_status)

        # The tenant's own registration count (stats, timeline). `record_ip`
        # is the caller saying "this check is a registration".
        if self.tenancy and record_ip:
            await self._record_event(scope, ip_address, ip_record, overall_suspicious)

        await self._maybe_purge(scope)

        return CheckResult(
            email=email,
            ip_address=ip_address,
            is_suspicious=overall_suspicious,
            risk_score=risk_score,
            reasons=reasons,
            weak_reasons=weak_reasons,
            soft_reasons=soft_reasons,
            hard_reasons=hard_reasons,
            ip_status=ip_status,
            ip_reason=ip_reason,
            subnet_status=subnet_status,
            subnet_reason=subnet_reason,
            is_banned=is_banned,
            normalized_email=normalize_email(email),
            suggested_domain=typo[0] if typo else None,
            typo_source=typo[1] if typo else None,
            smtp_status=smtp_status,
            smtp_catch_all=smtp_catch_all,
            ip_type=ip_type,
            is_datacenter=is_datacenter,
            is_vpn=is_vpn,
            is_proxy=is_proxy,
            is_tor=is_tor,
            ip_provider=ip_provider,
            ai_risk_score=ai_risk_score,
            ai_confidence=ai_confidence,
            ai_reasons=ai_reasons,
            ai_analysis=ai_analysis,
            is_b2c=email_is_b2c,
            gravatar_url=gravatar_url,
            breach_count=breach_count,
        )

    # ------------------------------------------------------------------
    # Convenience wrappers
    # ------------------------------------------------------------------

    @staticmethod
    def normalize_email(email: str) -> str:
        return normalize_email(email)

    @staticmethod
    def is_disposable(email: str) -> bool:
        return is_disposable_email(email)

    async def is_suspicious(self, email: str, *, tenant: Tenant | None = None) -> tuple[bool, list[str]]:
        scope = self._scope(tenant)
        _, reasons = await is_suspicious_email(email, trusted_extra_domains=scope.trusted_extra_domains)
        return has_suspicious_reason(reasons, scope.reason_tiers), reasons

    @staticmethod
    def is_role_account(email: str) -> bool:
        return is_role_account(email)

    @staticmethod
    def is_b2c(email: str) -> bool:
        return is_b2c_email(email)

    @staticmethod
    def validate_format(email: str) -> tuple[bool, str | None]:
        return validate_email_format(email)

    async def ban_email(
        self, email: str, banned_by: str | None = None, reason: str | None = None, *, tenant: Tenant | None = None,
    ):
        return await self.ban_engine.ban(email, banned_by, reason, tenant_id=self._scope(tenant).tenant_id,
                                         keyer=self._ban_keyer(tenant))

    async def unban_email(self, email: str, *, tenant: Tenant | None = None) -> bool:
        return await self.ban_engine.unban(email, tenant_id=self._scope(tenant).tenant_id,
                                           keyer=self._ban_keyer(tenant))

    async def is_email_banned(self, email: str, *, tenant: Tenant | None = None) -> bool:
        return await self.ban_engine.is_banned(email, tenant_id=self._scope(tenant).tenant_id,
                                               keyer=self._ban_keyer(tenant))

    async def check_ip(self, ip_address: str) -> tuple[str, str | None]:
        """Shared IP reputation (the same for every tenant)."""
        return await self.ip_engine.check_ip(ip_address)

    async def record_ip_registration(self, ip_address: str, is_suspicious: bool, *, tenant: Tenant | None = None):
        """Count a registration from an IP: shared reputation + the tenant's own stats."""
        record = await self.ip_engine.record_registration(ip_address, is_suspicious)
        if self.tenancy:
            await self._record_event(self._scope(tenant), ip_address, record, is_suspicious)
        return record

    async def whitelist_ip(self, ip_address: str, whitelisted_by: str, reason: str):
        """Whitelist an IP or /24 in the shared reputation table (all tenants)."""
        return await self.ip_engine.whitelist_ip(ip_address, whitelisted_by, reason)

    async def get_stats(self, *, tenant: Tenant | None = None) -> dict:
        """Aggregate statistics — the tenant's own, on backends with tenancy."""
        if self.tenancy:
            return await self.storage.get_tenant_stats(self._scope(tenant).tenant_id)
        return await self.storage.get_stats()

    async def get_registration_timeline(
        self, since: float, bucket_seconds: int = 3600, *, tenant: Tenant | None = None,
    ) -> list[dict]:
        """Get registration counts grouped by time bucket."""
        if self.tenancy:
            return await self.storage.get_registration_timeline(
                since, bucket_seconds, tenant_id=self._scope(tenant).tenant_id)
        return await self.storage.get_registration_timeline(since, bucket_seconds)

    def pattern_report(self, *, tenant: Tenant | None = None):
        """The tenant's pattern analysis, or None when patterns are disabled."""
        detector = self._detector_for(self._scope(tenant))
        return detector.analyze() if detector else None
