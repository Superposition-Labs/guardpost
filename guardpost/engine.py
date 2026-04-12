"""Main Guardpost engine — unified interface for all detection layers."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from guardpost.email.banned import BannedEmailEngine
from guardpost.email.validator import (
    check_registration_suspicion,
    is_b2c_email,
    is_disposable_email,
    is_role_account,
    is_suspicious_email,
    normalize_email,
    validate_email_format,
)
from guardpost.ip.reputation import IPReputationEngine
from guardpost.storage.memory import MemoryStorage

if TYPE_CHECKING:
    from guardpost.ai.scorer import AIScorer
    from guardpost.email.enrichment import EmailEnrichment
    from guardpost.email.smtp import SMTPVerifier
    from guardpost.fraud.patterns import PatternDetector
    from guardpost.ip.proxy import ProxyDetector
    from guardpost.storage.base import StorageBackend

logger = logging.getLogger(__name__)


@dataclass
class CheckResult:
    """Result of a full registration check."""

    email: str
    ip_address: str | None
    is_suspicious: bool
    risk_score: int  # 0–100
    reasons: list[str] = field(default_factory=list)
    ip_status: str = "clean"
    ip_reason: str | None = None
    is_banned: bool = False
    normalized_email: str = ""
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
            "ip_status": self.ip_status,
            "ip_reason": self.ip_reason,
            "is_banned": self.is_banned,
            "normalized_email": self.normalized_email,
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


def _compute_risk_score(reasons: list[str], ip_status: str, is_banned: bool) -> int:
    """Compute a 0–100 risk score from detection signals."""
    if is_banned:
        return 100

    score = 0
    weights = {
        "disposable_domain": 40,
        "disposable_mx_infrastructure": 35,
        "no_mx_records": 30,
        "suspicious_domain_keyword": 40,
        "gibberish_username": 25,
        "numeric_domain": 15,
        "very_short_domain": 10,
        "multiple_aliases": 10,
        "role_account": 5,
        "invalid_format": 50,
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
        base = reason.split(":")[0] if ":" in reason else reason
        score += weights.get(base, 10)

    if ip_status == "blacklisted":
        score += 30
    elif ip_status == "graylisted":
        score += 15

    return min(score, 100)


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
        **ip_kwargs,
    ) -> None:
        self.storage: StorageBackend = storage or MemoryStorage()
        self.ip_engine = IPReputationEngine(self.storage, **ip_kwargs)
        self.ban_engine = BannedEmailEngine(self.storage)
        self.smtp_verifier = smtp_verifier
        self.proxy_detector = proxy_detector
        self.ai_scorer = ai_scorer
        self.pattern_detector = pattern_detector
        self.enrichment = enrichment
        self._last_purge: float = 0.0
        self._purge_interval: float = 3600.0  # purge old registrations every hour
        self._registration_ttl: float = 86400.0  # keep registrations for 24 hours

    async def initialize(self) -> None:
        """Initialize storage (create tables/indexes)."""
        await self.storage.initialize()
        # Hydrate pattern detector from persisted registrations
        if self.pattern_detector:
            import time

            cutoff = time.time() - self.pattern_detector.window_seconds
            recent = await self.storage.get_recent_registrations(cutoff)
            for reg in recent:
                self.pattern_detector._registrations.append(reg)

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

        Returns:
            CheckResult with risk score, reasons, and status.
        """
        # Email checks (pure, no storage needed)
        is_suspicious, reasons = await check_registration_suspicion(email)

        # Banned email check
        is_banned = await self.ban_engine.is_banned(email)

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
        ip_type = None
        is_datacenter = False
        is_vpn = False
        is_proxy = False
        is_tor = False
        ip_provider = None

        if ip_address:
            ip_status, ip_reason = await self.ip_engine.check_ip(ip_address)
            if record_ip:
                await self.ip_engine.record_registration(ip_address, is_suspicious)

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
        if self.pattern_detector:
            self.pattern_detector.add_registration(
                email,
                ip_address=ip_address,
            )
            # Persist the registration event to storage
            if self.pattern_detector._registrations:
                last_reg = self.pattern_detector._registrations[-1]
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

        # Combine
        overall_suspicious = is_suspicious or is_banned or ip_status != "clean"
        risk_score = _compute_risk_score(reasons, ip_status, is_banned)

        # Periodic purge of old registration data (PII minimization)
        now = time.time()
        if now - self._last_purge > self._purge_interval:
            self._last_purge = now
            try:
                await self.storage.purge_old_registrations(now - self._registration_ttl)
            except Exception:
                logger.debug("Registration purge failed", exc_info=True)

        return CheckResult(
            email=email,
            ip_address=ip_address,
            is_suspicious=overall_suspicious,
            risk_score=risk_score,
            reasons=reasons,
            ip_status=ip_status,
            ip_reason=ip_reason,
            is_banned=is_banned,
            normalized_email=normalize_email(email),
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

    @staticmethod
    async def is_suspicious(email: str) -> tuple[bool, list[str]]:
        return await is_suspicious_email(email)

    @staticmethod
    def is_role_account(email: str) -> bool:
        return is_role_account(email)

    @staticmethod
    def is_b2c(email: str) -> bool:
        return is_b2c_email(email)

    @staticmethod
    def validate_format(email: str) -> tuple[bool, str | None]:
        return validate_email_format(email)

    async def ban_email(self, email: str, banned_by: str | None = None, reason: str | None = None):
        return await self.ban_engine.ban(email, banned_by, reason)

    async def unban_email(self, email: str) -> bool:
        return await self.ban_engine.unban(email)

    async def is_email_banned(self, email: str) -> bool:
        return await self.ban_engine.is_banned(email)

    async def check_ip(self, ip_address: str) -> tuple[str, str | None]:
        return await self.ip_engine.check_ip(ip_address)

    async def whitelist_ip(self, ip_address: str, whitelisted_by: str, reason: str):
        return await self.ip_engine.whitelist_ip(ip_address, whitelisted_by, reason)

    async def get_stats(self) -> dict:
        """Get aggregate statistics from the storage backend."""
        return await self.storage.get_stats()

    async def get_registration_timeline(
        self, since: float, bucket_seconds: int = 3600
    ) -> list[dict]:
        """Get registration counts grouped by time bucket."""
        return await self.storage.get_registration_timeline(since, bucket_seconds)
