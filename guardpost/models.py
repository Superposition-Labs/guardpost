"""Request and response models of the Guardpost API, shared by the server and the clients.

The v2 routes (:mod:`guardpost.api.v2`) validate requests and render
responses with these models, and :mod:`guardpost.client` sends and parses the
same ones, so the Python client cannot drift from the server. This module
needs only pydantic (no FastAPI): ``pip install guardpost-server[client]``.

Names that exist in v1 too carry a ``V2`` (``CheckV2Request``,
``CheckV2Response``, ``BanV2Request``, ``UnbanV2Request``, ``BanV2Response``,
``StatsV2Response``), which is also how ``openapi/guardpost.json`` names them.
The old names stay importable from :mod:`guardpost.api.v2`.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from guardpost.rules.network import canonical_ip

ACCOUNT_ID_PATTERN = r"^[A-Za-z0-9._:-]{1,128}$"
SHA256_PATTERN = r"^[0-9a-f]{64}$"

# Lifecycle events (POST /api/v2/accounts/{id}/events).
EVENT_TYPES = (
    "created", "deleted", "banned", "unbanned", "paid", "flagged", "unflagged",
    "referral_code_retracted", "referral_code_restored",
)
EventType = Literal[
    "created", "deleted", "banned", "unbanned", "paid", "flagged", "unflagged",
    "referral_code_retracted", "referral_code_restored",
]
# Rows per POST /api/v2/import/* request (the clients split larger imports).
IMPORT_MAX_ROWS = 1000

Decision = Literal["allow", "degrade", "block"]
Action = Literal["no_welcome_credits", "no_referral_attribution", "no_referral_payouts", "retract_referral_code"]


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _validate_ip(value: str | None) -> str | None:
    if value is not None and canonical_ip(value) is None:
        raise ValueError("invalid IP address")
    return value


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


class _NeedsEmail(_EmailOrHash):
    @model_validator(mode="after")
    def _needs_identity(self):
        if not self.email and not self.email_sha256:
            raise ValueError("email or email_sha256 is required")
        return self


class CheckV2Request(_NeedsEmail):
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


class CommitRequest(_In):
    check_id: str = Field(min_length=1, max_length=64)
    account_id: str = Field(pattern=ACCOUNT_ID_PATTERN)


class EventRequest(_EmailOrHash):
    type: EventType
    occurred_at: datetime | None = None
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=200)
    permanent_email_ban: bool = Field(default=False, description="banned: also ban the address for this tenant")
    reason: str | None = Field(default=None, max_length=500)
    actor: str | None = Field(default=None, max_length=128)


class BanV2Request(_NeedsEmail):
    reason: str | None = Field(default=None, max_length=500)
    banned_by: str | None = Field(default=None, max_length=128)


class UnbanV2Request(_NeedsEmail):
    pass


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
    decision: Decision | None = None
    reasons: list[str] | None = Field(default=None, max_length=50)

    _ip = field_validator("ip")(_validate_ip)


class BanImport(_NeedsEmail):
    banned_at: datetime | None = None
    banned_by: str | None = Field(default=None, max_length=128)
    reason: str | None = Field(default=None, max_length=500)


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
# Responses
# ---------------------------------------------------------------------------


class _Out(BaseModel):
    """A response. ``result["field"]`` also works, for code written against the 0.2 dict client."""

    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key) from None


class ReasonOut(_Out):
    code: str = Field(description="Factory's kind:detail form, e.g. subnet_burst:203.0.114.0/24, same_device:acc1")
    kind: str
    tier: Literal["hard", "soft", "weak"]
    evidence: dict | None = Field(default=None, description="Opaque facts: the tenant's own account ids, counts")


class ReferralOut(_Out):
    attribute: bool = Field(description="Record the referral (false: no attribution at all)")
    suspicious: bool = Field(description="Attribute it, but flagged: the referee gets no referral bonus")
    reason: str | None = None


class SignalsOut(_Out):
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


class CheckV2Response(_Out):
    check_id: str
    decision: Decision
    block_code: str | None = Field(
        description="On block, the Factory v2 refusal it reproduces: EMAIL_INVALID_FORMAT, EMAIL_TYPO_SUSPECTED, "
                    "EMAIL_DOMAIN_UNDELIVERABLE, EMAIL_BANNED, EMAIL_ALIAS_EXISTS, IP_BLACKLISTED, POLICY_BLOCK")
    risk_score: int
    reasons: list[ReasonOut]
    hard_reasons: list[str]
    soft_reasons: list[str]
    weak_reasons: list[str]
    actions: list[Action]
    referral: ReferralOut | None
    suggestion: str | None = Field(description="EMAIL_TYPO_SUSPECTED: the domain the user probably meant")
    signals: SignalsOut
    mode: Literal["evaluate", "commit"]
    committed: bool
    account_id: str | None
    occurred_at: str
    ruleset: str
    engine_version: str


class EventResponse(_Out):
    account_id: str
    type: str
    applied: bool
    duplicate: bool
    event_id: int
    email_ban_created: bool | None = None


class BanV2Response(_Out):
    banned: bool
    created: bool | None = None
    removed: bool | None = None


class OverrideResponse(_Out):
    target: str
    kind: Literal["ip", "net24"]
    action: Literal["allow", "block"] | None = None
    removed: bool | None = None


class ImportResponse(_Out):
    received: int
    inserted: int
    updated: int


class LatencyOut(_Out):
    samples: int
    p50: float | None
    p95: float | None


class ReferralStatsOut(_Out):
    total: int
    suspicious: int


class StatsV2Response(_Out):
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


class AccountSignalsOut(_Out):
    email: bool
    fingerprint: bool
    ip: bool
    global_ip: bool
    name_key: bool
    purged_at: str | None


class ReferredByOut(_Out):
    referrer_account_id: str
    created_at: str
    suspicious: bool
    reason: str | None


class AccountResponse(_Out):
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


class HealthResponse(_Out):
    """GET /api/v1/health (any valid key)."""

    status: str = "ok"
    version: str


__all__ = [
    "ACCOUNT_ID_PATTERN", "EVENT_TYPES", "IMPORT_MAX_ROWS", "SHA256_PATTERN",
    "AccountImport", "AccountRef", "AccountResponse", "AccountSignalsOut", "AccountsImportRequest", "Action",
    "BanImport", "BanV2Request", "BanV2Response", "BansImportRequest", "CheckV2Request", "CheckV2Response",
    "CommitRequest", "Decision", "Device", "EventRequest", "EventResponse", "EventType", "HealthResponse",
    "IPReputationImport", "IPReputationImportRequest", "ImportResponse", "LatencyOut", "Name", "OverrideRequest",
    "OverrideResponse", "ReasonOut", "ReferralImport", "ReferralIn", "ReferralOut", "ReferralStatsOut",
    "ReferralsImportRequest", "ReferredByOut", "SignalsOut", "Signup", "StatsV2Response", "UnbanV2Request",
    "ip_reputation_key",
]
