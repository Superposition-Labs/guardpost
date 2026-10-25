"""Reason tiers -> decision, block code and actions.

Every reason has a tier: ``hard`` blocks, ``soft`` degrades (Factory's
"suspicious": the account is created without bonuses), ``weak`` only feeds
the score. The decision is the highest tier present.

The v2 gates (format, typo, MX, ban, alias collision, blacklisted IP) are
hard by default and map 1:1 to Factory v2's HTTP 400s; a tenant may re-tier
any reason kind (``email.reason_tiers``), e.g. demote ``typo_domain`` to soft.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from guardpost.email.validator import DEFAULT_REASON_TIERS, ReasonTier

ALLOW = "allow"
DEGRADE = "degrade"
BLOCK = "block"

# Actions the integrating app takes on the new account.
NO_WELCOME_CREDITS = "no_welcome_credits"
NO_REFERRAL_ATTRIBUTION = "no_referral_attribution"
NO_REFERRAL_PAYOUTS = "no_referral_payouts"
RETRACT_REFERRAL_CODE = "retract_referral_code"
ACTIONS = (NO_WELCOME_CREDITS, NO_REFERRAL_ATTRIBUTION, NO_REFERRAL_PAYOUTS, RETRACT_REFERRAL_CODE)

# Gate reason kind -> (block code, Factory v2's 400 message). The block code
# names the v2 refusal the gate reproduces.
GATES: Mapping[str, tuple[str, str]] = MappingProxyType({
    "invalid_format": ("EMAIL_INVALID_FORMAT", "Invalid email format"),
    "typo_domain": ("EMAIL_TYPO_SUSPECTED", "This email domain looks like a typo"),
    "undeliverable_domain": ("EMAIL_DOMAIN_UNDELIVERABLE", "This email domain cannot receive mail"),
    "banned_email": ("EMAIL_BANNED", "Registration is not available for this email address"),
    "alias_collision": ("EMAIL_ALIAS_EXISTS", "An account with this email already exists"),
    "blacklisted_ip": ("IP_BLACKLISTED", "Registration is temporarily unavailable"),
})
# A hard reason that is not a gate (a tenant promoted it).
GENERIC_BLOCK_CODE = "POLICY_BLOCK"

V2_DEFAULT_TIERS: Mapping[str, ReasonTier] = MappingProxyType({
    **DEFAULT_REASON_TIERS,
    **{kind: ReasonTier.HARD for kind in GATES},
})

SAME_PERSON_KINDS = frozenset({"same_device", "same_name"})


@dataclass(frozen=True)
class Reason:
    """One reason, in Factory's ``kind:detail`` string form (:attr:`code`)."""

    kind: str
    detail: str | None = None
    # Opaque facts behind the reason: the tenant's own account ids, counts.
    # Never an email or an IP.
    evidence: Mapping | None = field(default=None, compare=False)

    @property
    def code(self) -> str:
        return self.kind if self.detail is None else f"{self.kind}:{self.detail}"


def tier_of(kind: str, overrides: Mapping[str, ReasonTier | str] | None = None) -> ReasonTier:
    if overrides and kind in overrides:
        return ReasonTier(overrides[kind])
    return V2_DEFAULT_TIERS.get(kind, ReasonTier.SOFT)


def is_suspicious(reasons: Iterable[Reason], overrides: Mapping[str, ReasonTier | str] | None = None) -> bool:
    """Factory's isSuspicious: any hard or soft reason so far."""
    return any(tier_of(r.kind, overrides) is not ReasonTier.WEAK for r in reasons)


def decide(reasons: Iterable[Reason], overrides: Mapping[str, ReasonTier | str] | None = None) -> str:
    tiers = {tier_of(r.kind, overrides) for r in reasons}
    if ReasonTier.HARD in tiers:
        return BLOCK
    if ReasonTier.SOFT in tiers:
        return DEGRADE
    return ALLOW


def block_code(reasons: Iterable[Reason], overrides: Mapping[str, ReasonTier | str] | None = None) -> str | None:
    for r in reasons:
        if tier_of(r.kind, overrides) is ReasonTier.HARD:
            return GATES.get(r.kind, (GENERIC_BLOCK_CODE, ""))[0]
    return None


def actions_for(decision: str, reasons: Iterable[Reason], *, returning_user: bool) -> list[str]:
    """What the app withholds from the new account, in ACTIONS order.

    degrade: no welcome credits, no referral attribution, no payouts (v2 sets
    custom_referral_bonus=0 and can_choose_referral_payout=false). A returning
    user gets neither welcome credits nor a referral. A same_device/same_name
    match retracts the new account's own referral code.
    """
    if decision == BLOCK:
        return []
    out: set[str] = set()
    if decision == DEGRADE:
        out |= {NO_WELCOME_CREDITS, NO_REFERRAL_ATTRIBUTION, NO_REFERRAL_PAYOUTS}
    if returning_user:
        out |= {NO_WELCOME_CREDITS, NO_REFERRAL_ATTRIBUTION}
    if any(r.kind in SAME_PERSON_KINDS for r in reasons):
        out.add(RETRACT_REFERRAL_CODE)
    return [a for a in ACTIONS if a in out]
