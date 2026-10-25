"""Referral fraud flags at signup (Factory v2 ``referrals/signup.ts`` createReferralTx).

A referral is only tracked for a new, clean, non-returning signup. The
referral row is then flagged suspicious (the referee gets no referral bonus)
when either:

- this IP already produced ``same_ip_limit`` (3) referrals in 24 h, any
  referrer, flagged or not: ``same_ip_<n+1>_in_24h``; or
- the referrer already has ``velocity_24h`` (3) unflagged referrals in 24 h
  (``referrer_velocity_24h (N referrals in 24h)``) or ``velocity_7d`` (10) in
  7 days (``referrer_velocity_7d (N referrals in 7d)``).

A self-referral, or a referrer whose code was retracted, is not attributed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

SAME_IP_LIMIT = 3
MAX_REFERRALS_PER_DAY = 3
MAX_REFERRALS_PER_WEEK = 10
DAY = 86_400.0


class ReferralIndex(Protocol):
    def count_referrals_from_ip(self, *, ip_key: str, since: float, until: float) -> int: ...

    def count_referrer_referrals(self, *, referrer_account_id: str, since: float, until: float) -> int:
        """Unflagged referrals of this referrer in the window."""
        ...

    def referrer_code_retracted(self, referrer_account_id: str) -> bool: ...


@dataclass(frozen=True)
class ReferralVerdict:
    attribute: bool
    suspicious: bool = False
    reason: str | None = None

    def to_dict(self) -> dict:
        return {"attribute": self.attribute, "suspicious": self.suspicious, "reason": self.reason}


def evaluate_referral(
    index: ReferralIndex,
    *,
    referrer_account_id: str,
    referred_account_id: str | None,
    ip_key: str | None,
    now: float,
    same_ip_limit: int = SAME_IP_LIMIT,
    velocity_24h: int = MAX_REFERRALS_PER_DAY,
    velocity_7d: int = MAX_REFERRALS_PER_WEEK,
) -> ReferralVerdict:
    """The referral verdict for a signup that is eligible for one."""
    if referred_account_id is not None and referrer_account_id == referred_account_id:
        return ReferralVerdict(False, reason="self_referral")
    if index.referrer_code_retracted(referrer_account_id):
        return ReferralVerdict(False, reason="referrer_code_retracted")

    reason = None
    if ip_key:
        same_ip = index.count_referrals_from_ip(ip_key=ip_key, since=now - DAY, until=now)
        if same_ip >= same_ip_limit:
            reason = f"same_ip_{same_ip + 1}_in_24h"
    if reason is None:
        day = index.count_referrer_referrals(referrer_account_id=referrer_account_id, since=now - DAY, until=now)
        if day >= velocity_24h:
            reason = f"referrer_velocity_24h ({day} referrals in 24h)"
        else:
            week = index.count_referrer_referrals(referrer_account_id=referrer_account_id,
                                                  since=now - 7 * DAY, until=now)
            if week >= velocity_7d:
                reason = f"referrer_velocity_7d ({week} referrals in 7d)"
    return ReferralVerdict(True, suspicious=reason is not None, reason=reason)
