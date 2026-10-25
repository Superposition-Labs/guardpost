"""Device fingerprint and the device-repeat rule (Factory v2 ``device-repeat.ts``).

The third account from the same device fingerprint on the same /24 (the exact
address for IPv6) inside a week is degraded silently. The fingerprint alone
is useless (the most common one is shared by hundreds of strangers), so it is
always paired with the network, and a non-global address never matches.
"""

from __future__ import annotations

import hashlib
from typing import Protocol

from guardpost.rules.policy import Reason
from guardpost.rules.signals import SignalKeys

DEVICE_REPEAT_WINDOW_DAYS = 7
DEVICE_REPEAT_PRIOR_THRESHOLD = 2
DAY = 86_400.0


def registration_fingerprint(user_agent: str | None, accept_language: str | None) -> str | None:
    """SHA-256 of ``User-Agent|Accept-Language`` (hex); None without a User-Agent."""
    if not user_agent:
        return None
    return hashlib.sha256(f"{user_agent}|{accept_language or ''}".encode()).hexdigest()


class DeviceIndex(Protocol):
    def count_device(self, *, fp_key: str, net_key: str, since: float, until: float,
                     exclude: str | None) -> int: ...


def device_repeat_reason(
    index: DeviceIndex,
    keys: SignalKeys,
    now: float,
    *,
    window_days: int = DEVICE_REPEAT_WINDOW_DAYS,
    threshold: int = DEVICE_REPEAT_PRIOR_THRESHOLD,
    exclude: str | None = None,
) -> Reason | None:
    """``device_repeat:<prior>`` when this device already registered enough accounts."""
    if not keys.fp_key or not keys.net_key:  # no UA, or a non-global address
        return None
    prior = index.count_device(fp_key=keys.fp_key, net_key=keys.net_key,
                               since=now - window_days * DAY, until=now, exclude=exclude)
    if prior < threshold:
        return None
    return Reason("device_repeat", str(prior), evidence={"prior_accounts": prior})
