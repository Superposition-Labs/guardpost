"""The same-person rule (Factory v2 ``same-person.ts`` findSamePersonReason).

The second account of one person is degraded when it has either:

- the exact IP and fingerprint of an account from the last 7 days
  (``same_device``; needs a fingerprint and a global address), or
- the same full name (:mod:`guardpost.rules.namekey`) as an account from the
  last 30 days, on the same /24 (exact address for IPv6) or with the same
  fingerprint (``same_name``). A name alone is never enough.

Factory names the earlier account by email; Guardpost names it by the
tenant's own opaque ``account_id`` (reason ``same_device:<account_id>``).
"""

from __future__ import annotations

from typing import Protocol

from guardpost.rules.policy import Reason
from guardpost.rules.signals import SignalKeys

SAME_DEVICE_WINDOW_DAYS = 7
SAME_NAME_WINDOW_DAYS = 30
DAY = 86_400.0


class SamePersonIndex(Protocol):
    def first_same_device(self, *, fp_key: str, ip_key: str, since: float, until: float,
                          exclude: str | None) -> str | None: ...

    def first_same_name(self, *, name_key: str, fp_key: str | None, net_key: str | None,
                        since: float, until: float, exclude: str | None) -> tuple[str, list[str]] | None: ...


def find_same_person_reason(
    index: SamePersonIndex,
    keys: SignalKeys,
    now: float,
    *,
    device_window_days: int = SAME_DEVICE_WINDOW_DAYS,
    name_window_days: int = SAME_NAME_WINDOW_DAYS,
    exclude: str | None = None,
) -> Reason | None:
    """The earliest matching account in the window, as a reason, else None."""
    if keys.fp_key and keys.net_key and keys.ip_key:
        prior = index.first_same_device(fp_key=keys.fp_key, ip_key=keys.ip_key,
                                        since=now - device_window_days * DAY, until=now, exclude=exclude)
        if prior is not None:
            return Reason("same_device", prior, evidence={"account_id": prior})

    if keys.name_key and (keys.net_key or keys.fp_key):
        match = index.first_same_name(name_key=keys.name_key, fp_key=keys.fp_key, net_key=keys.net_key,
                                      since=now - name_window_days * DAY, until=now, exclude=exclude)
        if match is not None:
            prior, matched = match
            return Reason("same_name", prior, evidence={"account_id": prior, "matched_on": matched})
    return None
