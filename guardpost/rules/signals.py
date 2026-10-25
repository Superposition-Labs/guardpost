"""The keyed signals the ledger rules compare (never a plaintext value)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SignalKeys:
    """Per-tenant HMACs of one signup's signals; None when the signal is absent.

    ``net_key`` is None for a non-global address (it then never matches,
    as in v2), while ``ip_key`` exists for any valid address.
    """

    email_key: str | None = None
    ip_key: str | None = None
    net_key: str | None = None
    fp_key: str | None = None
    name_key: str | None = None
