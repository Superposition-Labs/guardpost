"""Per-tenant configuration (validated with pydantic, stored as JSON).

Every field has a default, so ``{}`` is a valid config and a tenant only
records what it overrides. Unknown keys are rejected, so a typo in
``guardpost tenant config-set`` fails loudly instead of being ignored.

The device, same-person and referral settings are read by the v2 check
(guardpost/rules); their defaults are Factory v2's windows and thresholds.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from guardpost.email.validator import ReasonTier, parse_domain_list


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegionRules(_Model):
    # Flag every *.ua address with the soft reason ``ua_domain``, even on a
    # trusted domain (Factory v2's RU rule). None: on when region == "ru".
    ua_domain: bool | None = None


class EmailConfig(_Model):
    # Replaces the instance default (GUARDPOST_TRUSTED_EXTRA_DOMAINS) for this
    # tenant when set — including to an empty list. None: use the default.
    trusted_extra_domains: list[str] | None = None
    # Per-reason-kind tier overrides on top of the built-in defaults.
    reason_tiers: dict[str, ReasonTier] = Field(default_factory=dict)

    @field_validator("trusted_extra_domains")
    @classmethod
    def _normalize_domains(cls, v: list[str] | None) -> list[str] | None:
        return None if v is None else sorted(parse_domain_list(v))


class DeviceRepeat(_Model):
    window_days: int = Field(default=7, ge=1, le=365)
    prior_threshold: int = Field(default=2, ge=1, le=1000)


class SamePerson(_Model):
    device_window_days: int = Field(default=7, ge=1, le=365)
    name_window_days: int = Field(default=30, ge=1, le=365)


class Referral(_Model):
    same_ip_limit: int = Field(default=3, ge=1, le=1000)
    velocity_24h: int = Field(default=3, ge=1, le=10000)
    velocity_7d: int = Field(default=10, ge=1, le=10000)


class Retention(_Model):
    # Per-tenant registration signals (hashed events; the device, IP, network
    # and name keys of v2 ledger accounts) are deleted after this.
    signals_days: int = Field(default=35, ge=1, le=400)
    # v2 lifecycle events (POST /api/v2/accounts/{id}/events) are kept this long.
    events_days: int = Field(default=400, ge=1, le=3650)


class TenantConfig(_Model):
    region: str | None = Field(default=None, pattern=r"^[a-z]{2,16}$")
    region_rules: RegionRules = Field(default_factory=RegionRules)
    email: EmailConfig = Field(default_factory=EmailConfig)
    device_repeat: DeviceRepeat = Field(default_factory=DeviceRepeat)
    same_person: SamePerson = Field(default_factory=SamePerson)
    referral: Referral = Field(default_factory=Referral)
    retention: Retention = Field(default_factory=Retention)
    # Requests per minute for all of this tenant's keys together.
    # None: the instance default (GUARDPOST_RATE_LIMIT); 0: unlimited.
    rate_limit_per_minute: int | None = Field(default=None, ge=0, le=1_000_000)

    @property
    def ua_domain_enabled(self) -> bool:
        if self.region_rules.ua_domain is not None:
            return self.region_rules.ua_domain
        return self.region == "ru"

    def to_json(self) -> str:
        """Only the fields that were set, so defaults can evolve."""
        return json.dumps(self.model_dump(mode="json", exclude_unset=True), sort_keys=True)

    @classmethod
    def from_json(cls, text: str | None) -> TenantConfig:
        return cls.model_validate(json.loads(text or "{}"))


def deep_merge(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    """RFC 7396-style merge: dicts merge recursively, ``None`` deletes a key."""
    out = dict(base)
    for key, value in patch.items():
        if value is None:
            out.pop(key, None)
        elif isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def parse_assignment(assignment: str) -> dict[str, Any]:
    """``"email.reason_tiers.typo_domain=hard"`` -> nested patch dict.

    The value is parsed as JSON when it is valid JSON (numbers, booleans,
    lists, ``null`` to unset), else taken as a string.
    """
    path, sep, raw = assignment.partition("=")
    if not sep or not path.strip():
        raise ValueError(f"expected key.path=value, got {assignment!r}")
    try:
        value: Any = json.loads(raw)
    except json.JSONDecodeError:
        value = raw
    patch: dict[str, Any] = {}
    node = patch
    parts = [p.strip() for p in path.split(".")]
    if any(not p for p in parts):
        raise ValueError(f"empty segment in {path!r}")
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value
    return patch


def apply_patch(config: TenantConfig, patch: dict[str, Any]) -> TenantConfig:
    """Merge ``patch`` into the stored (set-only) fields and re-validate."""
    current = config.model_dump(mode="json", exclude_unset=True)
    return TenantConfig.model_validate(deep_merge(current, patch))
