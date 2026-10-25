"""Tenant, API key and request-context records."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from guardpost.tenancy.config import TenantConfig

TENANT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
TENANT_STATUSES = ("active", "suspended")


def utcnow() -> datetime:
    return datetime.now(UTC)


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def format_ts(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat() if value else None


def validate_tenant_id(tenant_id: str) -> str:
    if not TENANT_ID_RE.match(tenant_id or ""):
        raise ValueError(
            f"invalid tenant id {tenant_id!r}: use 1-63 lowercase letters, digits, '-' or '_'")
    return tenant_id


@dataclass
class Tenant:
    id: str
    name: str
    status: str = "active"
    config: TenantConfig = field(default_factory=TenantConfig)
    key_version: int = 1
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)

    @property
    def active(self) -> bool:
        return self.status == "active"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status,
            "config": self.config.model_dump(mode="json", exclude_unset=True),
            "effective_config": self.config.model_dump(mode="json"),
            "key_version": self.key_version,
            "created_at": format_ts(self.created_at),
            "updated_at": format_ts(self.updated_at),
        }


@dataclass
class ApiKey:
    id: str
    tenant_id: str
    key_sha256: str
    scopes: frozenset[str]
    label: str | None = None
    created_at: datetime = field(default_factory=utcnow)
    last_used_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None

    def usable(self, now: datetime | None = None) -> bool:
        now = now or utcnow()
        if self.revoked_at is not None and self.revoked_at <= now:
            return False
        return self.expires_at is None or now < self.expires_at

    def state(self, now: datetime | None = None) -> str:
        now = now or utcnow()
        if self.revoked_at is not None and self.revoked_at <= now:
            return "revoked"
        if self.expires_at is not None and now >= self.expires_at:
            return "expired"
        return "active"

    def to_dict(self, now: datetime | None = None) -> dict:
        """Everything except the hash."""
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "scopes": sorted(self.scopes),
            "label": self.label,
            "state": self.state(now),
            "created_at": format_ts(self.created_at),
            "last_used_at": format_ts(self.last_used_at),
            "expires_at": format_ts(self.expires_at),
            "revoked_at": format_ts(self.revoked_at),
        }


@dataclass(frozen=True)
class TenantContext:
    """Who a request acts as: resolved from its API key by the auth layer."""

    tenant: Tenant
    scopes: frozenset[str]
    # None only in open mode (GUARDPOST_ALLOW_OPEN=1 with no keys at all).
    key_id: str | None

    def allows(self, scope: str, *, v1: bool = True) -> bool:
        """``legacy`` (the GUARDPOST_API_KEY scope) grants every v1 route."""
        return scope in self.scopes or (v1 and "legacy" in self.scopes)
