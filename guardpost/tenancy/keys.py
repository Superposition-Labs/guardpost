"""API keys: format, creation, authentication, rotation, the legacy key.

Format: ``gpk_<id>_<secret>``. ``id`` is 12 hex characters and names the row;
``secret`` is 32 random bytes, URL-safe base64. Only ``sha256(full key)`` is
stored, and comparisons are constant-time.

The legacy key is ``GUARDPOST_API_KEY`` verbatim (any format), stored under
key id ``legacy``. The environment is its source of truth: each boot re-hashes
it into ``api_keys``, and revokes the row when the variable is unset.
"""

from __future__ import annotations

import logging
import re
import secrets
from datetime import datetime, timedelta

from guardpost.tenancy.crypto import constant_time_equals, sha256_hex
from guardpost.tenancy.models import ApiKey, Tenant, utcnow

logger = logging.getLogger(__name__)

KEY_PREFIX = "gpk_"
LEGACY_KEY_ID = "legacy"
LEGACY_SCOPES = frozenset({"legacy", "check", "dashboard"})

# check     — evaluate emails and IPs (v1 /check, /email/*, /ip/check, /ip/proxy, /ai/*)
# lifecycle — change state: bans, /ip/record
# dashboard — read stats, timeline, pattern report; open the dashboard
# backfill  — bulk imports (v2)
# admin     — instance administration (v2)
# legacy    — every v1 route (the GUARDPOST_API_KEY key)
SCOPES = frozenset({"check", "lifecycle", "dashboard", "backfill", "admin", "legacy"})

_KEY_RE = re.compile(r"^gpk_([0-9a-f]{12})_([A-Za-z0-9_-]{20,})$")
_DURATION_RE = re.compile(r"^(\d+)\s*([smhdw])$")
_DURATION_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}

# Hash compared against when the key id is unknown, so a miss costs the same.
_DUMMY_HASH = sha256_hex("guardpost-no-such-key")


def parse_scopes(value: str | list[str] | tuple[str, ...] | frozenset[str]) -> frozenset[str]:
    items = value.split(",") if isinstance(value, str) else list(value)
    scopes = frozenset(s.strip() for s in items if s and s.strip())
    unknown = scopes - SCOPES
    if unknown:
        raise ValueError(f"unknown scope(s): {', '.join(sorted(unknown))} (valid: {', '.join(sorted(SCOPES))})")
    if not scopes:
        raise ValueError("at least one scope is required")
    return scopes


def parse_duration(value: str) -> timedelta:
    """``"90d"``, ``"12h"``, ``"2w"``, ``"30m"``, ``"0s"``."""
    match = _DURATION_RE.match(value.strip().lower())
    if not match:
        raise ValueError(f"invalid duration {value!r}: use e.g. 90d, 12h, 2w, 30m")
    return timedelta(**{_DURATION_UNITS[match.group(2)]: int(match.group(1))})


def split_key(presented: str) -> tuple[str, str] | None:
    """``(key_id, secret)`` for a well-formed ``gpk_`` key, else None."""
    match = _KEY_RE.match(presented)
    return (match.group(1), match.group(2)) if match else None


def new_key(
    tenant_id: str,
    scopes: frozenset[str],
    *,
    label: str | None = None,
    expires_at: datetime | None = None,
    now: datetime | None = None,
) -> tuple[str, ApiKey]:
    """Generate a key. Returns ``(plaintext, record)``; show the plaintext once."""
    key_id = secrets.token_hex(6)
    plaintext = f"{KEY_PREFIX}{key_id}_{secrets.token_urlsafe(32)}"
    record = ApiKey(
        id=key_id,
        tenant_id=tenant_id,
        key_sha256=sha256_hex(plaintext),
        scopes=frozenset(scopes),
        label=label,
        created_at=now or utcnow(),
        expires_at=expires_at,
    )
    return plaintext, record


async def create_key(
    store,
    tenant_id: str,
    scopes: str | frozenset[str],
    *,
    label: str | None = None,
    expires_in: timedelta | None = None,
    now: datetime | None = None,
) -> tuple[str, ApiKey]:
    now = now or utcnow()
    if await store.get_tenant(tenant_id) is None:
        raise LookupError(f"no such tenant: {tenant_id}")
    plaintext, record = new_key(
        tenant_id, parse_scopes(scopes), label=label,
        expires_at=now + expires_in if expires_in is not None else None, now=now,
    )
    while await store.get_api_key(record.id) is not None:  # 48-bit ids: practically never
        plaintext, record = new_key(tenant_id, record.scopes, label=label, expires_at=record.expires_at, now=now)
    await store.save_api_key(record)
    return plaintext, record


async def revoke_key(store, key_id: str, *, now: datetime | None = None) -> ApiKey:
    record = await store.get_api_key(key_id)
    if record is None:
        raise LookupError(f"no such key: {key_id}")
    if record.revoked_at is None:
        record.revoked_at = now or utcnow()
        await store.save_api_key(record)
    return record


async def rotate_key(
    store,
    key_id: str,
    *,
    grace: timedelta,
    now: datetime | None = None,
) -> tuple[str, ApiKey, ApiKey]:
    """Issue a replacement key; the old one expires after ``grace``.

    Returns ``(new_plaintext, new_record, old_record)``. The new key copies the
    old key's tenant, scopes, label and remaining lifetime policy (an old
    expiry is not carried over: the replacement is a fresh key).
    """
    now = now or utcnow()
    old = await store.get_api_key(key_id)
    if old is None:
        raise LookupError(f"no such key: {key_id}")
    if key_id == LEGACY_KEY_ID:
        raise ValueError("the legacy key is GUARDPOST_API_KEY: rotate it by changing the environment, "
                         "or create a gpk_ key for its tenant and retire the variable")
    if not old.usable(now):
        raise ValueError(f"key {key_id} is already {old.state(now)}")
    plaintext, new = await create_key(store, old.tenant_id, old.scopes, label=old.label, now=now)
    cutoff = now + grace
    if old.expires_at is None or cutoff < old.expires_at:
        old.expires_at = cutoff
    await store.save_api_key(old)
    return plaintext, new, old


async def authenticate(store, presented: str, *, now: datetime | None = None) -> tuple[ApiKey, Tenant] | None:
    """Resolve a presented key to its record and tenant, or None.

    None covers unknown, malformed, revoked and expired keys alike — callers
    answer 401 without saying which.
    """
    if not presented:
        return None
    now = now or utcnow()
    parts = split_key(presented)
    digest = sha256_hex(presented)
    record = await store.get_api_key(parts[0]) if parts else None
    if record is None or record.id == LEGACY_KEY_ID:
        # Not a gpk_ key we know: it can only be the legacy key.
        record = await store.get_api_key(LEGACY_KEY_ID)
    if record is None:
        constant_time_equals(digest, _DUMMY_HASH)
        return None
    if not constant_time_equals(digest, record.key_sha256) or not record.usable(now):
        return None
    tenant = await store.get_tenant(record.tenant_id)
    if tenant is None:
        return None
    return record, tenant


async def has_usable_keys(store, *, now: datetime | None = None) -> bool:
    now = now or utcnow()
    return any(k.usable(now) for k in await store.list_api_keys())


async def sync_legacy_key(store, env_key: str | None, tenant_id: str, *, now: datetime | None = None) -> None:
    """Make the ``legacy`` row match GUARDPOST_API_KEY (see module docstring)."""
    now = now or utcnow()
    existing = await store.get_api_key(LEGACY_KEY_ID)
    if not env_key:
        if existing is not None and existing.revoked_at is None:
            existing.revoked_at = now
            await store.save_api_key(existing)
            logger.warning("GUARDPOST_API_KEY is unset: the legacy key was revoked")
        return

    digest = sha256_hex(env_key)
    if existing is not None and existing.key_sha256 == digest and existing.tenant_id == tenant_id:
        if existing.revoked_at is not None:
            logger.warning("The legacy key (GUARDPOST_API_KEY) was revoked with the CLI and stays revoked; "
                           "set a new GUARDPOST_API_KEY or unset it")
            return
        if existing.scopes != LEGACY_SCOPES or existing.expires_at is not None:
            existing.scopes = LEGACY_SCOPES
            existing.expires_at = None
            await store.save_api_key(existing)
        return

    await store.save_api_key(ApiKey(
        id=LEGACY_KEY_ID,
        tenant_id=tenant_id,
        key_sha256=digest,
        scopes=LEGACY_SCOPES,
        label="GUARDPOST_API_KEY",
        created_at=now,
    ))
    logger.info("Legacy key (GUARDPOST_API_KEY) mapped to tenant %r", tenant_id)
