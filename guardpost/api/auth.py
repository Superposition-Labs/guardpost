"""Authentication: API keys -> TenantContext.

A request may present a key three ways, tried in this order:
``X-Api-Key: <key>``, ``Authorization: Bearer <key>``, and the password of
``Authorization: Basic`` (the browser dashboard; the username is ignored).

Two authenticators share one interface:

- :class:`StoreAuthenticator` (SQLite / memory): ``api_keys`` rows, any number
  of tenants. ``GUARDPOST_API_KEY`` is one of the rows (id ``legacy``).
- :class:`EnvAuthenticator` (Redis / other single-tenant backends): the one
  ``GUARDPOST_API_KEY``, acting as the legacy tenant.
"""

from __future__ import annotations

import base64
import logging
import time

from fastapi import Request

from guardpost.tenancy import keys
from guardpost.tenancy.crypto import constant_time_equals, sha256_hex
from guardpost.tenancy.models import Tenant, TenantContext

logger = logging.getLogger(__name__)


def extract_basic_auth_password(request: Request) -> str | None:
    """Password from an HTTP Basic ``Authorization`` header, if present."""
    scheme, _, rest = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "basic" or not rest:
        return None
    try:
        decoded = base64.b64decode(rest.strip()).decode("utf-8")
    except Exception:
        return None
    _, _, password = decoded.partition(":")
    return password or None


def extract_credentials(request: Request) -> list[str]:
    """Every key the request presents, in precedence order (may be empty)."""
    found: list[str] = []
    x_api_key = request.headers.get("X-Api-Key", "").strip()
    if x_api_key:
        found.append(x_api_key)
    scheme, _, rest = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() == "bearer" and rest.strip():
        found.append(rest.strip())
    basic = extract_basic_auth_password(request)
    if basic:
        found.append(basic)
    return found


class StoreAuthenticator:
    """Keys from the storage backend's ``api_keys`` table."""

    def __init__(self, storage, *, touch_interval: float = 60.0) -> None:
        self.storage = storage
        self.touch_interval = touch_interval
        self._touched: dict[str, float] = {}

    async def authenticate(self, presented: str) -> TenantContext | None:
        result = await keys.authenticate(self.storage, presented)
        if result is None:
            return None
        key, tenant = result
        await self._touch(key.id)
        return TenantContext(tenant=tenant, scopes=key.scopes, key_id=key.id)

    async def _touch(self, key_id: str) -> None:
        # last_used_at at most once a minute per key: not a write per request.
        now = time.monotonic()
        if now - self._touched.get(key_id, float("-inf")) < self.touch_interval:
            return
        self._touched[key_id] = now
        try:
            from guardpost.tenancy.models import utcnow

            await self.storage.touch_api_key(key_id, utcnow())
        except Exception:
            logger.debug("Could not record last_used_at for key %s", key_id, exc_info=True)

    async def has_usable_keys(self) -> bool:
        return await keys.has_usable_keys(self.storage)


class EnvAuthenticator:
    """The single GUARDPOST_API_KEY of a backend without tenancy."""

    def __init__(self, api_key: str | None, tenant: Tenant) -> None:
        self._digest = sha256_hex(api_key) if api_key else None
        self.tenant = tenant

    async def authenticate(self, presented: str) -> TenantContext | None:
        if self._digest is None or not constant_time_equals(sha256_hex(presented), self._digest):
            return None
        return TenantContext(tenant=self.tenant, scopes=keys.LEGACY_SCOPES, key_id=keys.LEGACY_KEY_ID)

    async def has_usable_keys(self) -> bool:
        return self._digest is not None
