"""FastAPI dependencies shared by the API routers."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request

from guardpost.engine import Guardpost
from guardpost.tenancy.models import TenantContext


def get_engine(request: Request) -> Guardpost:
    """The engine the app's lifespan created (``app.state.engine``)."""
    engine = getattr(request.app.state, "engine", None)
    if engine is None:
        raise HTTPException(status_code=503, detail="Guardpost not initialized")
    return engine


EngineDep = Annotated[Guardpost, Depends(get_engine)]


async def get_tenant_context(request: Request) -> TenantContext:
    """The tenant this request acts as.

    The auth middleware resolves the key once per request (it also needs the
    tenant for rate limiting) and leaves the result on ``request.state``.
    Without a valid key: open mode (GUARDPOST_ALLOW_OPEN=1 and no usable key
    at all) acts as the legacy tenant, anything else is a 401.
    """
    ctx: TenantContext | None = getattr(request.state, "tenant_context", None)
    if ctx is not None:
        if not ctx.tenant.active:
            raise HTTPException(status_code=403, detail=f"Tenant {ctx.tenant.id!r} is {ctx.tenant.status}")
        return ctx
    state = request.app.state
    authenticator = getattr(state, "authenticator", None)
    if state.allow_open and authenticator is not None and not await authenticator.has_usable_keys():
        return state.open_context
    raise HTTPException(status_code=401, detail="Invalid or missing API key")


def require_scope(scope: str, *, dashboard: bool = False, v1: bool = True):
    """Dependency: a TenantContext whose key holds ``scope``.

    On v1 routes ``legacy`` holds every scope; ``v1=False`` (the v2 routes)
    requires the scope itself.
    """

    async def dependency(request: Request) -> TenantContext:
        try:
            ctx = await get_tenant_context(request)
        except HTTPException as exc:
            if dashboard and exc.status_code == 401:
                raise HTTPException(
                    status_code=401,
                    detail="Authentication required",
                    headers={"WWW-Authenticate": 'Basic realm="Guardpost Dashboard"'},
                ) from exc
            raise
        if not ctx.allows(scope, v1=v1):
            raise HTTPException(status_code=403, detail=f"API key lacks scope {scope!r}")
        return ctx

    dependency.__name__ = f"require_{scope}" if v1 else f"require_v2_{scope}"
    return dependency


TenantDep = Annotated[TenantContext, Depends(get_tenant_context)]
CheckScope = Annotated[TenantContext, Depends(require_scope("check"))]
LifecycleScope = Annotated[TenantContext, Depends(require_scope("lifecycle"))]
DashboardScope = Annotated[TenantContext, Depends(require_scope("dashboard"))]
require_dashboard = require_scope("dashboard", dashboard=True)
