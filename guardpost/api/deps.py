"""FastAPI dependencies shared by the API routers."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request

from guardpost.engine import Guardpost


def get_engine(request: Request) -> Guardpost:
    """The engine the app's lifespan created (``app.state.engine``)."""
    engine = getattr(request.app.state, "engine", None)
    if engine is None:
        raise HTTPException(status_code=503, detail="Guardpost not initialized")
    return engine


EngineDep = Annotated[Guardpost, Depends(get_engine)]
