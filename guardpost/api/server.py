"""Compatibility entry point for the Guardpost API.

The implementation is split across ``guardpost.api.app`` (factory, state,
middleware), ``auth`` (credentials), ``deps`` (dependencies) and ``v1`` (the
v1 routes and models). This module keeps the 0.2 import paths working:

    uvicorn guardpost.api.server:create_app --factory
"""

from __future__ import annotations

from guardpost.api.app import TokenBucket, _TokenBucket, create_app
from guardpost.api.v1 import (
    AIBatchRequest,
    AIBatchResponse,
    AIScoreRequest,
    AIScoreResponse,
    BanRequest,
    BanResponse,
    CheckRequest,
    CheckResponse,
    EmailValidateRequest,
    EmailValidateResponse,
    HealthResponse,
    IPCheckRequest,
    IPCheckResponse,
    IPRecordRequest,
    PatternReportResponse,
    ProxyCheckRequest,
    ProxyCheckResponse,
    SMTPVerifyRequest,
    SMTPVerifyResponse,
    StatsResponse,
    TimelineBucket,
    TimelineResponse,
    UnbanRequest,
)

__all__ = [
    "AIBatchRequest", "AIBatchResponse", "AIScoreRequest", "AIScoreResponse", "BanRequest",
    "BanResponse", "CheckRequest", "CheckResponse", "EmailValidateRequest", "EmailValidateResponse",
    "HealthResponse", "IPCheckRequest", "IPCheckResponse", "IPRecordRequest", "PatternReportResponse",
    "ProxyCheckRequest", "ProxyCheckResponse", "SMTPVerifyRequest", "SMTPVerifyResponse",
    "StatsResponse", "TimelineBucket", "TimelineResponse", "TokenBucket", "UnbanRequest",
    "_TokenBucket", "create_app",
]
