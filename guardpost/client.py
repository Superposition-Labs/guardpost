"""Guardpost Python client: :class:`GuardpostClient` (sync) and :class:`AsyncGuardpostClient`.

Install::

    pip install "guardpost-server[client]"     # httpx + pydantic

Both clients have the same methods and return the typed models of
:mod:`guardpost.models`, the ones the server validates and renders with::

    from guardpost.client import GuardpostClient

    with GuardpostClient("http://guardpost:8000", api_key="gpk_...") as gp:
        result = gp.check_v2(
            mode="commit",
            email="person@example.com",
            ip="203.0.113.7",
            device={"user_agent": ua, "accept_language": lang},
            account={"id": "u_123"},
            idempotency_key="signup:u_123",
        )
        result.decision            # "allow" | "degrade" | "block"
        result.actions             # ["no_welcome_credits", ...]

    async with AsyncGuardpostClient("http://guardpost:8000", api_key="gpk_...") as gp:
        result = await gp.check_v2(email="person@example.com", ip="203.0.113.7")

Behaviour shared by both clients:

- **Auth**: ``Authorization: Bearer <api_key>``.
- **Timeouts**: ``timeout`` (seconds) bounds each attempt; ``total_timeout``
  optionally bounds the whole call, retries and back-off included. A call in
  a signup's request path should set both (see docs/INTEGRATION.md).
- **Retries**: on 5xx, timeouts and connection errors only, never on a 4xx
  (429 included), with jittered exponential back-off. Every v2 write is safe
  to repeat; send an idempotency key with a commit-mode check so a repeat
  replays the first result instead of answering 409 ``account_exists``.
- **Errors**: every failure is a :class:`GuardpostError` (``status_code``,
  ``code``, ``retryable``); a request that fails validation before it is sent
  is a :class:`GuardpostRequestError`. ``str(error)`` never echoes request
  values, so it is safe to log.
- **Fail open**: ``gp.fail_open(default).check_v2(...)`` returns ``default``
  instead of raising any :class:`GuardpostError`.

The 0.2 dict methods (``check``, ``validate_email``, ``ban_email``, ...) still
work and emit a DeprecationWarning; ``async with GuardpostClient(...)`` (the 0.2
async usage) still works and yields an :class:`AsyncGuardpostClient`.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
import warnings
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ValidationError

from guardpost import __version__
from guardpost.models import (
    IMPORT_MAX_ROWS,
    AccountImport,
    AccountResponse,
    BanImport,
    BanV2Request,
    BanV2Response,
    CheckV2Request,
    CheckV2Response,
    CommitRequest,
    EventRequest,
    EventResponse,
    HealthResponse,
    ImportResponse,
    IPReputationImport,
    OverrideRequest,
    OverrideResponse,
    ReferralImport,
    StatsV2Response,
    UnbanV2Request,
)

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5.0
DEFAULT_RETRIES = 2
DEFAULT_BACKOFF = 0.2
DEFAULT_MAX_BACKOFF = 2.0

M = TypeVar("M", bound=BaseModel)
T = TypeVar("T")
D = TypeVar("D")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


def _summarize(detail: Any) -> str:
    """A loggable message for an error ``detail``: never the request's values.

    FastAPI's 422 detail echoes each invalid ``input`` (an email, an IP), so
    validation errors are reduced to their location and message.
    """
    if isinstance(detail, str):
        return detail
    if isinstance(detail, Mapping):
        return str(detail.get("message") or detail.get("code") or "error")
    if isinstance(detail, list):
        parts = []
        for item in detail[:5]:
            if isinstance(item, Mapping):
                loc = ".".join(str(p) for p in item.get("loc", ()) if p != "body")
                parts.append(f"{loc}: {item.get('msg', 'invalid')}" if loc else str(item.get("msg", "invalid")))
        return "validation error: " + "; ".join(parts) if parts else "validation error"
    return "error"


class GuardpostError(Exception):
    """A failed Guardpost call.

    Attributes:
        status_code: the HTTP status, or None when no response arrived
            (timeout, connection error) or the request was never sent.
        detail: the response's ``detail`` as sent (str, dict or list). For a
            422 it may contain request values: do not log it.
        code: the machine-readable v2 error code (``account_exists``,
            ``check_expired``, ``timeout``, ...), when there is one.
        message: a loggable message (no request values).
        retryable: whether the client retries this failure (5xx, timeout,
            connection error).
    """

    def __init__(
        self,
        status_code: int | None,
        detail: Any,
        *,
        code: str | None = None,
        message: str | None = None,
        retryable: bool | None = None,
    ) -> None:
        self.status_code = status_code
        self.detail = detail
        if code is None and isinstance(detail, Mapping):
            code = detail.get("code")
        self.code = code
        self.message = message if message is not None else _summarize(detail)
        self.retryable = (status_code is None or status_code >= 500) if retryable is None else retryable
        prefix = f"HTTP {status_code}" if status_code is not None else (code or "error")
        super().__init__(f"{prefix}: {self.message}")


class GuardpostTimeoutError(GuardpostError):
    """No response within the timeout (``code == "timeout"``)."""

    def __init__(self, message: str = "request timed out") -> None:
        super().__init__(None, message, code="timeout", retryable=True)


class GuardpostConnectionError(GuardpostError):
    """The request could not be sent or the connection broke (``code == "connection_error"``)."""

    def __init__(self, message: str, *, retryable: bool = True) -> None:
        super().__init__(None, message, code="connection_error", retryable=retryable)


class GuardpostRequestError(GuardpostError):
    """The request failed client-side validation and was not sent (``code == "invalid_request"``)."""

    def __init__(self, exc: ValidationError) -> None:
        errors = [{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors(include_input=False, include_url=False)]
        super().__init__(None, errors, code="invalid_request", retryable=False)


class GuardpostResponseError(GuardpostError):
    """A 2xx response that is not what the API promises (``code == "invalid_response"``).

    Usually a server newer than this client (an enum value it does not know):
    upgrade the client with the server.
    """

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(status_code, message, code="invalid_response", retryable=False)


# ---------------------------------------------------------------------------
# Calls
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RetryPolicy:
    """Retries for 5xx, timeouts and connection errors: jittered exponential back-off."""

    retries: int = DEFAULT_RETRIES
    backoff: float = DEFAULT_BACKOFF
    max_backoff: float = DEFAULT_MAX_BACKOFF

    def delay(self, attempt: int) -> float:
        """Seconds to wait before retry number ``attempt + 1`` (0-based): half to all of the capped step."""
        cap = min(self.max_backoff, self.backoff * (2 ** attempt))
        return random.uniform(cap / 2, cap) if cap > 0 else 0.0


@dataclass
class _Call(Generic[M]):
    method: str
    path: str
    model: type[M] | None  # None: the 0.2 dict methods
    json: Any = None
    params: dict[str, Any] | None = None
    headers: dict[str, str] = field(default_factory=dict)


def _validate(model: type[M], data: Any) -> M:
    if isinstance(data, model):
        return data
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise GuardpostRequestError(exc) from None


def _dump(body: BaseModel) -> dict[str, Any]:
    return body.model_dump(mode="json", exclude_none=True)


def _check_call(request: CheckV2Request | Mapping[str, Any] | None, idempotency_key: str | None,
                fields: dict[str, Any]) -> _Call[CheckV2Response]:
    if request is not None and fields:
        raise TypeError("check_v2() takes a request or keyword fields, not both")
    body = _validate(CheckV2Request, request if request is not None else fields)
    if idempotency_key and body.idempotency_key and idempotency_key != body.idempotency_key:
        raise ValueError("idempotency_key and the request's idempotency_key differ")
    key = idempotency_key or body.idempotency_key
    return _Call("POST", "/api/v2/check", CheckV2Response, json=_dump(body),
                 headers={"Idempotency-Key": key} if key else {})


def _commit_call(check_id: str, account_id: str) -> _Call[CheckV2Response]:
    body = _validate(CommitRequest, {"check_id": check_id, "account_id": account_id})
    return _Call("POST", "/api/v2/accounts", CheckV2Response, json=_dump(body))


def _event_call(account_id: str, event_type: str, fields: dict[str, Any]) -> _Call[EventResponse]:
    body = _validate(EventRequest, {"type": event_type, **fields})
    return _Call("POST", f"/api/v2/accounts/{_segment(account_id)}/events", EventResponse, json=_dump(body))


def _ban_call(email: str | None, email_sha256: str | None, reason: str | None,
              banned_by: str | None) -> _Call[BanV2Response]:
    body = _validate(BanV2Request, {"email": email, "email_sha256": email_sha256, "reason": reason,
                                    "banned_by": banned_by})
    return _Call("PUT", "/api/v2/bans", BanV2Response, json=_dump(body))


def _unban_call(email: str | None, email_sha256: str | None) -> _Call[BanV2Response]:
    body = _validate(UnbanV2Request, {"email": email, "email_sha256": email_sha256})
    return _Call("DELETE", "/api/v2/bans", BanV2Response, json=_dump(body))


def _override_call(target: str, action: Literal["allow", "block"] | None, reason: str | None,
                   created_by: str | None) -> _Call[OverrideResponse]:
    target = target.strip()
    if not target or "?" in target or "#" in target:
        raise ValueError("invalid override target: use an address or an IPv4 /24")
    path = f"/api/v2/ip-overrides/{target}"
    if action is None:
        return _Call("DELETE", path, OverrideResponse)
    body = _validate(OverrideRequest, {"action": action, "reason": reason, "created_by": created_by})
    return _Call("PUT", path, OverrideResponse, json=_dump(body))


def _import_calls(path: str, row_model: type[BaseModel], rows: Iterable[Any],
                  chunk_size: int) -> list[_Call[ImportResponse]]:
    if not 1 <= chunk_size <= IMPORT_MAX_ROWS:
        raise ValueError(f"chunk_size must be 1..{IMPORT_MAX_ROWS}")
    validated = [_dump(_validate(row_model, r)) for r in rows]
    return [_Call("POST", path, ImportResponse, json={"rows": validated[i:i + chunk_size]})
            for i in range(0, len(validated), chunk_size)]


def _sum_imports(results: list[ImportResponse]) -> ImportResponse:
    return ImportResponse(received=sum(r.received for r in results), inserted=sum(r.inserted for r in results),
                          updated=sum(r.updated for r in results))


def _segment(value: str) -> str:
    # Account ids match ^[A-Za-z0-9._:-]+$ (the server re-checks): nothing to escape.
    if not value or "/" in value or "?" in value or "#" in value:
        raise ValueError("invalid account id")
    return value


def _legacy_check(email: str, ip_address: str | None, record_ip: bool, smtp_verify: bool, check_proxy: bool,
                  ai_score: bool) -> _Call[Any]:
    payload: dict[str, Any] = {"email": email, "record_ip": record_ip, "smtp_verify": smtp_verify,
                               "check_proxy": check_proxy, "ai_score": ai_score}
    if ip_address:
        payload["ip_address"] = ip_address
    return _Call("POST", "/api/v1/check", None, json=payload)


def _legacy_ban(email: str, banned_by: str | None, reason: str | None) -> _Call[Any]:
    payload: dict[str, Any] = {"email": email}
    if banned_by:
        payload["banned_by"] = banned_by
    if reason:
        payload["reason"] = reason
    return _Call("POST", "/api/v1/email/ban", None, json=payload)


# The 0.2 dict methods: name -> (call builder, the replacement to suggest).
_LEGACY: dict[str, tuple[Callable[..., _Call[Any]], str]] = {
    "check": (_legacy_check, "check_v2()"),
    "validate_email": (lambda email: _Call("POST", "/api/v1/email/validate", None, json={"email": email}),
                       "check_v2(mode='evaluate')"),
    "check_ip": (lambda ip: _Call("POST", "/api/v1/ip/check", None, json={"ip_address": ip}),
                 "check_v2(mode='evaluate')"),
    "record_ip": (lambda ip, suspicious=False: _Call("POST", "/api/v1/ip/record", None,
                                                     json={"ip_address": ip, "is_suspicious": suspicious}),
                  "check_v2(mode='commit')"),
    "check_proxy": (lambda ip: _Call("POST", "/api/v1/ip/proxy", None, json={"ip_address": ip}),
                    "the /api/v1/ip/proxy route"),
    "smtp_verify": (lambda email: _Call("POST", "/api/v1/email/smtp", None, json={"email": email}),
                    "the /api/v1/email/smtp route"),
    "ban_email": (_legacy_ban, "ban()"),
    "unban_email": (lambda email: _Call("DELETE", "/api/v1/email/ban", None, json={"email": email}), "unban()"),
    "ai_score": (lambda email: _Call("POST", "/api/v1/ai/score", None, json={"email": email}),
                 "the /api/v1/ai/score route"),
    "ai_score_batch": (lambda emails: _Call("POST", "/api/v1/ai/score/batch", None, json={"emails": emails}),
                       "the /api/v1/ai/score/batch route"),
    "pattern_report": (lambda: _Call("GET", "/api/v1/patterns/report", None), "stats()"),
}


def _legacy(name: str, *args: Any) -> _Call[Any]:
    build, replacement = _LEGACY[name]
    warnings.warn(f"{name}() is the 0.2 dict API and will be removed; use {replacement}",
                  DeprecationWarning, stacklevel=3)
    return build(*args)


def _is_httpx_error(exc: Exception) -> bool:
    import httpx

    return isinstance(exc, httpx.RequestError)


class _Base:
    """Configuration and response handling shared by both clients."""

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        total_timeout: float | None = None,
        retries: int = DEFAULT_RETRIES,
        backoff: float = DEFAULT_BACKOFF,
        max_backoff: float = DEFAULT_MAX_BACKOFF,
        headers: Mapping[str, str] | None = None,
        transport: Any = None,
        http_client: Any = None,
    ) -> None:
        if retries < 0 or timeout <= 0 or (total_timeout is not None and total_timeout <= 0):
            raise ValueError("retries must be >= 0 and timeouts > 0")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.total_timeout = total_timeout
        self.retry = RetryPolicy(retries=retries, backoff=backoff, max_backoff=max_backoff)
        self._extra_headers = dict(headers or {})
        self._transport = transport
        self._client = http_client
        self._owns_client = http_client is None

    @property
    def retries(self) -> int:
        return self.retry.retries

    def _config(self) -> dict[str, Any]:
        return {"api_key": self.api_key, "timeout": self.timeout, "total_timeout": self.total_timeout,
                "retries": self.retry.retries, "backoff": self.retry.backoff,
                "max_backoff": self.retry.max_backoff, "headers": self._extra_headers}

    def _headers(self, call: _Call) -> dict[str, str]:
        headers = {"User-Agent": f"guardpost-python/{__version__}", "Accept": "application/json",
                   **self._extra_headers, **call.headers}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    @staticmethod
    def _error(resp) -> GuardpostError:
        try:
            detail = resp.json().get("detail", resp.text)
        except Exception:
            detail = resp.text or resp.reason_phrase
        return GuardpostError(resp.status_code, detail)

    @staticmethod
    def _parse(call: _Call, resp) -> Any:
        try:
            data = resp.json()
        except Exception:
            raise GuardpostResponseError(resp.status_code, "response is not JSON") from None
        if call.model is None:
            return data
        try:
            return call.model.model_validate(data)
        except ValidationError as exc:
            fields = ", ".join(".".join(map(str, e["loc"])) for e in exc.errors()[:5])
            raise GuardpostResponseError(
                resp.status_code, f"unexpected {call.model.__name__} ({fields}): is the server newer than "
                                  "the client?") from None

    @staticmethod
    def _transport_error(exc: Exception) -> GuardpostError:
        import httpx

        if isinstance(exc, httpx.TimeoutException):
            return GuardpostTimeoutError(f"request timed out ({type(exc).__name__})")
        if isinstance(exc, httpx.TransportError):
            return GuardpostConnectionError(f"{type(exc).__name__}: {exc}")
        return GuardpostConnectionError(f"{type(exc).__name__}: {exc}", retryable=False)

    def _budget(self, deadline: float | None) -> float | None:
        """This attempt's timeout, or None when the total budget is spent."""
        if deadline is None:
            return self.timeout
        remaining = deadline - time.monotonic()
        return min(self.timeout, remaining) if remaining > 0.001 else None

    def _backoff(self, err: GuardpostError, attempt: int, deadline: float | None) -> float | None:
        """The pause before the next attempt, or None to give up and raise ``err``."""
        if not err.retryable or attempt >= self.retry.retries:
            return None
        delay = self.retry.delay(attempt)
        if deadline is not None and time.monotonic() + delay >= deadline:
            return None
        return delay


# ---------------------------------------------------------------------------
# Fail open
# ---------------------------------------------------------------------------


def _report(name: str, exc: GuardpostError, on_error: Callable[[GuardpostError], Any] | None) -> None:
    logger.warning("guardpost %s failed open (%s)", name, exc)
    if on_error is not None:
        try:
            on_error(exc)
        except Exception:
            logger.exception("guardpost fail_open on_error callback raised")


def fail_open(call: Callable[[], T], default: D, *,
              on_error: Callable[[GuardpostError], Any] | None = None) -> T | D:
    """``call()``, or ``default`` when it raises a :class:`GuardpostError`."""
    try:
        return call()
    except GuardpostError as exc:
        _report(getattr(call, "__name__", "call"), exc, on_error)
        return default


async def afail_open(call: Awaitable[T] | Callable[[], Awaitable[T]], default: D, *,
                     on_error: Callable[[GuardpostError], Any] | None = None) -> T | D:
    """``await call`` (or ``await call()``), or ``default`` when it raises a :class:`GuardpostError`."""
    try:
        return await (call() if callable(call) else call)
    except GuardpostError as exc:
        _report(getattr(call, "__name__", "call"), exc, on_error)
        return default


class FailOpen(Generic[D]):
    """``client.fail_open(default)``: the client's methods, returning ``default`` on any GuardpostError."""

    def __init__(self, client: GuardpostClient, default: D,
                 on_error: Callable[[GuardpostError], Any] | None = None) -> None:
        self._client = client
        self._default = default
        self._on_error = on_error

    def __getattr__(self, name: str) -> Any:
        method = getattr(self._client, name)
        if not callable(method):
            return method

        def call(*args: Any, **kwargs: Any) -> Any:
            try:
                return method(*args, **kwargs)
            except GuardpostError as exc:
                _report(name, exc, self._on_error)
                return self._default

        return call


class AsyncFailOpen(Generic[D]):
    """``async_client.fail_open(default)``: awaitable methods returning ``default`` on any GuardpostError."""

    def __init__(self, client: AsyncGuardpostClient, default: D,
                 on_error: Callable[[GuardpostError], Any] | None = None) -> None:
        self._client = client
        self._default = default
        self._on_error = on_error

    def __getattr__(self, name: str) -> Any:
        method = getattr(self._client, name)
        if not callable(method):
            return method

        async def call(*args: Any, **kwargs: Any) -> Any:
            try:
                return await method(*args, **kwargs)
            except GuardpostError as exc:
                _report(name, exc, self._on_error)
                return self._default

        return call


# ---------------------------------------------------------------------------
# Sync client
# ---------------------------------------------------------------------------


class GuardpostClient(_Base):
    """Synchronous client.

    Args:
        base_url: e.g. ``http://guardpost:8000``.
        api_key: a ``gpk_...`` key (or the legacy GUARDPOST_API_KEY for v1 routes).
        timeout: seconds per attempt (default 5).
        total_timeout: seconds for the whole call including retries (default: none).
        retries: retries after the first attempt (default 2); 0 disables them.
        backoff, max_backoff: back-off base and cap in seconds.
        headers: extra headers on every request.
        transport: an ``httpx.BaseTransport`` (tests: ``httpx.MockTransport``).
        http_client: an ``httpx.Client`` to use instead (not closed by this client).
    """

    def __init__(self, base_url: str, **kwargs: Any) -> None:
        super().__init__(base_url, **kwargs)
        self._sleep: Callable[[float], None] = time.sleep
        self._async: AsyncGuardpostClient | None = None

    # --- lifecycle -------------------------------------------------------

    def _http(self):
        if self._client is None:
            import httpx

            self._client = httpx.Client(transport=self._transport, timeout=self.timeout)
        return self._client

    def close(self) -> None:
        if self._client is not None and self._owns_client:
            self._client.close()
            self._client = None

    def __enter__(self) -> GuardpostClient:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        self.close()

    async def __aenter__(self) -> AsyncGuardpostClient:
        """0.2 compatibility: ``async with GuardpostClient(...)`` yields an AsyncGuardpostClient."""
        warnings.warn("GuardpostClient is synchronous since 0.4: use AsyncGuardpostClient in async code",
                      DeprecationWarning, stacklevel=2)
        import httpx

        transport = self._transport if isinstance(self._transport, httpx.AsyncBaseTransport) else None
        self._async = AsyncGuardpostClient(self.base_url, transport=transport, **self._config())
        return self._async

    async def __aexit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                        tb: TracebackType | None) -> None:
        if self._async is not None:
            await self._async.aclose()
            self._async = None

    def fail_open(self, default: D, *, on_error: Callable[[GuardpostError], Any] | None = None) -> FailOpen[D]:
        """This client's methods, returning ``default`` instead of raising a GuardpostError.

        ``gp.fail_open(None).check_v2(...)`` is a CheckV2Response, or None when
        Guardpost timed out, was unreachable, or answered with an error.
        """
        return FailOpen(self, default, on_error)

    # --- transport -------------------------------------------------------

    def _send(self, call: _Call[Any]) -> Any:
        deadline = None if self.total_timeout is None else time.monotonic() + self.total_timeout
        attempt = 0
        while True:
            timeout = self._budget(deadline)
            if timeout is None:
                raise GuardpostTimeoutError("total_timeout exceeded")
            try:
                resp = self._http().request(call.method, self.base_url + call.path, json=call.json,
                                            params=call.params, headers=self._headers(call), timeout=timeout)
            except Exception as exc:
                if not _is_httpx_error(exc):
                    raise
                err = self._transport_error(exc)
            else:
                if resp.status_code < 400:
                    return self._parse(call, resp)
                err = self._error(resp)
            delay = self._backoff(err, attempt, deadline)
            if delay is None:
                raise err
            self._sleep(delay)
            attempt += 1

    # --- v2 --------------------------------------------------------------

    def check_v2(self, request: CheckV2Request | Mapping[str, Any] | None = None, /, *,
                 idempotency_key: str | None = None, **fields: Any) -> CheckV2Response:
        """POST /api/v2/check: ``mode="evaluate"`` (default) or ``"commit"`` (needs ``account={"id": ...}``).

        Pass a :class:`~guardpost.models.CheckV2Request` (or a dict), or its
        fields as keywords. ``idempotency_key`` is sent as Idempotency-Key.
        """
        return self._send(_check_call(request, idempotency_key, fields))

    def commit(self, check_id: str, account_id: str) -> CheckV2Response:
        """POST /api/v2/accounts: commit an evaluated check (within 1 hour)."""
        return self._send(_commit_call(check_id, account_id))

    def event(self, account_id: str, type: str, /, **fields: Any) -> EventResponse:
        """POST /api/v2/accounts/{id}/events: ``created``, ``deleted``, ``banned``, ``paid``, ...

        Fields: occurred_at, idempotency_key, email / email_sha256,
        permanent_email_ban, reason, actor.
        """
        return self._send(_event_call(account_id, type, fields))

    def ban(self, email: str | None = None, /, *, email_sha256: str | None = None, reason: str | None = None,
            banned_by: str | None = None) -> BanV2Response:
        """PUT /api/v2/bans: ban an address (or its normalized sha256) for this tenant."""
        return self._send(_ban_call(email, email_sha256, reason, banned_by))

    def unban(self, email: str | None = None, /, *, email_sha256: str | None = None) -> BanV2Response:
        """DELETE /api/v2/bans."""
        return self._send(_unban_call(email, email_sha256))

    def ip_override(self, target: str, action: Literal["allow", "block"] | None, *, reason: str | None = None,
                    created_by: str | None = None) -> OverrideResponse:
        """PUT /api/v2/ip-overrides/{ip_or_cidr}; ``action=None`` removes the override (DELETE)."""
        return self._send(_override_call(target, action, reason, created_by))

    def import_accounts(self, rows: Iterable[AccountImport | Mapping[str, Any]], *,
                        chunk_size: int = IMPORT_MAX_ROWS) -> ImportResponse:
        """POST /api/v2/import/accounts in chunks of ``chunk_size``; the counts are summed."""
        return self._import("/api/v2/import/accounts", AccountImport, rows, chunk_size)

    def import_bans(self, rows: Iterable[BanImport | Mapping[str, Any]], *,
                    chunk_size: int = IMPORT_MAX_ROWS) -> ImportResponse:
        """POST /api/v2/import/bans in chunks."""
        return self._import("/api/v2/import/bans", BanImport, rows, chunk_size)

    def import_referrals(self, rows: Iterable[ReferralImport | Mapping[str, Any]], *,
                         chunk_size: int = IMPORT_MAX_ROWS) -> ImportResponse:
        """POST /api/v2/import/referrals in chunks."""
        return self._import("/api/v2/import/referrals", ReferralImport, rows, chunk_size)

    def import_ip_reputation(self, rows: Iterable[IPReputationImport | Mapping[str, Any]], *,
                             chunk_size: int = IMPORT_MAX_ROWS) -> ImportResponse:
        """POST /api/v2/admin/ip-reputation/import (admin scope; the shared table) in chunks."""
        return self._import("/api/v2/admin/ip-reputation/import", IPReputationImport, rows, chunk_size)

    def _import(self, path: str, model: type[BaseModel], rows: Iterable[Any], chunk_size: int) -> ImportResponse:
        return _sum_imports([self._send(c) for c in _import_calls(path, model, rows, chunk_size)])

    def account(self, account_id: str) -> AccountResponse:
        """GET /api/v2/accounts/{id} (dashboard scope)."""
        return self._send(_Call("GET", f"/api/v2/accounts/{_segment(account_id)}", AccountResponse))

    def stats(self, days: int = 30) -> StatsV2Response:
        """GET /api/v2/stats (dashboard scope)."""
        return self._send(_Call("GET", "/api/v2/stats", StatsV2Response, params={"days": days}))

    def health(self) -> HealthResponse:
        """GET /api/v1/health (any valid key): status and server version."""
        return self._send(_Call("GET", "/api/v1/health", HealthResponse))

    # --- 0.2 dict API (deprecated) ----------------------------------------

    def check(self, email: str, *, ip_address: str | None = None, record_ip: bool = True,
              smtp_verify: bool = False, check_proxy: bool = False, ai_score: bool = False) -> dict[str, Any]:
        """Deprecated: POST /api/v1/check as a dict. Use :meth:`check_v2`."""
        return self._send(_legacy("check", email, ip_address, record_ip, smtp_verify, check_proxy, ai_score))

    def validate_email(self, email: str) -> dict[str, Any]:
        """Deprecated: POST /api/v1/email/validate."""
        return self._send(_legacy("validate_email", email))

    def check_ip(self, ip_address: str) -> dict[str, Any]:
        """Deprecated: POST /api/v1/ip/check."""
        return self._send(_legacy("check_ip", ip_address))

    def record_ip(self, ip_address: str, is_suspicious: bool = False) -> dict[str, Any]:
        """Deprecated: POST /api/v1/ip/record."""
        return self._send(_legacy("record_ip", ip_address, is_suspicious))

    def check_proxy(self, ip_address: str) -> dict[str, Any]:
        """Deprecated: POST /api/v1/ip/proxy."""
        return self._send(_legacy("check_proxy", ip_address))

    def smtp_verify(self, email: str) -> dict[str, Any]:
        """Deprecated: POST /api/v1/email/smtp."""
        return self._send(_legacy("smtp_verify", email))

    def ban_email(self, email: str, *, banned_by: str | None = None, reason: str | None = None) -> dict[str, Any]:
        """Deprecated: POST /api/v1/email/ban. Use :meth:`ban`."""
        return self._send(_legacy("ban_email", email, banned_by, reason))

    def unban_email(self, email: str) -> dict[str, Any]:
        """Deprecated: DELETE /api/v1/email/ban. Use :meth:`unban`."""
        return self._send(_legacy("unban_email", email))

    def ai_score(self, email: str) -> dict[str, Any]:
        """Deprecated: POST /api/v1/ai/score."""
        return self._send(_legacy("ai_score", email))

    def ai_score_batch(self, emails: list[str]) -> dict[str, Any]:
        """Deprecated: POST /api/v1/ai/score/batch."""
        return self._send(_legacy("ai_score_batch", emails))

    def pattern_report(self) -> dict[str, Any]:
        """Deprecated: GET /api/v1/patterns/report."""
        return self._send(_legacy("pattern_report"))


# ---------------------------------------------------------------------------
# Async client
# ---------------------------------------------------------------------------


class AsyncGuardpostClient(_Base):
    """Asynchronous client: the methods of :class:`GuardpostClient`, awaitable.

    ``transport`` is an ``httpx.AsyncBaseTransport`` (tests:
    ``httpx.ASGITransport(app=...)``); ``http_client`` an ``httpx.AsyncClient``.
    """

    def __init__(self, base_url: str, **kwargs: Any) -> None:
        super().__init__(base_url, **kwargs)
        self._sleep: Callable[[float], Awaitable[None]] = asyncio.sleep

    # --- lifecycle -------------------------------------------------------

    def _http(self):
        if self._client is None:
            import httpx

            self._client = httpx.AsyncClient(transport=self._transport, timeout=self.timeout)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    close = aclose  # the 0.2 name

    async def __aenter__(self) -> AsyncGuardpostClient:
        return self

    async def __aexit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                        tb: TracebackType | None) -> None:
        await self.aclose()

    def fail_open(self, default: D, *,
                  on_error: Callable[[GuardpostError], Any] | None = None) -> AsyncFailOpen[D]:
        """This client's methods, returning ``default`` instead of raising a GuardpostError."""
        return AsyncFailOpen(self, default, on_error)

    # --- transport -------------------------------------------------------

    async def _send(self, call: _Call[Any]) -> Any:
        deadline = None if self.total_timeout is None else time.monotonic() + self.total_timeout
        attempt = 0
        while True:
            timeout = self._budget(deadline)
            if timeout is None:
                raise GuardpostTimeoutError("total_timeout exceeded")
            try:
                resp = await self._http().request(call.method, self.base_url + call.path, json=call.json,
                                                  params=call.params, headers=self._headers(call),
                                                  timeout=timeout)
            except Exception as exc:
                if not _is_httpx_error(exc):
                    raise
                err = self._transport_error(exc)
            else:
                if resp.status_code < 400:
                    return self._parse(call, resp)
                err = self._error(resp)
            delay = self._backoff(err, attempt, deadline)
            if delay is None:
                raise err
            await self._sleep(delay)
            attempt += 1

    # --- v2 --------------------------------------------------------------

    async def check_v2(self, request: CheckV2Request | Mapping[str, Any] | None = None, /, *,
                       idempotency_key: str | None = None, **fields: Any) -> CheckV2Response:
        """POST /api/v2/check (see :meth:`GuardpostClient.check_v2`)."""
        return await self._send(_check_call(request, idempotency_key, fields))

    async def commit(self, check_id: str, account_id: str) -> CheckV2Response:
        """POST /api/v2/accounts: commit an evaluated check (within 1 hour)."""
        return await self._send(_commit_call(check_id, account_id))

    async def event(self, account_id: str, type: str, /, **fields: Any) -> EventResponse:
        """POST /api/v2/accounts/{id}/events."""
        return await self._send(_event_call(account_id, type, fields))

    async def ban(self, email: str | None = None, /, *, email_sha256: str | None = None,
                  reason: str | None = None, banned_by: str | None = None) -> BanV2Response:
        """PUT /api/v2/bans."""
        return await self._send(_ban_call(email, email_sha256, reason, banned_by))

    async def unban(self, email: str | None = None, /, *, email_sha256: str | None = None) -> BanV2Response:
        """DELETE /api/v2/bans."""
        return await self._send(_unban_call(email, email_sha256))

    async def ip_override(self, target: str, action: Literal["allow", "block"] | None, *,
                          reason: str | None = None, created_by: str | None = None) -> OverrideResponse:
        """PUT /api/v2/ip-overrides/{ip_or_cidr}; ``action=None`` removes it."""
        return await self._send(_override_call(target, action, reason, created_by))

    async def import_accounts(self, rows: Iterable[AccountImport | Mapping[str, Any]], *,
                              chunk_size: int = IMPORT_MAX_ROWS) -> ImportResponse:
        return await self._import("/api/v2/import/accounts", AccountImport, rows, chunk_size)

    async def import_bans(self, rows: Iterable[BanImport | Mapping[str, Any]], *,
                          chunk_size: int = IMPORT_MAX_ROWS) -> ImportResponse:
        return await self._import("/api/v2/import/bans", BanImport, rows, chunk_size)

    async def import_referrals(self, rows: Iterable[ReferralImport | Mapping[str, Any]], *,
                               chunk_size: int = IMPORT_MAX_ROWS) -> ImportResponse:
        return await self._import("/api/v2/import/referrals", ReferralImport, rows, chunk_size)

    async def import_ip_reputation(self, rows: Iterable[IPReputationImport | Mapping[str, Any]], *,
                                   chunk_size: int = IMPORT_MAX_ROWS) -> ImportResponse:
        return await self._import("/api/v2/admin/ip-reputation/import", IPReputationImport, rows, chunk_size)

    async def _import(self, path: str, model: type[BaseModel], rows: Iterable[Any],
                      chunk_size: int) -> ImportResponse:
        return _sum_imports([await self._send(c) for c in _import_calls(path, model, rows, chunk_size)])

    async def account(self, account_id: str) -> AccountResponse:
        return await self._send(_Call("GET", f"/api/v2/accounts/{_segment(account_id)}", AccountResponse))

    async def stats(self, days: int = 30) -> StatsV2Response:
        return await self._send(_Call("GET", "/api/v2/stats", StatsV2Response, params={"days": days}))

    async def health(self) -> HealthResponse:
        return await self._send(_Call("GET", "/api/v1/health", HealthResponse))

    # --- 0.2 dict API (deprecated) ----------------------------------------

    async def check(self, email: str, *, ip_address: str | None = None, record_ip: bool = True,
                    smtp_verify: bool = False, check_proxy: bool = False, ai_score: bool = False) -> dict[str, Any]:
        return await self._send(_legacy("check", email, ip_address, record_ip, smtp_verify, check_proxy,
                                        ai_score))

    async def validate_email(self, email: str) -> dict[str, Any]:
        return await self._send(_legacy("validate_email", email))

    async def check_ip(self, ip_address: str) -> dict[str, Any]:
        return await self._send(_legacy("check_ip", ip_address))

    async def record_ip(self, ip_address: str, is_suspicious: bool = False) -> dict[str, Any]:
        return await self._send(_legacy("record_ip", ip_address, is_suspicious))

    async def check_proxy(self, ip_address: str) -> dict[str, Any]:
        return await self._send(_legacy("check_proxy", ip_address))

    async def smtp_verify(self, email: str) -> dict[str, Any]:
        return await self._send(_legacy("smtp_verify", email))

    async def ban_email(self, email: str, *, banned_by: str | None = None,
                        reason: str | None = None) -> dict[str, Any]:
        return await self._send(_legacy("ban_email", email, banned_by, reason))

    async def unban_email(self, email: str) -> dict[str, Any]:
        return await self._send(_legacy("unban_email", email))

    async def ai_score(self, email: str) -> dict[str, Any]:
        return await self._send(_legacy("ai_score", email))

    async def ai_score_batch(self, emails: list[str]) -> dict[str, Any]:
        return await self._send(_legacy("ai_score_batch", emails))

    async def pattern_report(self) -> dict[str, Any]:
        return await self._send(_legacy("pattern_report"))


__all__ = [
    "AsyncFailOpen", "AsyncGuardpostClient", "FailOpen", "GuardpostClient", "GuardpostConnectionError",
    "GuardpostError", "GuardpostRequestError", "GuardpostResponseError", "GuardpostTimeoutError", "RetryPolicy",
    "afail_open", "fail_open",
]
