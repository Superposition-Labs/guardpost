"""The Python client: transport behaviour (mocked) and every method against the real app."""

from __future__ import annotations

import json
import warnings
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from conftest import provision_tenants

from guardpost.client import (
    AsyncGuardpostClient,
    GuardpostClient,
    GuardpostConnectionError,
    GuardpostError,
    GuardpostRequestError,
    GuardpostResponseError,
    GuardpostTimeoutError,
    afail_open,
    fail_open,
)
from guardpost.models import CheckV2Request, CheckV2Response, HealthResponse, ImportResponse

# The live tests hand the client a starlette TestClient, which frowns on per-request timeouts.
pytestmark = pytest.mark.filterwarnings("ignore:You should not use the 'timeout' argument:DeprecationWarning")

UA = "Mozilla/5.0 (X11; Linux x86_64) Test/1.0"
BASE = "http://gp.test"


def check_body(account: str = "u1", **extra) -> dict:
    """A v2 CheckV2Response body, as the server renders it."""
    body = {
        "check_id": "chk_1", "decision": "allow", "block_code": None, "risk_score": 0, "reasons": [],
        "hard_reasons": [], "soft_reasons": [], "weak_reasons": [], "actions": [], "referral": None,
        "suggestion": None,
        "signals": {"method": "email", "returning_user": False, "ip_status": "clean", "ip_reason": None,
                    "subnet_status": "clean", "subnet_reason": None, "ip_override": None, "global_ip": True,
                    "fingerprint": True, "name_key": False, "typo_source": None},
        "mode": "commit", "committed": True, "account_id": account, "occurred_at": "2026-10-01T00:00:00Z",
        "ruleset": "test", "engine_version": "0.0.0",
    }
    body.update(extra)
    return body


class Recorder:
    """An httpx.MockTransport handler: replays scripted responses (the last one repeats), records requests."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        item = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(item, Exception):
            raise item
        status, body = item
        return httpx.Response(status, json=body)


def sync_client(handler, **kwargs) -> GuardpostClient:
    kwargs.setdefault("api_key", "gpk_test_secret")
    kwargs.setdefault("backoff", 0)
    client = GuardpostClient(BASE, transport=httpx.MockTransport(handler), **kwargs)
    client._sleep = lambda s: None
    return client


def async_client(handler, **kwargs) -> AsyncGuardpostClient:
    kwargs.setdefault("api_key", "gpk_test_secret")
    kwargs.setdefault("backoff", 0)

    async def no_sleep(s):
        return None

    client = AsyncGuardpostClient(BASE, transport=httpx.MockTransport(handler), **kwargs)
    client._sleep = no_sleep
    return client


SIGNUP = {"mode": "commit", "email": "person@gmail.com", "ip": "198.51.100.7", "account": {"id": "u1"}}


# ---------------------------------------------------------------------------
# Configuration and errors
# ---------------------------------------------------------------------------


class TestConfig:
    def test_defaults(self):
        client = GuardpostClient("https://api.example.com/")
        assert client.base_url == "https://api.example.com"
        assert client.api_key is None
        assert client.timeout == 5.0
        assert client.retries == 2
        assert client.total_timeout is None

    def test_custom(self):
        client = AsyncGuardpostClient("https://api.example.com", api_key="gpk_x", timeout=1.5, retries=0,
                                      total_timeout=1.5)
        assert (client.api_key, client.timeout, client.retries, client.total_timeout) == ("gpk_x", 1.5, 0, 1.5)

    @pytest.mark.parametrize("kwargs", [{"retries": -1}, {"timeout": 0}, {"total_timeout": 0}])
    def test_invalid(self, kwargs):
        with pytest.raises(ValueError):
            GuardpostClient(BASE, **kwargs)


class TestErrors:
    def test_message(self):
        err = GuardpostError(401, "Invalid API key")
        assert (err.status_code, err.detail, err.code, err.retryable) == (401, "Invalid API key", None, False)
        assert str(err) == "HTTP 401: Invalid API key"

    def test_v2_detail(self):
        err = GuardpostError(409, {"code": "account_exists", "message": "Account 'u1' is already in the ledger"})
        assert err.code == "account_exists"
        assert "already in the ledger" in str(err)

    def test_retryable(self):
        assert GuardpostError(503, "x").retryable
        assert not GuardpostError(429, "x").retryable
        assert GuardpostTimeoutError().retryable and GuardpostTimeoutError().status_code is None

    def test_validation_detail_never_echoes_input(self):
        detail = [{"type": "value_error", "loc": ["body", "ip"], "msg": "Value error, invalid IP address",
                   "input": "secret.person@gmail.com"}]
        err = GuardpostError(422, detail)
        assert "secret.person" not in str(err)
        assert "ip: Value error" in str(err)


# ---------------------------------------------------------------------------
# Transport behaviour (mocked)
# ---------------------------------------------------------------------------


class TestTransport:
    def test_bearer_auth_and_idempotency_header(self):
        rec = Recorder((200, check_body()))
        with sync_client(rec) as gp:
            result = gp.check_v2(**SIGNUP, idempotency_key="signup:u1")
        assert isinstance(result, CheckV2Response)
        assert result.decision == "allow" and result.account_id == "u1"
        req = rec.requests[0]
        assert req.headers["Authorization"] == "Bearer gpk_test_secret"
        assert "X-Api-Key" not in req.headers
        assert req.headers["Idempotency-Key"] == "signup:u1"
        assert req.headers["User-Agent"].startswith("guardpost-python/")
        sent = json.loads(req.content)
        assert sent["email"] == "person@gmail.com" and "idempotency_key" not in sent
        assert req.url.path == "/api/v2/check"

    def test_request_model_and_body_key(self):
        rec = Recorder((200, check_body()))
        with sync_client(rec) as gp:
            gp.check_v2(CheckV2Request(**SIGNUP, idempotency_key="k1"))
            with pytest.raises(ValueError):
                gp.check_v2(CheckV2Request(**SIGNUP, idempotency_key="k1"), idempotency_key="k2")
            with pytest.raises(TypeError):
                gp.check_v2(SIGNUP, mode="commit")
        assert rec.requests[0].headers["Idempotency-Key"] == "k1"

    def test_client_side_validation(self):
        rec = Recorder((200, check_body()))
        with sync_client(rec) as gp:
            with pytest.raises(GuardpostRequestError) as exc:
                gp.check_v2(email="secret.person@gmail.com", ip="not-an-ip")
        assert exc.value.code == "invalid_request" and not exc.value.retryable
        assert "secret.person" not in str(exc.value)
        assert rec.requests == []

    def test_retries_5xx_then_succeeds(self):
        rec = Recorder((503, {"detail": "Guardpost not initialized"}), (500, {"detail": "boom"}),
                       (200, check_body()))
        with sync_client(rec, retries=2) as gp:
            assert gp.check_v2(**SIGNUP).decision == "allow"
        assert len(rec.requests) == 3

    def test_gives_up_after_retries(self):
        rec = Recorder((502, {"detail": "bad gateway"}))
        with sync_client(rec, retries=2) as gp, pytest.raises(GuardpostError) as exc:
            gp.health()
        assert exc.value.status_code == 502
        assert len(rec.requests) == 3

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 422, 429])
    def test_never_retries_4xx(self, status):
        rec = Recorder((status, {"detail": {"code": "nope", "message": "no"}}))
        with sync_client(rec, retries=3) as gp, pytest.raises(GuardpostError) as exc:
            gp.check_v2(**SIGNUP)
        assert exc.value.status_code == status and exc.value.code == "nope"
        assert len(rec.requests) == 1

    def test_retries_connection_errors(self):
        rec = Recorder(httpx.ConnectError("refused"), (200, {"status": "ok", "version": "0.4.0"}))
        with sync_client(rec) as gp:
            assert gp.health() == HealthResponse(status="ok", version="0.4.0")
        assert len(rec.requests) == 2

    def test_timeout(self):
        rec = Recorder(httpx.ReadTimeout("slow"))
        with sync_client(rec, retries=1) as gp, pytest.raises(GuardpostTimeoutError) as exc:
            gp.health()
        assert exc.value.code == "timeout"
        assert len(rec.requests) == 2

    def test_connection_error_without_retries(self):
        rec = Recorder(httpx.ConnectError("refused"))
        with sync_client(rec, retries=0) as gp, pytest.raises(GuardpostConnectionError):
            gp.health()
        assert len(rec.requests) == 1

    def test_total_timeout_caps_attempt_and_retries(self):
        rec = Recorder(httpx.ReadTimeout("slow"))
        timeouts = []

        def handler(request):
            timeouts.append(request.extensions["timeout"]["read"])
            return rec(request)

        gp = sync_client(handler, timeout=5.0, total_timeout=0.5, retries=5, backoff=0.4, max_backoff=0.4)
        gp._sleep = __import__("time").sleep
        with pytest.raises(GuardpostTimeoutError):
            gp.health()
        assert timeouts[0] <= 0.5
        # A 0.2-0.4 s back-off fits at most twice into a 0.5 s budget.
        assert len(timeouts) <= 3

    def test_invalid_response(self):
        rec = Recorder((200, check_body(decision="maybe")))
        with sync_client(rec) as gp, pytest.raises(GuardpostResponseError) as exc:
            gp.check_v2(**SIGNUP)
        assert exc.value.code == "invalid_response" and "decision" in str(exc.value)

    def test_dict_style_access(self):
        rec = Recorder((200, {"status": "ok", "version": "0.4.0"}))
        with sync_client(rec) as gp:
            health = gp.health()
        assert health["status"] == "ok"
        with pytest.raises(KeyError):
            health["nope"]

    def test_imports_are_chunked_and_summed(self):
        rec = Recorder((200, {"received": 2, "inserted": 2, "updated": 0}),
                       (200, {"received": 1, "inserted": 0, "updated": 1}))
        rows = [{"email_sha256": f"{i:064x}"} for i in range(3)]
        with sync_client(rec) as gp:
            result = gp.import_bans(rows, chunk_size=2)
            with pytest.raises(ValueError):
                gp.import_bans(rows, chunk_size=1001)
        assert result == ImportResponse(received=3, inserted=2, updated=1)
        assert [len(json.loads(r.content)["rows"]) for r in rec.requests] == [2, 1]

    def test_ip_override_put_and_delete(self):
        rec = Recorder((200, {"target": "203.0.113.0/24", "kind": "net24", "action": "block"}),
                       (200, {"target": "203.0.113.0/24", "kind": "net24", "removed": True}))
        with sync_client(rec) as gp:
            assert gp.ip_override("203.0.113.0/24", "block", reason="farm").action == "block"
            assert gp.ip_override("203.0.113.0/24", None).removed is True
        assert [(r.method, r.url.path) for r in rec.requests] == [
            ("PUT", "/api/v2/ip-overrides/203.0.113.0/24"), ("DELETE", "/api/v2/ip-overrides/203.0.113.0/24")]

    def test_event_body(self):
        rec = Recorder((200, {"account_id": "u1", "type": "paid", "applied": True, "duplicate": False,
                              "event_id": 7}))
        with sync_client(rec) as gp:
            assert gp.event("u1", "paid", idempotency_key="paid:u1").event_id == 7
            with pytest.raises(GuardpostRequestError):
                gp.event("u1", "exploded")
            with pytest.raises(ValueError):
                gp.event("../admin", "paid")
        assert json.loads(rec.requests[0].content) == {"type": "paid", "idempotency_key": "paid:u1",
                                                       "permanent_email_ban": False}


class TestFailOpen:
    def test_default_on_error(self):
        rec = Recorder((503, {"detail": "down"}))
        errors = []
        with sync_client(rec, retries=0) as gp:
            assert gp.fail_open(None, on_error=errors.append).check_v2(**SIGNUP) is None
        assert errors[0].status_code == 503

    def test_result_passes_through(self):
        rec = Recorder((200, check_body()))
        with sync_client(rec) as gp:
            assert gp.fail_open("fallback").check_v2(**SIGNUP).decision == "allow"

    def test_client_side_validation_fails_open(self):
        with sync_client(Recorder((200, check_body()))) as gp:
            assert gp.fail_open("fallback").check_v2(email="x@gmail.com", ip="999.1.1.1") == "fallback"

    def test_programming_errors_still_raise(self):
        with sync_client(Recorder((200, check_body()))) as gp, pytest.raises(TypeError):
            gp.fail_open(None).check_v2(SIGNUP, mode="commit")

    def test_function_helper(self):
        with sync_client(Recorder(httpx.ConnectError("refused")), retries=0) as gp:
            assert fail_open(gp.health, "down") == "down"

    async def test_async(self):
        gp = async_client(Recorder(httpx.ReadTimeout("slow")), retries=0)
        async with gp:
            assert await gp.fail_open("allow-locally").check_v2(**SIGNUP) == "allow-locally"
            assert await afail_open(gp.health(), None) is None
            assert await afail_open(gp.health, None) is None


class TestAsyncTransport:
    async def test_retries_then_succeeds(self):
        rec = Recorder((500, {"detail": "boom"}), (200, check_body()))
        async with async_client(rec) as gp:
            result = await gp.check_v2(**SIGNUP, idempotency_key="signup:u1")
        assert result.committed and len(rec.requests) == 2
        assert rec.requests[1].headers["Authorization"] == "Bearer gpk_test_secret"

    async def test_never_retries_4xx(self):
        rec = Recorder((409, {"detail": {"code": "account_exists", "message": "exists"}}))
        async with async_client(rec, retries=3) as gp:
            with pytest.raises(GuardpostError) as exc:
                await gp.check_v2(**SIGNUP)
        assert exc.value.code == "account_exists" and len(rec.requests) == 1


class TestLegacyDictAPI:
    def test_sync_methods_warn_and_return_dicts(self):
        rec = Recorder((200, {"email": "t@example.com", "is_suspicious": True, "risk_score": 40}))
        with sync_client(rec) as gp:
            with pytest.warns(DeprecationWarning, match="check_v2"):
                result = gp.check("t@example.com", ip_address="1.2.3.4", smtp_verify=True)
            with pytest.warns(DeprecationWarning):
                gp.ban_email("bad@example.com", banned_by="admin", reason="spam")
            with pytest.warns(DeprecationWarning):
                gp.pattern_report()
        assert result["is_suspicious"] is True
        assert (rec.requests[0].method, rec.requests[0].url.path) == ("POST", "/api/v1/check")
        assert json.loads(rec.requests[0].content) == {
            "email": "t@example.com", "record_ip": True, "smtp_verify": True, "check_proxy": False,
            "ai_score": False, "ip_address": "1.2.3.4"}
        assert json.loads(rec.requests[1].content) == {"email": "bad@example.com", "banned_by": "admin",
                                                       "reason": "spam"}

    async def test_02_async_usage_still_works(self):
        rec = Recorder((200, {"email": "t@example.com", "is_suspicious": False}))
        with pytest.warns(DeprecationWarning, match="AsyncGuardpostClient"):
            async with GuardpostClient(BASE, api_key="k", transport=httpx.MockTransport(rec)) as gp:
                assert isinstance(gp, AsyncGuardpostClient)
                with pytest.warns(DeprecationWarning):
                    result = await gp.check("t@example.com")
        assert result == {"email": "t@example.com", "is_suspicious": False}

    async def test_async_legacy_methods(self):
        rec = Recorder((200, {"results": []}))
        async with async_client(rec) as gp:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                for call in (gp.validate_email("a@b.com"), gp.check_ip("1.2.3.4"), gp.record_ip("1.2.3.4"),
                             gp.check_proxy("1.2.3.4"), gp.smtp_verify("a@b.com"), gp.unban_email("a@b.com"),
                             gp.ai_score("a@b.com"), gp.ai_score_batch(["a@b.com"])):
                    await call
            await gp.close()
        assert [r.url.path for r in rec.requests] == [
            "/api/v1/email/validate", "/api/v1/ip/check", "/api/v1/ip/record", "/api/v1/ip/proxy",
            "/api/v1/email/smtp", "/api/v1/email/ban", "/api/v1/ai/score", "/api/v1/ai/score/batch"]


# ---------------------------------------------------------------------------
# Against the real app
# ---------------------------------------------------------------------------


def now(**delta) -> datetime:
    return datetime.now(UTC) + timedelta(**delta)


@pytest.fixture
def live(tmp_path, v2_app):
    """The real app with two tenants; returns (TestClient, keys)."""
    db = tmp_path / "gp.db"
    keys = provision_tenants(db, {"alpha": {}, "beta": {}})
    keys["check_only"] = provision_tenants(db, {"gamma": {}}, scopes="check")["gamma"]
    client = v2_app(db=db, api_key="legacy-key", legacy_tenant="alpha")
    return client, keys


def signup(account: str, email: str, ip: str = "198.51.210.10", **extra) -> dict:
    return {"email": email, "ip": ip, "device": {"user_agent": UA, "accept_language": "en"},
            "account": {"id": account}, **extra}


class TestSyncClientLive:
    def test_full_lifecycle(self, live):
        test_client, keys = live
        gp = GuardpostClient("http://testserver", api_key=keys["alpha"], http_client=test_client)

        assert gp.health().status == "ok"

        evaluated = gp.check_v2(**signup("a1", "first.person@gmail.com"))
        assert evaluated.mode == "evaluate" and not evaluated.committed
        committed = gp.commit(evaluated.check_id, "a1")
        assert committed.committed and committed.account_id == "a1"
        assert gp.commit(evaluated.check_id, "a1") == committed  # idempotent

        first = gp.check_v2(mode="commit", idempotency_key="signup:a2", **signup("a2", "second.person@gmail.com"))
        replay = gp.check_v2(mode="commit", idempotency_key="signup:a2", **signup("a2", "second.person@gmail.com"))
        assert replay == first

        with pytest.raises(GuardpostError) as exc:
            gp.check_v2(mode="commit", **signup("a2", "second.person@gmail.com"))
        assert (exc.value.status_code, exc.value.code) == (409, "account_exists")

        paid = gp.event("a1", "paid", idempotency_key="paid:a1")
        assert paid.applied
        assert gp.event("a1", "paid", idempotency_key="paid:a1").duplicate

        assert gp.ban("banned.person@gmail.com", reason="abuse").created is True
        blocked = gp.check_v2(**signup("a3", "banned.person@gmail.com"))
        assert blocked.decision == "block" and blocked.block_code == "EMAIL_BANNED"
        assert gp.unban("banned.person@gmail.com").removed is True

        assert gp.ip_override("203.0.113.0/24", "block").kind == "net24"
        refused = gp.check_v2(**signup("a4", "fourth.person@gmail.com", ip="203.0.113.9"))
        assert refused.block_code == "IP_BLACKLISTED"
        assert gp.ip_override("203.0.113.0/24", None).removed is True

        created = now(days=-3)
        imported = gp.import_accounts([{"account_id": f"old{i}", "email": f"old.person{i}@gmail.com",
                                        "created_at": created, "ip": "198.51.211.4"} for i in range(5)],
                                      chunk_size=2)
        assert imported == ImportResponse(received=5, inserted=5, updated=0)
        assert gp.import_bans([{"email": "old.banned@gmail.com"}]).inserted == 1
        assert gp.import_referrals([{"referred_account_id": "old1", "referrer_account_id": "old0",
                                     "created_at": created}]).inserted == 1
        assert gp.import_ip_reputation([{"ip_address": "192.0.2.0/24", "total_registrations": 3}]).received == 1

        account = gp.account("old1")
        assert account.referred_by.referrer_account_id == "old0"
        assert account.signals.email is True

        stats = gp.stats(days=7)
        assert stats.tenant_id == "alpha" and stats.accounts >= 7
        assert sum(stats.decisions.values()) >= 2

    def test_tenant_isolation_and_scopes(self, live):
        test_client, keys = live
        alpha = GuardpostClient("http://testserver", api_key=keys["alpha"], http_client=test_client)
        beta = GuardpostClient("http://testserver", api_key=keys["beta"], http_client=test_client)
        alpha.check_v2(mode="commit", **signup("shared-id", "iso.person@gmail.com"))
        assert beta.stats().accounts == 0
        with pytest.raises(GuardpostError) as exc:
            beta.account("shared-id")
        assert exc.value.status_code == 404

        check_only = GuardpostClient("http://testserver", api_key=keys["check_only"], http_client=test_client)
        with pytest.raises(GuardpostError) as exc:
            check_only.stats()
        assert exc.value.status_code == 403

        anonymous = GuardpostClient("http://testserver", api_key="gpk_nope_nope", http_client=test_client)
        with pytest.raises(GuardpostError) as exc:
            anonymous.health()
        assert exc.value.status_code == 401

    def test_occurred_at_needs_backfill_scope(self, live):
        test_client, keys = live
        too_old = now(days=-2)
        check_only = GuardpostClient("http://testserver", api_key=keys["check_only"], http_client=test_client)
        with pytest.raises(GuardpostError) as exc:
            check_only.check_v2(occurred_at=too_old, **signup("x1", "late.person@gmail.com"))
        assert exc.value.code == "occurred_at_out_of_window"
        # A key with the backfill scope may replay old signups.
        gp = GuardpostClient("http://testserver", api_key=keys["alpha"], http_client=test_client)
        assert gp.check_v2(occurred_at=too_old, **signup("x1", "late.person@gmail.com")).decision == "allow"

    def test_legacy_key_on_v1(self, live):
        test_client, _ = live
        gp = GuardpostClient("http://testserver", api_key="legacy-key", http_client=test_client)
        with pytest.warns(DeprecationWarning):
            result = gp.check("someone@gmail.com", ip_address="198.51.100.20")
        assert result["is_suspicious"] is False
        # On v2 the legacy key holds only its explicit check and dashboard scopes.
        assert gp.stats().tenant_id == "alpha"
        with pytest.raises(GuardpostError) as exc:
            gp.ban("someone@gmail.com")
        assert exc.value.status_code == 403


@pytest.fixture
def provisioned(tmp_path, clean_env):
    db = tmp_path / "gp.db"
    return db, provision_tenants(db, {"alpha": {}})


class TestAsyncClientLive:
    async def test_lifecycle_over_asgi(self, provisioned):
        from guardpost.api.server import create_app
        from guardpost.email.validator import StubDnsResolver

        db, keys = provisioned
        app = create_app(db_path=str(db), secret="test-secret-not-for-production", purge_interval=0,
                         dns_resolver=StubDnsResolver())
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app, client=("203.0.113.9", 50000))
            async with AsyncGuardpostClient("http://testserver", api_key=keys["alpha"],
                                            transport=transport) as gp:
                assert (await gp.health()).status == "ok"
                evaluated = await gp.check_v2(**signup("b1", "async.person@gmail.com"))
                committed = await gp.commit(evaluated.check_id, "b1")
                assert committed.committed
                replay_key = {"idempotency_key": "signup:b2"}
                first = await gp.check_v2(mode="commit", **replay_key, **signup("b2", "async.two@gmail.com"))
                assert await gp.check_v2(mode="commit", **replay_key,
                                         **signup("b2", "async.two@gmail.com")) == first
                assert (await gp.event("b1", "flagged", reason="manual")).applied
                assert (await gp.ban("async.banned@gmail.com")).banned
                assert (await gp.unban("async.banned@gmail.com")).removed
                assert (await gp.ip_override("198.51.100.1", "allow")).kind == "ip"
                assert (await gp.import_accounts([{"account_id": "b9", "email": "async.nine@gmail.com",
                                                   "created_at": now(days=-1)}])).inserted == 1
                assert (await gp.import_bans([{"email": "async.ban2@gmail.com"}])).inserted == 1
                assert (await gp.import_referrals([{"referred_account_id": "b9", "referrer_account_id": "b1",
                                                    "created_at": now(days=-1)}])).inserted == 1
                assert (await gp.account("b1")).flagged_at is not None
                stats = await gp.stats()
                assert stats.accounts == 3 and stats.bans == 1
