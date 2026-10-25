"""API server tests: version, client-IP resolution for rate limits, metrics port."""

import urllib.request

import pytest
from fastapi.testclient import TestClient

import guardpost
from guardpost.api.server import create_app


@pytest.fixture
def make_client(tmp_path, monkeypatch):
    for var in ("GUARDPOST_API_KEY", "GUARDPOST_REDIS_URL", "GUARDPOST_RATE_LIMIT", "GUARDPOST_TRUSTED_PROXIES",
                "GUARDPOST_ENABLE_METRICS", "GUARDPOST_METRICS_PORT", "GUARDPOST_TRUSTED_EXTRA_DOMAINS"):
        monkeypatch.delenv(var, raising=False)
    clients = []

    def _make(peer=("203.0.113.9", 50000), **kwargs):
        app = create_app(db_path=str(tmp_path / f"gp{len(clients)}.db"), **kwargs)
        client = TestClient(app, client=peer)
        client.__enter__()
        clients.append(client)
        return client

    yield _make
    for client in clients:
        client.__exit__(None, None, None)


def test_app_version_comes_from_package(make_client):
    client = make_client()
    assert client.app.version == guardpost.__version__
    assert client.get("/api/v1/health").json()["version"] == guardpost.__version__


class TestRateLimitClientIP:
    def test_spoofed_header_ignored_without_trusted_proxies(self, make_client):
        client = make_client(rate_limit=2)
        codes = [
            client.get("/healthz", headers={"X-Forwarded-For": f"1.2.3.{i}"}).status_code
            for i in range(3)
        ]
        # Rotating the header must not buy a fresh bucket per request.
        assert codes == [200, 200, 429]

    def test_untrusted_peer_cannot_spoof_even_when_proxies_configured(self, make_client):
        client = make_client(rate_limit=2, trusted_proxies="10.0.0.0/8")
        codes = [
            client.get("/healthz", headers={"X-Forwarded-For": f"1.2.3.{i}"}).status_code
            for i in range(3)
        ]
        assert codes == [200, 200, 429]

    def test_trusted_proxy_hop_is_the_key(self, make_client):
        client = make_client(peer=("10.0.0.5", 50000), rate_limit=2, trusted_proxies="10.0.0.0/8")
        # Two distinct real clients behind the proxy get separate buckets...
        for ip in ("198.51.100.1", "198.51.100.2"):
            assert client.get("/healthz", headers={"X-Forwarded-For": ip}).status_code == 200
            assert client.get("/healthz", headers={"X-Forwarded-For": ip}).status_code == 200
        # ...and a client cannot escape its bucket by prepending a fake hop.
        spoof = {"X-Forwarded-For": "9.9.9.9, 198.51.100.1"}
        assert client.get("/healthz", headers=spoof).status_code == 429

    def test_invalid_trusted_proxies_fails_at_startup(self, tmp_path):
        with pytest.raises(ValueError):
            create_app(db_path=str(tmp_path / "x.db"), trusted_proxies="not-a-cidr")


class TestMetrics:
    def test_no_metrics_route_on_the_api_app(self, make_client):
        client = make_client(enable_metrics=True, metrics_port=0)
        assert client.get("/metrics").status_code == 404

    def test_metrics_served_on_separate_port_with_route_templates(self, make_client):
        client = make_client(enable_metrics=True, metrics_port=0)
        port = client.app.state.metrics_port
        assert port
        client.post("/api/v1/email/validate", json={"email": "someone@gmail.com"})
        client.get("/no/such/path/12345")

        body = urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5).read().decode()
        assert "guardpost_request_duration_seconds" in body
        assert 'endpoint="/api/v1/email/validate"' in body
        assert 'endpoint="<unmatched>"' in body
        assert "/no/such/path/12345" not in body

    def test_metrics_disabled_by_default(self, make_client):
        client = make_client()
        assert not hasattr(client.app.state, "metrics_port")
        assert client.get("/metrics").status_code == 404


class TestEmailValidateFields:
    def test_typo_source_reported(self, make_client):
        client = make_client()
        body = client.post("/api/v1/email/validate", json={"email": "x@gnail.com"}).json()
        assert "typo_domain" in body["reasons"]
        assert body["suggested_domain"] == "gmail.com"
        assert body["typo_source"] == "map"

    def test_trusted_extra_domains_honoured(self, make_client):
        from guardpost.email.validator import _mx_host_cache, clear_caches

        clear_caches()
        _mx_host_cache["factory.bot"] = None
        try:
            client = make_client(trusted_extra_domains="factory.bot")
            body = client.post("/api/v1/email/validate", json={"email": "telegram_1@factory.bot"}).json()
            assert body["reasons"] == []
            assert body["is_suspicious"] is False
        finally:
            clear_caches()


def test_cli_serve_passes_proxy_and_metrics_options(monkeypatch):
    import uvicorn

    from guardpost import cli

    seen = {}
    monkeypatch.setattr("guardpost.api.server.create_app", lambda **kw: seen.setdefault("app_kwargs", kw) and "app")
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.setdefault("run_kwargs", kw))
    monkeypatch.delenv("GUARDPOST_METRICS_HOST", raising=False)
    cli.main(["serve", "--host", "0.0.0.0", "--trusted-proxies", "10.0.0.0/8",
              "--enable-metrics", "--metrics-port", "9200"])
    assert seen["app_kwargs"]["trusted_proxies"] == "10.0.0.0/8"
    assert seen["app_kwargs"]["enable_metrics"] is True
    assert seen["app_kwargs"]["metrics_port"] == 9200
    assert seen["app_kwargs"]["metrics_host"] == "0.0.0.0"
    # uvicorn must not rewrite the peer from X-Forwarded-For behind our back.
    assert seen["run_kwargs"]["proxy_headers"] is False


def test_v1_check_returns_tiered_reasons(make_client):
    client = make_client()
    body = client.post("/api/v1/check", json={"email": "hello@duck.com", "record_ip": False}).json()
    assert body["reasons"] == ["relay_domain", "role_account_extended"]
    assert body["weak_reasons"] == ["relay_domain", "role_account_extended"]
    assert body["soft_reasons"] == []
    assert body["hard_reasons"] == []
    assert body["is_suspicious"] is False

    body = client.post("/api/v1/check", json={"email": "someone@sharklasers.com", "record_ip": False}).json()
    assert body["soft_reasons"] == ["disposable_domain"]
    assert body["is_suspicious"] is True
