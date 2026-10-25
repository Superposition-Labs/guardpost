<p align="center">
  <img src=".github/assets/guardpost-header.jpg" alt="Guardpost header" width="100%" />
</p>

# Guardpost

Self-hosted registration abuse detection service. Answers **"is this registration suspicious?"** via a REST API, and recommends silent degradation instead of hard blocking so attackers can't learn your detection signals.

## Features

- **5-layer email validation**: disposable blocklist (9,900+ domains) → heuristic patterns → DNS MX → MX infrastructure fingerprinting → role account detection
- **Email normalization**: Gmail dot tricks, +aliases, Yahoo hyphen aliases
- **IP reputation**: automatic graylist/blacklist with configurable thresholds
- **Banned email system**: SHA-256 normalized hash storage
- **SMTP verification**: RCPT TO + catch-all detection + SOCKS5 proxy support
- **VPN/Proxy/Datacenter detection**: cloud provider ranges + Tor exit nodes + MaxMind + IPinfo
- **AI email scoring**: LLM-powered risk analysis via OpenRouter
- **Pattern detection**: sequential usernames, similarity clustering, IP burst, velocity anomalies
- **Email enrichment**: Gravatar + Have I Been Pwned
- **REST API**: FastAPI with OpenAPI docs, API key auth, rate limiting
- **Storage**: SQLite (default), Redis (distributed), MongoDB, PostgreSQL
- **Docker ready** with Redis Stack

## Quick Start

### Docker Compose (recommended)

```bash
git clone https://github.com/Superposition-Labs/guardpost
cd guardpost
GUARDPOST_API_KEY=your-secret-key docker compose up -d
```

The default `docker-compose.yml` runs Guardpost with Redis Stack (RedisJSON, RedisTimeSeries, RediSearch, RedisBloom). The API is available at `http://localhost:8000`.

### Docker (standalone)

```bash
docker build -t guardpost .
docker run -p 8000:8000 -e GUARDPOST_API_KEY=your-secret-key guardpost
```

### Call the API

```bash
curl -X POST http://localhost:8000/api/v1/check \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: your-secret-key" \
  -d '{"email": "user@mailinator.com", "ip_address": "1.2.3.4"}'
```

OpenAPI docs at `http://localhost:8000/docs`.

### Python SDK

Use the included client to talk to your Guardpost instance from Python:

```bash
pip install httpx
```

```python
from guardpost.client import GuardpostClient

async with GuardpostClient("http://localhost:8000", api_key="your-secret-key") as gp:
    result = await gp.check("user@mailinator.com", ip_address="1.2.3.4")
    ai = await gp.ai_score("xk3jf8@gmail.com")
```

### CLI (from source)

```bash
git clone https://github.com/Superposition-Labs/guardpost
cd guardpost
pip install -e ".[api]"      # or ".[server]" for everything the Docker image runs
guardpost check user@mailinator.com
guardpost check user@gmail.com --ip 1.2.3.4
```

## Redis Storage

The default Docker deployment uses Redis Stack as the storage backend. This enables:

- **Distributed rate limiting** — atomic sliding-window via Lua scripting, works across multiple instances
- **AI score caching** — TTL-based JSON cache for OpenRouter responses
- **Bloom filter** — O(1) probabilistic banned-email lookups
- **Count-Min Sketch** — approximate IP registration frequency without per-IP counters
- **Top-K** — real-time tracking of most active registration IPs
- **TimeSeries** — native registration timeline with 7-day raw + 30-day compacted retention
- **RediSearch** — secondary index on IP reputation for aggregate stats queries

Redis configuration is passed via `GUARDPOST_REDIS_URL` environment variable (e.g. `redis://redis:6379`). When Redis is not configured, Guardpost falls back to SQLite.

### Redis-specific constructor options

| Parameter                 | Default      | Purpose                                             |
| ------------------------- | ------------ | --------------------------------------------------- |
| `bloom_capacity`          | `100,000`    | Expected banned email count for Bloom filter sizing |
| `bloom_error_rate`        | `0.01`       | Bloom filter false-positive rate                    |
| `topk_size`               | `100`        | Top IPs to track                                    |
| `cms_width` / `cms_depth` | `2000` / `5` | Count-Min Sketch dimensions                         |

## Detection Layers

| Layer                | Catches                                               | Example                         |
| -------------------- | ----------------------------------------------------- | ------------------------------- |
| Disposable blocklist | 9,900+ known domains                                  | mailinator.com                  |
| Heuristic patterns   | Numeric domains (≥4 digits), short domains (≤2 chars) | test@1234abc.com                |
| DNS MX validation    | Domains with no mail server                           | test@doesnotexist.xyz           |
| MX infrastructure    | Fresh domains using disposable mail backends          | Domains pointing to mail.tm     |
| Role accounts        | 43 core prefixes (`role_account`) + 157 extended (`role_account_extended`, weak) | info@, admin@ / dev@, hello@ |
| IP reputation        | IPs with excessive registrations                      | 5+ suspicious → graylist        |
| Banned emails        | Permanently banned (SHA-256 hash match)               | Exact match after normalization |

## API Endpoints

| Method   | Path                      | Description                          |
| -------- | ------------------------- | ------------------------------------ |
| `POST`   | `/api/v1/check`           | Full registration check (email + IP) |
| `POST`   | `/api/v1/email/validate`  | Email-only validation                |
| `POST`   | `/api/v1/email/smtp`      | SMTP mailbox verification            |
| `POST`   | `/api/v1/ip/check`        | IP reputation check                  |
| `POST`   | `/api/v1/ip/record`       | Record a registration from IP        |
| `POST`   | `/api/v1/ip/proxy`        | VPN/proxy/datacenter detection       |
| `POST`   | `/api/v1/ai/score`        | AI email risk scoring                |
| `POST`   | `/api/v1/ai/score/batch`  | Batch AI scoring                     |
| `GET`    | `/api/v1/patterns/report` | Registration pattern report          |
| `POST`   | `/api/v1/email/ban`       | Ban an email                         |
| `DELETE` | `/api/v1/email/ban`       | Unban an email                       |
| `GET`    | `/api/v1/stats`           | Aggregate statistics                 |
| `GET`    | `/api/v1/health`          | Health check                         |

OpenAPI docs at `/docs` when the server is running.

## Configuration

### IP Reputation Thresholds

```python
gp = Guardpost(
    storage=SQLiteStorage("/path/to/db.sqlite"),
    graylist_suspicious=5,     # suspicious regs → graylist
    graylist_total_7d=15,      # total regs in 7 days → graylist
    blacklist_suspicious=8,    # suspicious regs → blacklist
    blacklist_total_30d=30,    # total regs in 30 days → blacklist
)
```

### Environment Variables

| Variable                           | Purpose                                |
| ---------------------------------- | -------------------------------------- |
| `GUARDPOST_API_KEY`                | API key for authentication             |
| `GUARDPOST_REDIS_URL`              | Redis connection URL                   |
| `GUARDPOST_RATE_LIMIT`             | Max requests/min per IP (0 = disabled) |
| `GUARDPOST_TRUSTED_PROXIES`        | Comma-separated CIDRs of reverse proxies allowed to set `X-Forwarded-For` (see below) |
| `GUARDPOST_ENABLE_METRICS`         | Serve Prometheus metrics on a separate port |
| `GUARDPOST_METRICS_PORT`           | Metrics port (default `9100`)          |
| `GUARDPOST_METRICS_HOST`           | Metrics bind address (default: the API `--host`; `127.0.0.1` outside the CLI) |
| `GUARDPOST_ENABLE_SMTP`            | Enable SMTP verification               |
| `GUARDPOST_ENABLE_PROXY_DETECTION` | Enable VPN/proxy detection             |
| `GUARDPOST_ENABLE_AI`              | Enable AI scoring                      |
| `GUARDPOST_ENABLE_PATTERNS`        | Enable pattern detection               |
| `GUARDPOST_ENABLE_ENRICHMENT`      | Enable Gravatar + HIBP                 |
| `OPENROUTER_API_KEY`               | OpenRouter API key for AI scoring      |
| `IPINFO_TOKEN`                     | IPinfo.io token for proxy detection    |
| `GUARDPOST_MAXMIND_DB`             | Path to MaxMind GeoLite2 ASN .mmdb     |
| `HIBP_API_KEY`                     | Have I Been Pwned API key              |
| `GUARDPOST_TRUSTED_EXTRA_DOMAINS`  | Comma-separated deployment-specific domains to trust (e.g. `factory.bot,deleted.local`), on top of the shared trusted list |

### Client IP behind a reverse proxy

`X-Forwarded-For` is ignored unless the direct peer is listed in
`GUARDPOST_TRUSTED_PROXIES` (or `guardpost serve --trusted-proxies`). When it
is, Guardpost walks the header right to left and takes the first hop that is not
a trusted proxy, so a client cannot choose its rate-limit key by sending its own
header. With nothing configured, the TCP peer address is the client. uvicorn's
own proxy-header rewriting is disabled by `guardpost serve` so this is the only
place the client IP is derived.

### Metrics

```bash
guardpost serve --enable-metrics --metrics-port 9100   # or GUARDPOST_ENABLE_METRICS=1
curl http://127.0.0.1:9100/metrics
```

Metrics are served by a separate listener, not by the API app: `/metrics` on the
API port returns 404. In Docker the listener binds inside the container (the
image runs with `--host 0.0.0.0`) and the port is not `EXPOSE`d; scrape it over
the internal network and never publish it. Request latency is labelled by route
template (`/api/v1/check`), never by the raw path. Requires the `metrics` extra
(included in `server` and in the Docker image).

### Storage Backends

| Backend          | Install extra                  | Use case                |
| ---------------- | ------------------------------ | ----------------------- |
| SQLite (default) | —                              | Single instance         |
| Redis            | included in Docker image       | Distributed, production |
| MongoDB          | `pip install -e ".[mongo]"`    | Horizontal scaling      |
| PostgreSQL       | `pip install -e ".[postgres]"` | Existing infra          |

## Development

```bash
git clone https://github.com/Superposition-Labs/guardpost
cd guardpost
pip install -e ".[dev]"
pytest
```

## License

MIT
