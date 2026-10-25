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

### Reason tiers

Every reason in a `/api/v1/check` result is also listed in exactly one tier:

| Tier   | Field          | Effect                                    | Default members |
| ------ | -------------- | ----------------------------------------- | --------------- |
| `hard` | `hard_reasons` | block                                     | none yet |
| `soft` | `soft_reasons` | degrade: allow, deny bonuses              | everything not listed elsewhere, incl. `subnet_burst` |
| `weak` | `weak_reasons` | raise `risk_score` only                   | `gibberish_domain`, `relay_domain`, `role_account_extended`, `homograph_domain`, `null_mx` |

`is_suspicious` is `hard_reasons or soft_reasons` (or a banned email / bad IP),
so it means what it meant before tiers existed. Overrides per reason kind:
`Guardpost(reason_tiers={"typo_domain": "hard"})`. A `typo_domain` result also
carries `suggested_domain` and `typo_source` (`map`, `tld` or `numeric`).

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

OpenAPI docs at `/docs` when the server is running; the committed contract is
[`openapi/guardpost.json`](openapi/guardpost.json) (CI fails when it drifts:
`python scripts/export_openapi.py`).

### API v2: server-side signup rules and the account ledger

v2 runs Factory v2's signup rules on the server, in the same order, against a
per-tenant pseudonymous ledger (needs SQLite and `GUARDPOST_SECRET`; otherwise
every `/api/v2` route answers 503).

| Method          | Path                                   | Scope       | Description |
| --------------- | -------------------------------------- | ----------- | ----------- |
| `POST`          | `/api/v2/check`                        | `check`     | Evaluate a signup (`mode: evaluate`, kept 1 h) or evaluate and record it (`mode: commit`) |
| `POST`          | `/api/v2/accounts`                     | `check`     | Commit an evaluated check: `{check_id, account_id}` |
| `GET`           | `/api/v2/accounts/{id}`                | `dashboard` | One account's ledger state |
| `POST`          | `/api/v2/accounts/{id}/events`         | `lifecycle` | `created`, `deleted`, `banned`, `unbanned`, `paid`, `flagged`, `unflagged`, `referral_code_retracted`, `referral_code_restored` |
| `PUT`/`DELETE`  | `/api/v2/bans`                         | `lifecycle` | Ban or unban an address (`email` or `email_sha256`) |
| `PUT`/`DELETE`  | `/api/v2/ip-overrides/{ip_or_cidr}`    | `lifecycle` | Per-tenant `allow`/`block` for an address or IPv4 /24 |
| `POST`          | `/api/v2/import/{accounts,bans,referrals}` | `backfill` | Upsert up to 1,000 rows |
| `POST`          | `/api/v2/admin/ip-reputation/import`   | `admin`     | Merge rows into the shared IP table |
| `GET`           | `/api/v2/stats`                        | `dashboard` | Decisions, reason histogram, degraded-then-paid, latency |

A check returns `decision` (`allow`, `degrade`, `block`), the reasons in
Factory's `kind:detail` form with their tier and evidence (the tenant's own
account ids, never an email), `block_code` (Factory v2's 400s:
`EMAIL_TYPO_SUSPECTED`, `EMAIL_DOMAIN_UNDELIVERABLE`, `EMAIL_BANNED`,
`EMAIL_ALIAS_EXISTS`, `IP_BLACKLISTED`, ...), `actions` (`no_welcome_credits`,
`no_referral_attribution`, `no_referral_payouts`, `retract_referral_code`) and
the referral verdict. Send `Idempotency-Key` (or `idempotency_key`): a replay
returns the identical result for 24 hours. `occurred_at` must be within 15
minutes of the server clock unless the key has the `backfill` scope.
[`parity/vectors.json`](parity/vectors.json) pins the rules against Factory v2.

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
| `GUARDPOST_API_KEY`                | The legacy single API key (key id `legacy`, scopes `legacy,check,dashboard`) |
| `GUARDPOST_LEGACY_TENANT`          | Tenant the legacy key and pre-0.3 data belong to (default `default`) |
| `GUARDPOST_ALLOW_OPEN`             | `1` = serve unauthenticated when no API key exists at all (development only; otherwise boot is refused) |
| `GUARDPOST_SECRET`                 | Instance secret for per-tenant keyed hashes. Back it up separately. Required by `/api/v2`; when it is first set, bans are re-keyed to HMACs and the database is tied to it (a different or missing secret then refuses to boot). Unset: a generated one is kept in the database and v2 is disabled |
| `GUARDPOST_ALLOW_DB_SECRET`        | `1` = let `/api/v2` run on the generated database secret (tests and development only) |
| `GUARDPOST_PURGE_INTERVAL`         | Seconds between in-process retention purges of the v2 ledger (default `3600`; `0` = off, run `guardpost purge`) |
| `GUARDPOST_STORAGE`                | `sqlite` or `redis` (default: `redis` when `GUARDPOST_REDIS_URL` is set, else `sqlite`) |
| `GUARDPOST_MULTI_TENANT`           | `1` = refuse to boot on a backend without tenancy instead of running single-tenant |
| `GUARDPOST_DB_PATH`                | SQLite database path                   |
| `GUARDPOST_REDIS_URL`              | Redis URL: the storage backend, or with `GUARDPOST_STORAGE=sqlite` rate limiting only |
| `GUARDPOST_RATE_LIMIT`             | Default max requests/min per tenant, and per IP for unauthenticated traffic (0 = disabled) |
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
| `GUARDPOST_TRUSTED_EXTRA_DOMAINS`  | Comma-separated deployment-specific domains to trust (e.g. `factory.bot,deleted.local`), on top of the shared trusted list. Instance default; a tenant's `email.trusted_extra_domains` replaces it |

### Tenants and API keys

One instance serves several tenants (apps). Tenants share network and domain
intel — IP and /24 reputation, disposable domains, MX — and nothing else: bans,
stats, the timeline, the dashboard and the pattern report are per tenant. The
API key decides the tenant; no request field can choose another one.

```bash
guardpost migrate                                   # also runs automatically on boot
guardpost tenant create factory --name Factory --region ru
guardpost key create --tenant factory --label factory-v2 --scopes check,lifecycle --expires 90d
guardpost key list --tenant factory
guardpost key rotate <key-id> --grace 7d            # new key printed once; old one expires in 7 days
guardpost key revoke <key-id>
guardpost tenant config-set factory email.reason_tiers.typo_domain=hard rate_limit_per_minute=600
guardpost tenant show factory                       # effective config + keys (never the secrets)
guardpost ip whitelist --global 203.0.113.0/24      # shared by every tenant
guardpost ip-reputation import rows.jsonl           # merge Factory v2 ip_reputation rows (shared)
guardpost purge                                     # retention now (also hourly in process)
```

- Keys look like `gpk_<id>_<secret>`. Only their SHA-256 is stored, and
  `key create` / `key rotate` print the key once, alone on stdout. Send it as
  `X-Api-Key`, `Authorization: Bearer`, or the dashboard's Basic password.
- Scopes: `check` (evaluation routes), `lifecycle` (bans, `/ip/record`, v2
  events and overrides), `dashboard` (stats, timeline, pattern report,
  dashboard), `backfill` (v2 imports and old `occurred_at`), `admin` (the
  shared IP import). The legacy key's `legacy` scope covers every v1 route but
  grants nothing on v2, where only its explicit `check` and `dashboard` count.
- `GUARDPOST_API_KEY` keeps working unchanged for v1 clients: each boot hashes
  it into `api_keys` as key `legacy` for `GUARDPOST_LEGACY_TENANT`, and revokes
  that row when the variable is unset.
- With no key at all the server refuses to start unless `GUARDPOST_ALLOW_OPEN=1`.
- Tenant config (`guardpost tenant config-set`, validated; unknown keys rejected):
  `region`, `region_rules.ua_domain` (soft-flag every `*.ua` address, trusted
  or not; on by default for region `ru`), `email.trusted_extra_domains`,
  `email.reason_tiers`, `rate_limit_per_minute` (one bucket for all the
  tenant's keys), `retention.signals_days` (35), `retention.events_days`
  (400), and the v2 rule windows `device_repeat`, `same_person`, `referral`.
- Privacy: no email is written to disk. Per-tenant activity is kept as events
  holding an HMAC of the IP under a tenant key derived from `GUARDPOST_SECRET`.
  The v2 ledger stores only HMACs of the normalized email, device fingerprint,
  IP, /24 and name key; plaintext IPs live only in the shared reputation
  table, which has no account link. Retention: ledger signals 35 days, checks
  24 hours, events 400 days, clean idle IP rows 90 days.
  Pattern analysis runs on an in-memory window, which starts empty after a
  restart.
- Tenancy needs the SQLite backend. On Redis Guardpost runs single-tenant (one
  key, one ban list); set `GUARDPOST_STORAGE=sqlite` to keep Redis for rate
  limiting only.

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
| SQLite (default) | —                              | Single instance; the only backend with tenancy |
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
