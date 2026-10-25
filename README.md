<p align="center">
  <img src=".github/assets/guardpost-header.jpg" alt="Guardpost header" width="100%" />
</p>

# Guardpost

Self-hosted signup abuse detection that several apps can share. An app sends each signup to
`POST /api/v2/check` and gets back a decision (`allow`, `degrade` or `block`), the reasons in
`kind:detail` form, and the exact perks to withhold. Guardpost prefers silent degradation to hard
blocking, so abusers cannot learn which signal caught them.

One instance runs per data jurisdiction. Tenants (apps) on an instance share network and domain
intel (IP and /24 reputation, disposable domains, MX) and nothing else. Bans, accounts, device and
same-person matches and referrals stay per tenant, stored as keyed hashes. No email is ever written
to disk.

## Features

- **Server-side signup rules** (`/api/v2/check`), ported from Factory v2 with the same order,
  windows and thresholds, and pinned by [parity vectors](parity/vectors.json):
  - email gates: format, typo (`EMAIL_TYPO_SUSPECTED` with a suggestion), undeliverable domain,
    ban, alias collision;
  - email flags: about 9,980 disposable domains (the community list plus Guardpost's own,
    refreshed weekly), throwaway keywords, MX infrastructure fingerprinting, role accounts (43 core
    prefixes and 157 extended), dotted-Gmail noise, multiple `+` aliases, the RU `.ua` rule,
    homographs and null MX;
  - shared IP and /24 reputation (graylist, blacklist, `subnet_burst`) with per-tenant overrides,
    shown to each tenant as a status only (no counts from other tenants' signups);
  - device repeat (the same fingerprint on the same /24), same person (the same IP and device, or
    the same name in any script on the same network or device), and referral flags (same IP,
    referrer velocity).
- **Three tiers**: `hard` blocks, `soft` degrades and `weak` only scores. Any reason can be
  re-tiered per tenant. The actions are `no_welcome_credits`, `no_referral_attribution`,
  `no_referral_payouts` and `retract_referral_code`.
- **An account ledger per tenant**, pseudonymous (HMACs under a per-tenant key), with lifecycle
  events, bans, backfill imports, idempotent checks and commits, and per-tenant stats.
- **Multi-tenant**: API keys with scopes, per-tenant config and rate limits, and a CLI for tenants
  and keys, rotation included.
- **Clients**: Python (sync and async) and TypeScript (zero dependencies). Both retry, time out and
  can fail open.
- **Operations**: SQLite (WAL) with Litestream, nightly snapshots, a restore drill, Prometheus
  metrics on a separate port, and a compose kit per region.
- **The v1 API** (`/api/v1/*`) still works: email validation, IP reputation, SMTP verification,
  VPN/proxy detection, AI scoring, pattern detection and enrichment (each one opt-in).

## Documentation

| Guide | For |
| ----- | --- |
| [docs/INTEGRATION.md](docs/INTEGRATION.md) | App developers: evaluate vs commit, shadow → enforce, failing open and timeouts, idempotency, `occurred_at`, events, backfill, examples |
| [docs/RULES.md](docs/RULES.md) | Every reason with its tier, detail and evidence; actions; tenant settings; Factory equivalents and known divergences |
| [docs/PRIVACY.md](docs/PRIVACY.md) | What is hashed and what is plaintext, retention, data jurisdiction, losing `GUARDPOST_SECRET` |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Operators: every environment variable, tenants and keys, migrations, backups, the restore drill, metrics, upgrades, moving off the 0.2 sidecar |
| [clients/ts](clients/ts) | The TypeScript client |
| [`openapi/guardpost.json`](openapi/guardpost.json) | The API contract (CI fails when it drifts) |

## Quick start

Run an instance with the deploy kit (Docker, a throwaway secret, no replication). The published
image is amd64; on Apple silicon, build one with `docker build -t guardpost:local .` and add
`GUARDPOST_IMAGE=guardpost:local` to `.env`.

```bash
git clone https://github.com/Superposition-Labs/guardpost
cd guardpost/deploy
docker network create factory_network
printf 'GUARDPOST_SECRET=%s\nGUARDPOST_LEGACY_TENANT=demo\n' "$(openssl rand -hex 32)" > .env
docker compose run --rm --entrypoint guardpost guardpost migrate
docker compose run --rm --entrypoint guardpost guardpost key create --tenant demo --label quickstart --scopes check,lifecycle,dashboard
docker compose -f compose.yml -f compose.dashboard.yml up -d
```

`key create` prints the key once. The API now answers on `http://127.0.0.1:8200`, and as
`http://guardpost:8000` to containers on `factory_network`. Evaluate and record a signup:

```bash
curl -s http://127.0.0.1:8200/api/v2/check \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -H "Idempotency-Key: signup:u_1" \
  -d '{"mode": "commit", "email": "someone@mailinator.com", "ip": "203.0.113.7",
       "device": {"user_agent": "Mozilla/5.0", "accept_language": "en"}, "account": {"id": "u_1"}}'
```

```json
{"decision": "degrade", "soft_reasons": ["disposable_domain", "suspicious_domain_keyword"],
 "actions": ["no_welcome_credits", "no_referral_attribution", "no_referral_payouts"], "...": "..."}
```

For production (Litestream, backups, RU specifics), follow [docs/OPERATIONS.md](docs/OPERATIONS.md).

### Python client

```bash
pip install "guardpost-server[client] @ git+https://github.com/Superposition-Labs/guardpost"
```

```python
from guardpost.client import GuardpostClient

with GuardpostClient("http://127.0.0.1:8200", api_key=KEY, timeout=2.0) as gp:
    result = gp.check_v2(mode="commit", email=email, ip=ip, account={"id": user_id},
                         idempotency_key=f"signup:{user_id}")
    if result.decision == "block":
        refuse(result.block_code, result.suggestion)

    verdict = gp.fail_open(None).check_v2(email=email, ip=ip)
```

`fail_open(None)` returns `None` instead of raising when Guardpost is slow or down.
`AsyncGuardpostClient` has the same methods, awaitable. The 0.2 dict methods (`check`,
`ban_email`, ...) still work and emit a DeprecationWarning.

### TypeScript client

```ts
import { GuardpostClient, failOpen } from "@superposition-labs/guardpost";

const gp = new GuardpostClient({ baseUrl: "http://guardpost:8000", apiKey: KEY, timeoutMs: 2000 });
const result = await gp.checkV2({ mode: "commit", email, ip, account: { id: userId } }, { idempotencyKey: `signup:${userId}` });
const verdict = await failOpen(gp.checkV2({ email, ip }, { totalTimeoutMs: 1500 }), null);
```

It is not on npm yet: vendor [`clients/ts/dist`](clients/ts/dist) (ESM and `.d.ts`, no
dependencies).

### CLI

```bash
pip install -e ".[server]"
guardpost check user@mailinator.com --ip 203.0.113.7
guardpost serve --db ./guardpost.db
guardpost tenant create shop --region global
guardpost key create --tenant shop --label shop-prod --scopes check,lifecycle,dashboard
```

[docs/OPERATIONS.md](docs/OPERATIONS.md#tenants-and-keys) lists the admin commands (`migrate`,
`tenant`, `key`, `ip`, `ip-reputation`, `purge`).

## API

A running server serves OpenAPI docs at `/docs`.

### v2 (tenants and the ledger)

v2 needs SQLite and `GUARDPOST_SECRET`; without them every v2 route answers 503.

| Method         | Path                                       | Scope       | Description |
| -------------- | ------------------------------------------ | ----------- | ----------- |
| `POST`         | `/api/v2/check`                            | `check`     | Evaluate a signup (`mode: evaluate`, kept 1 h), or evaluate and record it (`mode: commit`) |
| `POST`         | `/api/v2/accounts`                         | `check`     | Commit an evaluated check: `{check_id, account_id}` |
| `GET`          | `/api/v2/accounts/{id}`                    | `dashboard` | One account's ledger state |
| `POST`         | `/api/v2/accounts/{id}/events`             | `lifecycle` | `created`, `deleted`, `banned`, `unbanned`, `paid`, `flagged`, `unflagged`, `referral_code_retracted`, `referral_code_restored` |
| `PUT`/`DELETE` | `/api/v2/bans`                             | `lifecycle` | Ban or unban an address (`email` or `email_sha256`) |
| `PUT`/`DELETE` | `/api/v2/ip-overrides/{ip_or_cidr}`        | `lifecycle` | Per-tenant `allow`/`block` for an address or IPv4 /24 |
| `POST`         | `/api/v2/import/{accounts,bans,referrals}` | `backfill`  | Upsert up to 1,000 rows |
| `POST`         | `/api/v2/admin/ip-reputation/import`       | `admin`     | Merge rows into the shared IP table |
| `GET`          | `/api/v2/stats`                            | `dashboard` | Decisions, reason histogram, degraded-then-paid, latency |

### v1

| Method   | Path                      | Description                          |
| -------- | ------------------------- | ------------------------------------ |
| `POST`   | `/api/v1/check`           | Full registration check (email + IP) |
| `POST`   | `/api/v1/email/validate`  | Email-only validation                |
| `POST`   | `/api/v1/email/smtp`      | SMTP mailbox verification            |
| `POST`   | `/api/v1/ip/check`        | IP reputation check                  |
| `POST`   | `/api/v1/ip/record`       | Record a registration from an IP     |
| `POST`   | `/api/v1/ip/proxy`        | VPN/proxy/datacenter detection       |
| `POST`   | `/api/v1/ai/score`        | AI email risk scoring                |
| `POST`   | `/api/v1/ai/score/batch`  | Batch AI scoring                     |
| `GET`    | `/api/v1/patterns/report` | Registration pattern report          |
| `POST`   | `/api/v1/email/ban`       | Ban an email                         |
| `DELETE` | `/api/v1/email/ban`       | Unban an email                       |
| `GET`    | `/api/v1/stats`           | Aggregate statistics                 |
| `GET`    | `/api/v1/health`          | Health check                         |

Every v1 result also lists its reasons by tier (`hard_reasons`, `soft_reasons`, `weak_reasons`).
`is_suspicious` means a hard or soft reason, as it did before tiers existed.

## Storage backends

| Backend          | Install extra                  | Use |
| ---------------- | ------------------------------ | --- |
| SQLite (default) | none                           | The only backend with tenancy and v2; replicated with Litestream |
| Redis            | `redis` (in the Docker image)  | v1 only, single tenant; or rate limiting only, next to SQLite (`GUARDPOST_STORAGE=sqlite`) |
| MongoDB          | `mongo`                        | v1 only, single tenant |
| PostgreSQL       | `postgres`                     | v1 only, single tenant |

The root `docker-compose.yml` is the single-tenant Redis Stack setup from 0.2. `deploy/` is the
multi-tenant deployment.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check guardpost/ tests/ scripts/
python scripts/export_openapi.py
scripts/smoke.sh
```

After an API change, `export_openapi.py` regenerates `openapi/guardpost.json` (CI runs it with
`--check`). The TypeScript client then needs `npm run generate && npm run build` in `clients/ts`
(see its README). `scripts/smoke.sh` boots the deploy kit on a local Docker and exercises it end
to end; `SMOKE_LITESTREAM=1` adds replication and the restore drill.

## License

MIT
