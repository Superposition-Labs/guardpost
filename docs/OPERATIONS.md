# Operating Guardpost

Running one Guardpost instance per region with the kit in [`deploy/`](../deploy): first boot,
tenants and keys, configuration, migrations, backups and the restore drill, metrics, upgrades, and
the move from the 0.2 sidecar in Factory v1's compose files.

Command blocks below are meant to be pasted as they are: they hold no comments.

- [Layout](#layout)
- [First boot](#first-boot)
- [Tenants and keys](#tenants-and-keys)
- [Configuration reference](#configuration-reference)
- [Migrations](#migrations)
- [Backups](#backups)
- [Restore drill and restoring](#restore-drill-and-restoring)
- [Metrics and health](#metrics-and-health)
- [Upgrading](#upgrading)
- [Upgrading 0.2 to 0.3](#upgrading-02-to-03)
- [Migrating from the 0.2 sidecar in Factory's compose](#migrating-from-the-02-sidecar-in-factorys-compose)
- [Troubleshooting](#troubleshooting)

## Layout

Each region runs Guardpost as its own compose project, `guardpost`, next to the app's stack:

| Path on the host | From the repo | What |
| ---------------- | ------------- | ---- |
| `/opt/guardpost/compose.yml` | `deploy/compose.yml` | guardpost (+ the `litestream` profile) |
| `/opt/guardpost/compose.dashboard.yml` | `deploy/compose.dashboard.yml` | optional `127.0.0.1:8200` for the dashboard |
| `/opt/guardpost/litestream.yml` | `deploy/litestream.yml` | replication config (generic S3) |
| `/opt/guardpost/scripts/` | `deploy/scripts/` | `backup-snapshot.sh`, `restore-drill.sh` |
| `/opt/guardpost/.env` | `deploy/env.example` | every setting and secret (root, `chmod 600`) |
| docker volume `guardpost_data` | | `/data/guardpost.db` (SQLite, WAL) |

- The container joins the app's external network (`GUARDPOST_NETWORK`, default `factory_network`)
  with the alias `guardpost`: apps call `http://guardpost:8000`.
- Nothing is published. `compose.dashboard.yml` adds `127.0.0.1:8200` for
  `ssh -L 8200:127.0.0.1:8200 <host>`; enable it with
  `COMPOSE_FILE=compose.yml:compose.dashboard.yml` in `.env`. Metrics (9100) and Litestream's
  metrics (9090) are reachable on the docker network only.
- One container, one process, one uvicorn worker. Never scale it: SQLite takes one writer, and the
  retention purge runs in process.
- Run compose from `/opt/guardpost` so it reads `.env` (`COMPOSE_PROFILES`, `COMPOSE_FILE`).

Install or update the kit:

```bash
sudo mkdir -p /opt/guardpost/scripts
sudo cp deploy/compose.yml deploy/compose.dashboard.yml deploy/litestream.yml /opt/guardpost/
sudo cp deploy/scripts/*.sh /opt/guardpost/scripts/
sudo test -f /opt/guardpost/.env || sudo install -m 600 deploy/env.example /opt/guardpost/.env
```

RU: GHCR and Docker Hub pulls from Russia fail, so set `GUARDPOST_IMAGE` and `LITESTREAM_IMAGE` to
mirrored copies (pushed from outside Russia, e.g. with `skopeo copy`, as Factory v2's `deploy-ru.yml`
does for its images) and keep the tags identical.

## First boot

On a fresh instance (no 0.2 data; for that, see [the migration](#migrating-from-the-02-sidecar-in-factorys-compose)):

1. Fill in `/opt/guardpost/.env`: a new `GUARDPOST_SECRET` (`openssl rand -hex 32`, stored in the
   region's secret store and offline; see [PRIVACY.md](PRIVACY.md#guardpost_secret)),
   `GUARDPOST_LEGACY_TENANT=factory`, the `LITESTREAM_*` block, and, while Factory v1 still calls
   Guardpost, `GUARDPOST_API_KEY` = v1's key.
2. Create the schema and the tenant, and set its region (`ru` or `global`; `ru` turns on the
   `ua_domain` rule). `migrate` creates the legacy tenant `factory` itself:

   ```bash
   cd /opt/guardpost
   docker compose pull
   docker compose run --rm --entrypoint guardpost guardpost migrate
   docker compose run --rm --entrypoint guardpost guardpost tenant config-set factory region=ru
   ```

3. Create the app's key (printed once, alone on stdout: store it straight into the app's secrets).
   The server refuses to start with no usable key at all, so create it before `up` unless
   `GUARDPOST_API_KEY` is set:

   ```bash
   docker compose run --rm --entrypoint guardpost guardpost key create --tenant factory --label factory-v2-ru --scopes check,lifecycle,dashboard
   ```

4. Start, then check:

   ```bash
   docker compose up -d
   docker compose ps
   docker compose exec guardpost guardpost tenant show factory
   docker compose logs --tail 20 litestream
   ```

5. Install the nightly snapshot ([Backups](#backups)) and run the [restore drill](#restore-drill-and-restoring) once.

For the Global region use `region=global` and a label such as `factory-v2-global`.

## Tenants and keys

The CLI runs inside the container and acts on the live database (changes apply to the next request):

```bash
cd /opt/guardpost
docker compose exec guardpost guardpost tenant list
docker compose exec guardpost guardpost tenant show factory
docker compose exec guardpost guardpost tenant create shop --name Shop --region global
docker compose exec guardpost guardpost tenant config-set factory rate_limit_per_minute=600 email.reason_tiers.typo_domain=hard
docker compose exec guardpost guardpost tenant set-status shop suspended
docker compose exec guardpost guardpost key create --tenant factory --label factory-backfill --scopes backfill,admin --expires 7d
docker compose exec guardpost guardpost key list --tenant factory
docker compose exec guardpost guardpost key rotate 9bbd0d372969 --grace 7d
docker compose exec guardpost guardpost key revoke 9bbd0d372969
docker compose exec guardpost guardpost ip whitelist --global 203.0.113.0/24
docker compose exec guardpost guardpost purge
```

- Keys are `gpk_<id>_<secret>`; only their sha256 is stored. Scopes: `check`, `lifecycle`,
  `dashboard`, `backfill`, `admin` (see [INTEGRATION.md](INTEGRATION.md#concepts)). Give every
  deployment and tool its own key; give backfill keys an `--expires`.
- **Rotating an app key**: `key rotate <id> --grace 7d` prints a new key with the same tenant,
  scopes and label, and makes the old one expire after the grace period. Deploy the new key to the
  app within it. `key revoke` ends a key at once.
- **The legacy key** (`GUARDPOST_API_KEY`, key id `legacy`) is re-synced from the environment on
  every boot: change it in `.env` and in the caller at the same time and restart; unset it to revoke
  it. To retire it, give v1 a `gpk_` key with `check,dashboard` and drop the variable.
- **`GUARDPOST_SECRET` cannot be rotated** without a re-backfill ([PRIVACY.md](PRIVACY.md#guardpost_secret)).
- `tenant config-set` validates and rejects unknown keys; `tenant show` prints the effective config
  ([RULES.md](RULES.md#per-tenant-settings) lists the settings).

## Configuration reference

Every variable the server reads. The deploy kit sets the ones marked "kit" itself; the rest come
from `.env` through `compose.yml`.

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `GUARDPOST_SECRET` | none | Instance secret for every per-tenant HMAC. Required by `/api/v2` (503 without it). Once set, the database is tied to it and another or a missing secret refuses to boot |
| `GUARDPOST_LEGACY_TENANT` | `default` (kit: `factory`) | Tenant of `GUARDPOST_API_KEY` and of pre-0.3 data. Recorded at the first migration; later changes do not move migrated data |
| `GUARDPOST_API_KEY` | none | The 0.2 single key (key id `legacy`, scopes `legacy,check,dashboard`); unset revokes it |
| `GUARDPOST_ALLOW_OPEN` | off | `1` serves unauthenticated when no key exists at all (development only; otherwise boot is refused) |
| `GUARDPOST_ALLOW_DB_SECRET` | off | `1` lets `/api/v2` run on the generated database-stored secret (tests only) |
| `GUARDPOST_STORAGE` | `redis` with a Redis URL, else `sqlite` (kit: `sqlite`) | Storage backend; only SQLite has tenancy and v2 |
| `GUARDPOST_MULTI_TENANT` | off (kit: `1`) | Refuse to boot on a backend without tenancy |
| `GUARDPOST_DB_PATH` | `~/.guardpost/guardpost.db` (image: `/data/guardpost.db`) | SQLite database path |
| `GUARDPOST_REDIS_URL` | none | Redis: the storage backend, or with `GUARDPOST_STORAGE=sqlite` rate limiting only |
| `GUARDPOST_PURGE_INTERVAL` | `3600` | Seconds between in-process retention purges (`0`: off; run `guardpost purge`) |
| `GUARDPOST_RATE_LIMIT` | `0` | Requests per minute per tenant (and per IP when unauthenticated); a tenant's `rate_limit_per_minute` overrides it |
| `GUARDPOST_TRUSTED_PROXIES` | none | CIDRs of proxies allowed to set `X-Forwarded-For`; without any, the header is ignored |
| `GUARDPOST_TRUSTED_EXTRA_DOMAINS` | none | Comma-separated app-internal domains treated as trusted (instance default; a tenant's `email.trusted_extra_domains` replaces it) |
| `GUARDPOST_CORS_ORIGINS` | none | Comma-separated origins allowed by CORS (none: no browser access) |
| `GUARDPOST_ENABLE_METRICS` | off (kit: `1`) | Prometheus metrics on a separate listener |
| `GUARDPOST_METRICS_PORT` | `9100` | Metrics port |
| `GUARDPOST_METRICS_HOST` | the API `--host` (`127.0.0.1` outside the CLI; image `0.0.0.0`) | Metrics bind address |
| `GUARDPOST_ENABLE_PATTERNS` | off | v1 pattern report (in-memory window) |
| `GUARDPOST_ENABLE_SMTP` | off | v1 SMTP mailbox verification |
| `GUARDPOST_ENABLE_PROXY_DETECTION` | off | v1 VPN/proxy/datacenter detection |
| `GUARDPOST_MAXMIND_DB` | none | MaxMind GeoLite2 ASN `.mmdb` path (proxy detection) |
| `IPINFO_TOKEN` | none | IPinfo token (proxy detection) |
| `GUARDPOST_ENABLE_AI` | off | v1 AI email scoring (needs `OPENROUTER_API_KEY`) |
| `GUARDPOST_AI_MODEL` | `openai/gpt-4o-mini` | OpenRouter model for AI scoring |
| `OPENROUTER_API_KEY` | none | OpenRouter key |
| `GUARDPOST_ENABLE_ENRICHMENT` | off | v1 Gravatar + Have I Been Pwned enrichment |
| `HIBP_API_KEY` | none | Have I Been Pwned key |

The image is built with `GUARDPOST_VERSION` (a build argument, passed to hatch-vcs as
`SETUPTOOLS_SCM_PRETEND_VERSION`); `/api/v1/health` reports it.

Deploy kit only (`compose.yml`, the scripts):

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `COMPOSE_PROFILES` | none (env.example: `litestream`) | `litestream` runs the replication sidecar |
| `COMPOSE_FILE` | `compose.yml` | add `compose.dashboard.yml` for the loopback port |
| `GUARDPOST_IMAGE` | `ghcr.io/superposition-labs/guardpost:0.3` | the server image (RU: the mirror) |
| `GUARDPOST_NETWORK` | `factory_network` | the app's external docker network |
| `GUARDPOST_VOLUME` | `guardpost_data` | the data volume's name |
| `GUARDPOST_LOCAL_PORT` | `8200` | loopback port of `compose.dashboard.yml` |
| `LITESTREAM_IMAGE` | `litestream/litestream:0.5.17` | (RU: the mirror) |
| `LITESTREAM_BUCKET`, `LITESTREAM_PATH` (`guardpost`) | none | replica bucket and prefix |
| `LITESTREAM_ENDPOINT`, `LITESTREAM_REGION` (`auto`) | none | S3 endpoint: R2 `https://<account>.r2.cloudflarestorage.com` + `auto`; Yandex `https://storage.yandexcloud.net` + `ru-central1` |
| `LITESTREAM_ACCESS_KEY_ID`, `LITESTREAM_SECRET_ACCESS_KEY` | none | a key scoped to that bucket |
| `LITESTREAM_SIGN_PAYLOAD`, `LITESTREAM_REQUIRE_CONTENT_MD5` | Litestream's | `true` for Yandex Object Storage |
| `LITESTREAM_HEARTBEAT_URL` | none | dead-man's switch pinged every 5 minutes while replication is healthy |
| `SNAPSHOT_DIR` | `/opt/guardpost/snapshots` | where `backup-snapshot.sh` keeps snapshots |
| `SNAPSHOT_KEEP_DAYS` | `14` | local snapshot retention |
| `SNAPSHOT_AGE_RECIPIENT` | none | age public key: encrypt snapshots |
| `SNAPSHOT_RCLONE_DEST` | none | rclone `remote:path` for an off-host copy |
| `GUARDPOST_DIR` | `/opt/guardpost` | where the scripts find `compose.yml` and `.env` |

## Migrations

Migrations live in `guardpost/storage/migrations/sqlite/` and run on every boot, each in its own
`BEGIN IMMEDIATE` transaction (a failed one rolls back whole). With `GUARDPOST_SECRET` set, the boot
also re-keys any unkeyed bans to HMACs once. To run them by hand, or see where a database stands:

```bash
cd /opt/guardpost
docker compose run --rm --entrypoint guardpost guardpost migrate --status
docker compose run --rm --entrypoint guardpost guardpost migrate
```

There is no down-migration. A database migrated by a newer release cannot be opened by an older
one: take a snapshot before every upgrade, and roll back by restoring it.

## Backups

Two independent layers, plus the secret:

1. **Litestream** (continuous). The `litestream` service replicates `/data/guardpost.db` to S3
   with a 1-second sync interval and 14 days of point-in-time restore (daily snapshots). Global:
   R2, e.g. Factory v2's bucket under the `guardpost/` prefix. RU: Yandex Object Storage in
   `ru-central1`. Use a key scoped to the bucket, a lifecycle rule as a backstop, and the
   heartbeat URL for an outside alert when replication stops.
2. **Nightly snapshot** (`scripts/backup-snapshot.sh`): `VACUUM INTO` a consistent copy inside the
   running container, `PRAGMA integrity_check`, gzip, age-encrypt when `SNAPSHOT_AGE_RECIPIENT` is
   set, keep `SNAPSHOT_KEEP_DAYS` days in `SNAPSHOT_DIR`, and copy off the host with rclone when
   `SNAPSHOT_RCLONE_DEST` is set (RU: a Russian store). It exits non-zero on any failure. Cron
   (`/etc/cron.d/guardpost-backup`):

   ```
   17 3 * * * root /opt/guardpost/scripts/backup-snapshot.sh >> /var/log/guardpost-backup.log 2>&1
   ```

3. **`GUARDPOST_SECRET`**, backed up separately from both (the region's secret store and offline).
   A backup without its secret holds only useless hashes plus the shared IP table; a backup with it
   can test guesses against the ledger.

## Restore drill and restoring

Run the drill after the first boot, after every upgrade, and monthly:

```bash
sudo /opt/guardpost/scripts/restore-drill.sh
```

It restores the Litestream replica into a throwaway copy in the data volume (the live database is
only read), then checks the copy inside the guardpost container: `integrity_check`, the schema
version against the live one, row counts side by side, and that the keyed data belongs to this
`GUARDPOST_SECRET`. It deletes the copy and exits 0 only if everything passed. Extra arguments go
to `litestream restore`, e.g. `-timestamp 2026-10-20T03:00:00Z`.

Restoring for real (the database is lost or corrupt):

```bash
cd /opt/guardpost
docker compose stop guardpost litestream
docker compose run --rm --no-deps litestream restore -config /etc/litestream.yml -o /data/guardpost.restored.db /data/guardpost.db
docker compose run --rm --no-deps --entrypoint sh guardpost -c "cd /data && mkdir -p broken && mv guardpost.db guardpost.db-wal guardpost.db-shm broken/ 2>/dev/null; mv guardpost.restored.db guardpost.db"
docker compose up -d
docker compose exec guardpost guardpost migrate --status
```

From a nightly snapshot instead: decrypt and gunzip it, `docker cp` it into the stopped container
as `/data/guardpost.db` (owned by uid 999), and start. Litestream continues from the restored
database. Restore only onto the same region's host, with the same `GUARDPOST_SECRET` (another secret
refuses to boot by design).

## Metrics and health

- `GET /readyz` (the healthcheck) and `/healthz` are unauthenticated; `GET /api/v1/health` needs a
  key and reports the version.
- Prometheus, on the app's network: `guardpost:9100/metrics` and `guardpost-litestream:9090/metrics`.
  `/metrics` on the API port is a 404 by design.

  ```yaml
  - job_name: guardpost
    static_configs:
      - targets: ["guardpost:9100"]
  - job_name: guardpost-litestream
    static_configs:
      - targets: ["guardpost-litestream:9090"]
  ```

- Useful series: `guardpost_request_duration_seconds{endpoint, status_code}` (by route template:
  latency and 5xx rate of `/api/v2/check`), `guardpost_rate_limit_hits_total`,
  `guardpost_checks_total` / `guardpost_detection_reason_total` (v1 checks), and Litestream's
  replication lag. `GET /api/v2/stats` gives per-tenant decisions, the reason histogram,
  degraded-then-paid and check latency p50/p95.
- Alert on: the container unhealthy, a missed Litestream heartbeat, a failed nightly snapshot (the
  log or cron mail), a 5xx rate above zero on `/api/v2/*`, and p95 check latency above 300 ms.

## Upgrading

Releases are tagged `vX.Y.Z` and publish `:X.Y.Z`, `:X.Y` and `:latest`; `main` publishes only
`:edge` and `:<sha>`. Pin the minor (`:0.3`) and move it on purpose:

```bash
cd /opt/guardpost
sudo /opt/guardpost/scripts/backup-snapshot.sh
docker compose pull guardpost
docker compose up -d guardpost
docker compose ps
sudo /opt/guardpost/scripts/restore-drill.sh
```

Read the release notes for migrations first: there is no downgrade (restore the snapshot instead).
RU: mirror the new tag before pulling.

## Upgrading 0.2 to 0.3

What changes for a 0.2 deployment:

- Migration `0002` adds tenants, API keys and per-tenant bans, moves the 0.2 data to
  `GUARDPOST_LEGACY_TENANT` and **drops the plaintext `registrations` table**, then VACUUMs so the
  dropped rows do not survive in free pages. (0.3.0 did not VACUUM. Its Docker image is not
  affected, because Debian's SQLite zeroes deleted content, but a pip install on another SQLite
  build may be: run `guardpost migrate --vacuum` with a later release on such a database.)
  `0003` adds the v2 ledger. With
  `GUARDPOST_SECRET` set, the bans are then re-keyed from sha256 to per-tenant HMACs.
- `/api/v1/*` keeps working with the same key (it becomes the legacy key of the legacy tenant).
- Boot is refused with no key at all (unless `GUARDPOST_ALLOW_OPEN=1`), with a changed or missing
  secret once one was used, and on Redis with `GUARDPOST_MULTI_TENANT=1`.

Rules:

1. **Copy the volume first.** The migration rewrites the database in place and 0.2 cannot open the
   result: the copy is the only rollback.
2. Set `GUARDPOST_SECRET` **and** `GUARDPOST_LEGACY_TENANT` before the first 0.3 boot or `migrate`.
   The legacy tenant is recorded at the first migration; data migrated to `default` stays there.
3. **No downgrade.** Roll back by restoring the copy and running 0.2 again.
4. Delete the copy once 0.3 is verified: it still holds the 0.2 plaintext registrations.

## Migrating from the 0.2 sidecar in Factory's compose

Factory v1 (Larp-Factory) runs Guardpost 0.2 as a `guardpost` service inside its own compose files
(`docker-compose.prod.yml` on Global, `docker-compose.yandex.yml` on RU): container
`factory_guardpost`, a project-scoped volume `<project>_guardpost_data`, port 8200 published, and
`depends_on: guardpost` on the backend. v1 calls `http://guardpost:8000` with `GUARDPOST_API_KEY`;
that does not change. Do one region at a time, in a maintenance window. The v1 benchmark never
gates signups, so v1 keeps working while the sidecar is down.

Before the window:

- Install the kit and fill in `/opt/guardpost/.env` ([Layout](#layout), [First boot](#first-boot)
  step 1): a new `GUARDPOST_SECRET`, `GUARDPOST_LEGACY_TENANT=factory`, `GUARDPOST_API_KEY` = the
  value v1 uses, the Litestream block, and on RU the mirrored images. Pull the images.
- Open the Larp-Factory PR that removes the `guardpost` service, the backend's
  `depends_on: guardpost` and the `guardpost_data` volume entry from both compose files (removing
  the entry does not delete the volume).
- Find the sidecar's volume:

  ```bash
  docker inspect factory_guardpost --format '{{range .Mounts}}{{.Name}} {{end}}'
  ```

In the window (`OLD` is the volume name printed above):

1. **Stop the sidecar.**

   ```bash
   docker stop factory_guardpost
   ```

2. **Copy the volume** into `guardpost_data`, leaving the original untouched as the rollback. The
   copy runs in the guardpost image (already pulled, mirrored on RU), as root so it can fix the
   ownership:

   ```bash
   OLD=larp-factory_guardpost_data
   cd /opt/guardpost
   docker compose run --rm --no-deps --user 0 --entrypoint sh -v "$OLD":/from:ro guardpost -c "cp -a /from/. /data/ && chown -R 999:999 /data && ls -la /data"
   ```

3. **Migrate** with `GUARDPOST_SECRET` and `GUARDPOST_LEGACY_TENANT` set (both come from `.env`):

   ```bash
   cd /opt/guardpost
   docker compose run --rm --entrypoint guardpost guardpost migrate
   docker compose run --rm --entrypoint guardpost guardpost migrate --status
   docker compose run --rm --entrypoint guardpost guardpost tenant config-set factory region=ru
   ```

   `migrate` prints the applied migrations and the number of re-keyed bans. Use `region=global` on
   the Global host.

4. **Start** the new instance and check it from v1's backend container, as v1 sees it:

   ```bash
   docker compose up -d
   docker compose ps
   docker exec factory_backend sh -c 'curl -fsS -H "X-Api-Key: $GUARDPOST_API_KEY" http://guardpost:8000/api/v1/health'
   ```

   (`factory_backend` is v1's backend container; `docker ps --format '{{.Names}}'` lists the names.)
   The health answer shows the 0.3 version. Then create Factory v2's key
   ([First boot](#first-boot) step 3) for later.

5. **Remove the sidecar from the app compose files in the same window**: merge and deploy the
   Larp-Factory PR, and remove the stopped container, so a later v1 deploy can never start a second
   container that answers to the alias `guardpost`:

   ```bash
   docker rm factory_guardpost
   ```

After the window: v1's logs show `[guardpost-benchmark] ... match=` again; `docker compose logs
litestream` shows replication; run the [restore drill](#restore-drill-and-restoring); install the
nightly snapshot cron; check that 8200 and 9100 are closed from outside. After a week, delete the
old volume (it holds 0.2's plaintext registrations): `docker volume rm "$OLD"`.

Rollback before step 5: `docker compose -f /opt/guardpost/compose.yml down`, then
`docker start factory_guardpost` (its volume was never touched). After step 5: also revert the
Larp-Factory PR.

Note that v1's `/api/v1/check` (with `record_ip`) and a v2 commit both bump the shared IP counters,
so never send the same signups through both: v1's benchmark and Factory v2's shadow serve
different traffic.

## Troubleshooting

| Symptom | Cause and fix |
| ------- | ------------- |
| Boot stops with `SecretMismatchError` | `GUARDPOST_SECRET` differs from (or is missing for) the one the keyed data was written with. Restore the right secret; never "fix" it with a new one ([PRIVACY.md](PRIVACY.md#guardpost_secret)) |
| Boot stops: "no API keys are configured" | Create a key with `docker compose run --rm --entrypoint guardpost guardpost key create ...`, or set `GUARDPOST_API_KEY` |
| `/api/v2/*` answers 503 | No `GUARDPOST_SECRET`, or a non-SQLite backend |
| `... needs migrating (N pending): run guardpost migrate` from the CLI | The CLI never migrates implicitly: run `migrate` (the server does it on boot) |
| Litestream restarts in a loop | Missing `LITESTREAM_*` values (it refuses an empty bucket or endpoint), wrong key scope, or for Yandex the signing flags. `docker compose logs litestream` |
| `sqlite3.OperationalError: attempt to write a readonly database` | Files in the volume not owned by uid 999 (a copy made as root): `chown -R 999:999` on the volume |
| An app gets 429 | The tenant's `rate_limit_per_minute` or `GUARDPOST_RATE_LIMIT`; the clients never retry 429 |
| Two containers answer `guardpost` | The 0.2 sidecar was started again by an app deploy: remove it (step 5 above) |
