# Privacy and data handling

What Guardpost stores about the people who sign up to a tenant's app, in what form, for how long,
where, and what happens if the instance secret is lost. It describes 0.3 and later with the SQLite
backend and `GUARDPOST_SECRET` set (the configuration in [`deploy/`](../deploy) and the only one
that serves `/api/v2`).

## Principles

- **No email is written to disk.** Not in the database, not in a replica, not in a snapshot, not in
  a log line (logs name at most the domain: `***@example.com`). The access log shows the calling
  app's container address and the route, which for events contains the tenant's account id.
- **Per-tenant pseudonyms.** Every per-person value is an HMAC under a key that belongs to one
  tenant on one instance. The same address or IP hashes differently in every tenant, so tenants
  cannot be joined on disk, and the database alone cannot be tested against a list of addresses.
- **Plaintext IPs only where they are shared, and never next to an account.** The shared IP
  reputation table holds addresses and /24 networks with counters and a status, and no link to
  any tenant or account.
- **Responses carry no personal data.** A check's evidence names the tenant's own opaque account
  ids and counts, never an email or an IP.

## What is hashed

`tk = HKDF-SHA256(GUARDPOST_SECRET, salt "guardpost-tenant-key", info "guardpost/tenant/<tenant id>/v<key version>")`

Each value is `HMAC-SHA256(tk, "<purpose>\0<value>")`:

| Value | Input before the HMAC | Where |
| ----- | --------------------- | ----- |
| email | sha256 hex of the alias-normalized address (Factory v2's `normalized_email_hash`); an app may send that hash instead of the address | `accounts.email_key`, `bans.email_hash` |
| device fingerprint | sha256 hex of `User-Agent\|Accept-Language` (Factory v2's `registration_fingerprint`) | `accounts.fp_key` |
| IP | the canonical address | `accounts.ip_key`, `referrals.ip_key`, `registration_events.ip_key` |
| network | the /24 (IPv4) or the address (IPv6), global addresses only | `accounts.net_key` |
| name | the normalized, script-folded, order-independent full name key | `accounts.name_key_h` |
| IP override target | the address or /24 | `ip_overrides` (matched, never listed) |
| request | the canonical request body | `checks.request_hmac` (idempotency) |

The user agent, accept-language, name and address themselves are never stored. An evaluated (not
yet committed) check keeps its IP sealed (encrypted and authenticated under `tk`, with the check id
as nonce) so a later commit can bump the shared counters; checks are deleted after 24 hours.

API keys are stored as sha256 of the key (256 bits of entropy, so no salt is needed) and compared in
constant time. The database records a fingerprint of `GUARDPOST_SECRET`, never the secret.

## What is plaintext

| Data | Why | Linked to a person? |
| ---- | --- | ------------------- |
| `ip_reputation`: addresses and /24s, registration counters, first and last registration time, status (`clean`/`graylisted`/`blacklisted`), its reason, whitelist flag | the network intel every tenant shares | no: no tenant, no account |
| tenants (id, name, config), API key ids, labels, scopes, expiry | administration | no |
| account ids and timestamps (created, deleted, banned, paid, flagged), decision, reason codes | the ledger | the tenant's own opaque ids only |
| free text in bans (`banned_by`, `reason`) and events (`reason`, `actor`) | audit | **only if the app puts personal data there: never send an email in these fields** |
| `tenant_counters`: per-tenant totals of v1 registrations | the v1 dashboard | no |

What another tenant can learn from the shared table: whether an address or /24 is graylisted or
blacklisted, and nothing more. The stored status reasons name counts (`5 suspicious
registrations`) that every tenant's signups produced, so responses carry the status only
(`graylisted_ip:graylisted`, null `signals.ip_reason` / `subnet_reason`). A tenant can ask for
the full text (`ip.reason_detail = full`); it gets it only while it is the instance's only active
tenant that has held a key, or when the operator sets `GUARDPOST_ALLOW_FULL_REASON_DETAIL=1`
([RULES.md](RULES.md#shared-ip-reason-detail)). The legacy tenant's v1 routes keep 0.2's strings.
Nothing in any response tells a tenant which other tenant's signups moved a counter.

With `GUARDPOST_ENABLE_PATTERNS` the v1 pattern report keeps a window of recent v1 registrations,
addresses included, in memory only: it is never written and starts empty after a restart. The v2
check does not use it.

## Retention

Applied hourly in process (`GUARDPOST_PURGE_INTERVAL`) and by `guardpost purge`. Per tenant
(`retention.signals_days`, `retention.events_days`):

| Data | Kept |
| ---- | ---- |
| device, IP, network and name keys of an account; the IP key of a referral; v1 registration events | 35 days after the signup, then nulled |
| the email key of a live account | while the account exists (it is the alias-collision and ban identity); erased at once by a `deleted` event |
| checks (evaluated, pending, idempotency records, sealed IPs) | 24 hours |
| lifecycle events | 400 days |
| bans | until lifted |
| shared IP rows that are clean, not whitelisted and idle | 90 days after the last registration |
| Litestream replica | 14 days of point-in-time history (`deploy/litestream.yml`) |
| nightly snapshots | `SNAPSHOT_KEEP_DAYS` (14) on the host, and the bucket's lifecycle rule off it |

A replica or snapshot can hold data for up to its own retention after the live database purged it.
Erasure requests: the app sends `deleted` (the email key goes at once); the remaining signals expire
at 35 days, and the replica's history at 14 days after that.

## Data jurisdiction

- **One instance per jurisdiction.** Global and RU each run their own Guardpost, database, secret,
  replica and snapshots. Nothing is synchronised between them, the shared IP reputation included,
  and a tenant's key works only on its own instance.
- **RU data stays in Russia.** The RU instance runs on the RU host; Litestream replicates to Yandex
  Object Storage (`ru-central1`) and snapshots go to a Russian store. The RU image is pulled from a
  mirror, but no data moves the other way. Do not point an RU replica or snapshot at R2, GHCR or any
  store outside Russia, and do not restore an RU snapshot on the Global host.
- **Global** replicates to Cloudflare R2 (or another S3 store in the EU).

## GUARDPOST_SECRET

The secret is the root of every per-tenant key. Treat it like a database encryption key:

- Generate it once per instance (`openssl rand -hex 32`) and store it in the region's secret store
  **and** offline. Never in the repository, the replica bucket or the snapshot bucket: a backup
  plus the secret is what can test a list of addresses against the ledger.
- **Changing it is refused.** The database records which secret its keyed data belongs to; a boot
  with another secret, or without one, stops with `SecretMismatchError` rather than silently
  starting a second, disjoint ledger.
- **Losing it** makes every keyed hash useless: bans, the account ledger, overrides. Nothing can be
  recovered from them (that is the point). Recovery is to start over: a fresh database (or one with
  the keyed tables emptied) under a new secret, then a full re-backfill from the apps (bans,
  30 days of accounts, 7 days of referrals). The shared IP reputation is plaintext and survives.
  Until the backfill completes, bans and the device and same-person windows are empty.
- **Rotation is not supported** without that re-backfill (`key_version` per tenant exists for a
  future per-tenant rotation, but no tool uses it yet).

## Upgrading from 0.2

0.2 stored registrations with plaintext emails and bans as unkeyed sha256. Migration `0002` drops
the plaintext `registrations` table and VACUUMs the file (a dropped table's bytes otherwise stay in
free pages, and so in every copy and replica, unless SQLite was built with secure delete as in the
Docker image; `guardpost migrate --vacuum` repairs a database that 0.3.0 migrated elsewhere), and
the first boot (or `guardpost migrate`) with
`GUARDPOST_SECRET` re-keys every ban to the HMAC form. Copy the 0.2 volume before migrating (see
[OPERATIONS.md](OPERATIONS.md#upgrading-02-to-03)) and delete that copy once the new instance is
verified: it is the last place the old plaintext lives.
