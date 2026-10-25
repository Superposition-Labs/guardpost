# Integrating an app with Guardpost

This guide is for an app (a "tenant") that sends its signups to Guardpost and acts on the
answer. It covers the v2 API: `POST /api/v2/check` and the account ledger behind it. The v1
routes (`/api/v1/*`) still work unchanged for existing callers; new integrations should use v2.

- [Concepts](#concepts)
- [The signup lifecycle: evaluate and commit](#the-signup-lifecycle-evaluate-and-commit)
- [What to send](#what-to-send)
- [What comes back](#what-comes-back)
- [Rolling out: off, shadow, enforce](#rolling-out-off-shadow-enforce)
- [Timeouts, retries and failing open](#timeouts-retries-and-failing-open)
- [Idempotency](#idempotency)
- [occurred_at](#occurred_at)
- [Lifecycle events, bans and IP overrides](#lifecycle-events-bans-and-ip-overrides)
- [Backfill and imports](#backfill-and-imports)
- [Errors](#errors)
- [Examples](#examples)

Related: [RULES.md](RULES.md) (every reason, tier and action), [PRIVACY.md](PRIVACY.md) (what is
stored and how), [OPERATIONS.md](OPERATIONS.md) (running an instance). The contract is
[`openapi/guardpost.json`](../openapi/guardpost.json).

## Concepts

- **Instance.** One Guardpost per data jurisdiction (Global, RU). An app in a region talks only to
  that region's instance; nothing is shared between instances.
- **Tenant.** Your app. The API key decides the tenant; no request field can name another one.
  Tenants on one instance share only network and domain intel (IP and /24 reputation, disposable
  domains, MX). Bans, accounts, device and same-person matches and referrals are per tenant.
- **Account ids.** Guardpost knows your users only by your own opaque id (`account.id`,
  `^[A-Za-z0-9._:-]{1,128}$`, never an email). Evidence in a response names your own account ids.
- **Keys and scopes.** Keys look like `gpk_<id>_<secret>` and are sent as
  `Authorization: Bearer <key>` (`X-Api-Key` also works). Give each deployment its own key with the
  scopes it needs:

  | Scope       | Grants |
  | ----------- | ------ |
  | `check`     | `POST /api/v2/check`, `POST /api/v2/accounts` (commit) |
  | `lifecycle` | account events, `PUT/DELETE /api/v2/bans`, `PUT/DELETE /api/v2/ip-overrides/*` |
  | `dashboard` | `GET /api/v2/stats`, `GET /api/v2/accounts/{id}` |
  | `backfill`  | `POST /api/v2/import/*`, and checks with an `occurred_at` older than 15 minutes |
  | `admin`     | `POST /api/v2/admin/ip-reputation/import` (the table every tenant shares) |

  A typical app key is `check,lifecycle,dashboard`; the backfill tool gets its own short-lived
  `backfill` key (plus `admin` for the IP reputation import). Keys are created with the CLI
  ([OPERATIONS.md](OPERATIONS.md#tenants-and-keys)).

## The signup lifecycle: evaluate and commit

A check has two halves: **evaluate** (run the rules, read-only) and **commit** (record the account
in the ledger, so later signups are compared with it, and bump the shared IP and /24 counters).

```
mode "evaluate"                              mode "commit"
---------------                              -------------
POST /api/v2/check {mode: evaluate, ...}     POST /api/v2/check {mode: commit, account: {id}, ...}
  -> decision, check_id (pending 1 hour)       -> decision, committed: true
app creates the user (or refuses)
POST /api/v2/accounts {check_id, account_id}
  -> the same result, committed: true
```

- **Evaluate, then commit** is for a check in the request path (enforce): evaluate before the user
  exists, act on the decision, and commit the `check_id` once the user row is created. A pending
  check can be committed for 1 hour; if the app refuses the signup or the transaction rolls back,
  do nothing and it expires. Committing a check for a different `account_id` than the one it was
  evaluated with (`account.id`) is refused (`409 account_mismatch`): evaluate again.
- **Commit mode** does both in one call and needs `account.id`. It is the shadow pattern: the app
  has already decided with its own rules and created the user, and tells Guardpost afterwards.
- **Commit-in-shadow.** In shadow mode Guardpost records every account the app created, including
  one Guardpost itself would have blocked (the app created it, so it exists). It counts as
  suspicious on the shared IP counters. This is a known divergence (`blocked-signup-committed` in
  [RULES.md](RULES.md#known-divergences)); it only happens when the decisions already differ.
- Refused signups are not sent in shadow mode (deferred: a `guardpost.attempt` event may come later).
- Commit is idempotent: committing the same check for the same account again returns the same
  result. A commit-mode check for an account that is already in the ledger is `409 account_exists`;
  send an [idempotency key](#idempotency) so a retry replays instead.

## What to send

`POST /api/v2/check` (all fields but the email are optional; send what you have, the rules that
lack an input simply do not fire):

| Field | Meaning |
| ----- | ------- |
| `mode` | `evaluate` (default) or `commit` |
| `email` | The address as typed. Or `email_sha256` instead: sha256 hex of the alias-normalized address (Factory v2's `normalized_email_hash`). With only the hash, the email rules (format, typo, MX, disposable, role, ...) cannot run; bans and alias collisions still do. |
| `ip` | The client address as the app sees it after its own proxy handling (IPv4 or IPv6) |
| `device` | `{user_agent, accept_language}` (the raw headers), or `{fingerprint}`: sha256 hex of `User-Agent + "\|" + Accept-Language` |
| `name` | `{first, last, display}` as entered, or a precomputed `{key}` (Factory v2's `registrationNameKey`) |
| `referral` | `{referrer_account_id, code}` when the signup came through a referral code the app resolved |
| `signup` | `{method: "email" \| "oauth", oauth_provider, returning_user}`. `email` runs the format, typo and MX gates; `oauth` skips them (the provider verified the mailbox). `returning_user`: the address belonged to a deleted account (Guardpost cannot know this: a deleted account's email key is erased) |
| `account` | `{id}`: your account id. Required in `commit` mode; in `evaluate` mode it marks the check for that account (and excludes it from its own matches) |
| `region` | Region rules when the tenant config sets none (`ru` turns on `ua_domain`) |
| `occurred_at` | When the signup happened ([rules](#occurred_at)) |
| `idempotency_key` | Or the `Idempotency-Key` header ([rules](#idempotency)) |

Unknown fields are rejected (`422`), so a typo fails loudly.

## What comes back

```json
{
  "check_id": "chk_4f0c...",
  "decision": "degrade",
  "block_code": null,
  "risk_score": 20,
  "reasons": [{"code": "subnet_burst:203.0.113.0/24", "kind": "subnet_burst", "tier": "soft", "evidence": null}],
  "hard_reasons": [], "soft_reasons": ["subnet_burst:203.0.113.0/24"], "weak_reasons": [],
  "actions": ["no_welcome_credits", "no_referral_attribution", "no_referral_payouts"],
  "referral": {"attribute": false, "suspicious": false, "reason": "signup_degrade"},
  "suggestion": null,
  "signals": {"method": "email", "ip_status": "clean", "subnet_status": "graylisted", "...": "..."},
  "mode": "commit", "committed": true, "account_id": "u_123",
  "occurred_at": "2026-10-25T10:00:00Z", "ruleset": "2026.11-1", "engine_version": "0.4.0"
}
```

- `decision` is the highest tier among the reasons: any `hard` reason → `block`, any `soft` →
  `degrade`, otherwise `allow` (`weak` reasons only raise `risk_score`).
- `block` → refuse the signup. `block_code` names the Factory v2 refusal it reproduces
  (`EMAIL_TYPO_SUSPECTED` comes with `suggestion`, the domain the user probably meant).
- `degrade` → create the account quietly without the perks; never tell the user why (silent
  degradation keeps the signals secret).
- `actions` is the exact list of what to withhold, also for an `allow` (a returning user, a
  same-person match): `no_welcome_credits`, `no_referral_attribution`, `no_referral_payouts`,
  `retract_referral_code`.
- `referral` is the verdict on the referral the request carried (null without one): `attribute`
  false means do not record it at all; `suspicious` true means record it flagged (no referral bonus).
- `ruleset` identifies the rule set; compare it when you compare decisions with your own rules.

[RULES.md](RULES.md) lists every reason, its tier, its detail and its evidence.

## Rolling out: off, shadow, enforce

An app adopts Guardpost in three steps, each a config switch (Factory v2: `GUARDPOST_MODE`).

1. **off** (default): nothing is sent.
2. **shadow**: the app keeps deciding with its own rules. After a signup commits, an outbox job
   (never the request path) sends a `commit`-mode check with `occurred_at` = the user's
   `created_at` and the idempotency key `signup:<account id>`, then compares Guardpost's
   decision with the app's own and logs or stores the comparison (no email in the log line).
   Lifecycle events (deleted, banned, paid, ...) go through the same outbox. A Guardpost outage
   then costs nothing but a backlog.

   Before turning shadow on, [backfill](#backfill-and-imports) the windows (30 days of accounts,
   bans, 7 days of referrals, IP reputation), or the first weeks of shadow compare against an empty
   ledger. Measure parity while your app is the instance's only tenant: a second tenant's traffic
   moves the shared IP counters.

   Proposed bar for leaving shadow: at least 2 weeks and 300 signups per region; at least 99%
   decision match outside the [known divergences](RULES.md#known-divergences); no case where
   Guardpost is looser on a block reason; p95 latency under 300 ms; errors under 0.5%.
3. **enforce**: the check moves into the signup request: `evaluate` before the user is created,
   act on `decision` and `actions`, then `commit` the check (through the outbox is fine). In this
   mode the call must be capped: **about 1.5 s for the whole call, retries included**, and on a
   timeout or any error the app **falls back to its local rules**, not to "allow". Keep the local
   rules in the code base for exactly that.

## Timeouts, retries and failing open

Both official clients ([Python](../guardpost/client.py), [TypeScript](../clients/ts)) behave the same:

- a per-attempt timeout (default 5 s) and an optional total budget for the whole call;
- retries with jittered exponential back-off (default 2 retries from 200 ms) on 5xx, timeouts and
  connection errors, **never on a 4xx** (429 included: back off at the caller, e.g. the outbox);
- every failure is a `GuardpostError` with `status`, `code` and `retryable`; its message never
  contains request values (a 422's raw `detail` may, so log the message, not the detail);
- a fail-open helper that returns your fallback on any `GuardpostError`.

Suggested settings:

| Where | Per attempt | Total | Retries | On failure |
| ----- | ----------- | ----- | ------- | ---------- |
| shadow (outbox job) | 2 s | none | 2 | the job fails and the outbox retries it later |
| enforce (request path) | 1 s | 1.5 s | 1 (only if it fits the budget) | local rules |
| lifecycle events (outbox) | 2 s | none | 2 | outbox retry |
| backfill tool | 30 s | none | 3 | stop and resume from the last chunk |

Retrying any v2 write is safe: commits are idempotent, events and checks with an idempotency key
replay, imports and bans are upserts. A commit-mode check without a key is the one exception (the
retry answers `409 account_exists`), so always send one.

## Idempotency

- Send `Idempotency-Key: <key>` (or `idempotency_key` in the body; if both are sent they must be
  equal) on every `POST /api/v2/check`. Keys are per tenant, up to 200 characters.
- A replay with the same key and the same request returns the identical result, the same
  `check_id` included, for 24 hours (the checks' retention). After that the key is forgotten.
- The same key with a different request is `422 idempotency_key_reused`. "Same request" is the
  parsed body without the key, so field order and whitespace do not matter.
- Lifecycle events take `idempotency_key` in the body. A replay answers `applied: false,
  duplicate: true` with the first event's id; the same key on another account or event type is a
  `422`. Event keys live as long as the event (400 days by default).
- Suggested keys: `signup:<account id>` for the signup check; `<type>:<account id>:<source id>` for
  events (e.g. `paid:u_123:<payment id>`, `banned:u_123:<admin action id>`).

## occurred_at

- The moment the signup (or event) happened, ISO 8601. A value without a timezone is UTC. Default:
  the server's clock.
- A check's `occurred_at` must be within 15 minutes of the server clock. Older values need a key
  with the `backfill` scope (replays, the shadow outbox after an outage). More than 15 minutes in
  the future is always refused.
- Every window is evaluated as `[occurred_at - window, occurred_at)` against accounts created
  before `occurred_at`, so a replay sees the ledger as it was then, and an outbox that delivers
  late still gets the answer it would have had on time.
- In shadow mode use the user's `created_at`, not the time the outbox job runs.
- Events take any `occurred_at` (when it happened).

## Lifecycle events, bans and IP overrides

`POST /api/v2/accounts/{account_id}/events` (`lifecycle` scope) keeps the ledger true to the app:

| Event | Effect |
| ----- | ------ |
| `created` | Records the account if a check never did (`source: event`; send `email` or `email_sha256`) |
| `deleted` | Erases the account's email key at once (the address can sign up again without an alias collision); its device, IP and name keys stay until retention (35 days), so a delete-and-re-register is still matched |
| `banned` | Marks the account banned. With `permanent_email_ban: true` also bans the address for this tenant (`email`/`email_sha256` needed if the account has no email key left) |
| `unbanned` | Lifts the account ban; a permanent email ban stays (lift it with `DELETE /api/v2/bans`) |
| `paid` | The first payment (later ones change nothing): feeds the "degraded, then paid" number in stats |
| `flagged` / `unflagged` | A manual suspicion flag |
| `referral_code_retracted` / `referral_code_restored` | The account's own referral code; a retracted referrer gets no new attributions |

Events for an account Guardpost has never seen are `404 account_not_found` (send `created` first,
or import it). `reason` and `actor` are free text: never put an email in them.

- `PUT /api/v2/bans` / `DELETE /api/v2/bans` ban or lift an address (`email` or `email_sha256`) for
  this tenant. A banned address is refused with `EMAIL_BANNED`.
- `PUT /api/v2/ip-overrides/{ip_or_cidr}` with `{"action": "allow" | "block"}` overrides the shared
  reputation of an address or an IPv4 /24 for this tenant only; `DELETE` removes it. Overrides are
  stored keyed, so they can be matched but never listed.

## Backfill and imports

Imports need the `backfill` scope (the IP import `admin`), take up to 1,000 rows per request (the
clients split larger lists) and upsert: they answer `{received, inserted, updated}`. Run them
before shadow starts, and again as a nightly reconciliation of the last 48 hours.

| Route | Rows | Send |
| ----- | ---- | ---- |
| `POST /api/v2/import/bans` | `{email \| email_sha256, banned_at, banned_by, reason}` | every permanent ban |
| `POST /api/v2/import/accounts` | `{account_id, email \| email_sha256, created_at, ip, device, name, deleted_at, banned_at, paid_at, flagged_at, referral_code_retracted_at, decision, reasons}` | the last 30 days of signups (the longest window), deleted accounts of the last 30 days included (without an email) |
| `POST /api/v2/import/referrals` | `{referred_account_id, referrer_account_id, created_at, ip, suspicious, reason}` | the last 7 days |
| `POST /api/v2/admin/ip-reputation/import` | the app's `ip_reputation` rows | once, to seed the shared table (also `guardpost ip-reputation import` on the host) |

- Imported accounts do not touch the shared IP counters (they would double count): seed those with
  the IP reputation import.
- Signals older than the tenant's retention (35 days) are dropped by the next purge, so there is
  no point importing more.
- Replays (re-running old signups through `POST /api/v2/check` with old `occurred_at`) are for a
  throwaway instance only: on a live one they would write the ledger twice.

## Errors

Errors are JSON with a `detail`. v2 refusals carry `{"code", "message"}`; validation errors are
FastAPI's list.

| Status | `code` | Meaning |
| ------ | ------ | ------- |
| 401 | | Missing, unknown, revoked or expired key |
| 403 | | The key lacks the scope, or the tenant is suspended |
| 404 | `check_not_found`, `account_not_found` | Unknown check (kept 24 h) or account |
| 409 | `account_exists` | The account is already in the ledger |
| 409 | `check_already_committed`, `account_mismatch` | The check was committed (or evaluated) for another account |
| 410 | `check_expired` | An evaluated check can be committed for 1 hour |
| 422 | `occurred_at_out_of_window`, `occurred_at_in_future` | See [occurred_at](#occurred_at) |
| 422 | `idempotency_key_reused` | See [Idempotency](#idempotency) |
| 422 | `account_required`, `email_unknown`, or a validation list | A malformed request |
| 429 | | The tenant's rate limit (not retried by the clients) |
| 503 | | The v2 ledger is disabled (no `GUARDPOST_SECRET`), or the server is starting |

## Examples

### Python

```python
from guardpost.client import AsyncGuardpostClient, GuardpostClient, GuardpostError

# Shadow: an outbox handler, after the signup transaction committed.
async def guardpost_signup(job, gp: AsyncGuardpostClient):
    user = job.payload
    result = await gp.check_v2(
        mode="commit",
        occurred_at=user["created_at"],
        email=user["email"],
        ip=user["ip"],
        device={"user_agent": user["user_agent"], "accept_language": user["accept_language"]},
        name={"first": user["first_name"], "last": user["last_name"]},
        signup={"method": user["method"], "returning_user": user["returning"]},
        referral={"referrer_account_id": user["referrer_id"]} if user["referrer_id"] else None,
        account={"id": user["id"]},
        idempotency_key=f"signup:{user['id']}",
    )
    compare_and_log(user, result.decision, result.reasons)  # raises -> the outbox retries the job

# Enforce: in the request path, capped, falling back to the local rules.
gp = GuardpostClient("http://guardpost:8000", api_key=KEY, timeout=1.0, total_timeout=1.5, retries=1)
verdict = gp.fail_open(None).check_v2(email=email, ip=ip, device=device, account={"id": new_id})
if verdict is None:
    verdict = local_rules(email, ip, device)          # Guardpost slow or down
elif verdict.decision == "block":
    refuse(verdict.block_code, verdict.suggestion)
else:
    user = create_user(..., perks="no_welcome_credits" not in verdict.actions)
    enqueue("guardpost.commit", check_id=verdict.check_id, account_id=user.id)   # gp.commit(...)

# Lifecycle and backfill.
gp.event("u_123", "paid", occurred_at=paid_at, idempotency_key=f"paid:u_123:{payment_id}")
gp.event("u_123", "banned", permanent_email_ban=True, reason="chargeback ring", actor="admin:42")
with GuardpostClient(URL, api_key=BACKFILL_KEY, timeout=30, retries=3) as backfill:
    backfill.import_bans({"email_sha256": h, "banned_at": t} for h, t in bans)
    backfill.import_accounts(rows_from_last_30_days())          # chunked to 1,000 per request
```

### TypeScript

```ts
import { GuardpostClient, GuardpostError, failOpen } from "@superposition-labs/guardpost";

const gp = new GuardpostClient({ baseUrl: "http://guardpost:8000", apiKey: config.GUARDPOST_API_KEY, timeoutMs: 2000 });

// Shadow: outbox handler.
export async function guardpostSignup(user: SignupPayload) {
  const result = await gp.checkV2(
    {
      mode: "commit",
      occurred_at: user.createdAt.toISOString(),
      email: user.email,
      ip: user.ip,
      device: { user_agent: user.userAgent, accept_language: user.acceptLanguage },
      name: { first: user.firstName, last: user.lastName },
      signup: { method: user.method, returning_user: user.returning },
      referral: user.referrerId ? { referrer_account_id: user.referrerId } : null,
      account: { id: user.id },
    },
    { idempotencyKey: `signup:${user.id}` },
  );
  await recordComparison(user.id, result); // throws -> the outbox retries
}

// Enforce: capped at 1.5 s, local rules on any failure.
const verdict = await failOpen(
  gp.checkV2({ mode: "evaluate", email, ip, device, account: { id: newId } }, { timeoutMs: 1000, totalTimeoutMs: 1500, retries: 1 }),
  null,
  (error: GuardpostError) => metrics.guardpostErrors.inc({ code: error.code ?? "http" }),
);
const decision = verdict ?? (await localRules(email, ip, device));

// Lifecycle.
await gp.event(user.id, { type: "deleted", occurred_at: new Date().toISOString(), idempotency_key: `deleted:${user.id}` });
await gp.importAccounts(rows, { chunkSize: 500, timeoutMs: 30_000, retries: 3 });
```
