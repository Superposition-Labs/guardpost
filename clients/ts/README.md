# @superposition-labs/guardpost

TypeScript client for [Guardpost](https://github.com/Superposition-Labs/guardpost), the self-hosted signup
abuse detection service. No runtime dependencies: it uses the global `fetch`, `AbortSignal.timeout` and
`AbortSignal.any` (Node 20.3+, Deno, Bun, browsers).

```ts
import { GuardpostClient, failOpen } from "@superposition-labs/guardpost";

const gp = new GuardpostClient({
  baseUrl: "http://guardpost:8000",
  apiKey: process.env.GUARDPOST_API_KEY!, // a gpk_... key
  timeoutMs: 2000,
});

// Shadow: evaluate and record in one call, off the request path (an outbox job).
const result = await gp.checkV2(
  {
    mode: "commit",
    occurred_at: user.createdAt.toISOString(),
    email: user.email,
    ip,
    device: { user_agent: userAgent, accept_language: acceptLanguage },
    name: { first: user.firstName, last: user.lastName },
    account: { id: user.id },
  },
  { idempotencyKey: `signup:${user.id}` },
);
result.decision; // "allow" | "degrade" | "block"
result.actions;  // ["no_welcome_credits", "no_referral_attribution", ...]

// Enforce (later): a hard cap, then the app's own rules if Guardpost is slow or down.
const verdict = await failOpen(
  gp.checkV2({ mode: "evaluate", email, ip }, { totalTimeoutMs: 1500, retries: 0 }),
  null,
);
if (verdict === null) runLocalRules();
```

Methods: `checkV2`, `commit`, `event`, `ban`, `unban`, `ipOverride`, `importAccounts`, `importBans`,
`importReferrals`, `importIpReputation`, `account`, `stats`, `health`. Every method takes per-call
`timeoutMs`, `totalTimeoutMs`, `retries` and `signal`.

- Auth: `Authorization: Bearer <apiKey>`.
- Retries: 5xx, timeouts and network errors only (default 2, jittered exponential back-off from 200 ms);
  never a 4xx, 429 included.
- Errors: a `GuardpostError` with `status`, `code` (`account_exists`, `timeout`, `connection_error`,
  `aborted`, ...) and `retryable`. Its message never contains request values; `detail` may.
- Types: generated from the server's OpenAPI document into `dist/schema.d.ts` (`components`, `paths`
  are exported too).

The integration guide (lifecycle, shadow → enforce, idempotency, backfill) is
[docs/INTEGRATION.md](https://github.com/Superposition-Labs/guardpost/blob/main/docs/INTEGRATION.md).

## Development

```bash
npm ci
npm run generate   # src/schema.d.ts from ../../openapi/guardpost.json
npm run build      # dist/ (committed: consumers vendor dist/index.js)
npm test
npm run check:generated && npm run check:pack
```

`dist/` is committed because Factory v2 vendors the compiled file (Node's type stripping does not apply
inside `node_modules`). CI fails when `src/schema.d.ts` or `dist/` is stale.
