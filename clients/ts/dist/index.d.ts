/**
 * Guardpost TypeScript client. Zero runtime dependencies: global `fetch`,
 * `AbortSignal.timeout` and `AbortSignal.any` (Node 20.3+, Deno, Bun, browsers).
 *
 *   import { GuardpostClient, failOpen } from "@superposition-labs/guardpost";
 *
 *   const gp = new GuardpostClient({ baseUrl: "http://guardpost:8000", apiKey: process.env.GUARDPOST_API_KEY! });
 *   const result = await gp.checkV2(
 *     { mode: "commit", email, ip, device: { user_agent, accept_language }, account: { id: userId } },
 *     { idempotencyKey: `signup:${userId}` },
 *   );
 *   result.decision; // "allow" | "degrade" | "block"
 *
 * Behaviour (the same as the Python client, guardpost/client.py):
 * - Auth: `Authorization: Bearer <apiKey>`.
 * - Timeouts: `timeoutMs` bounds each attempt (default 5000); `totalTimeoutMs`
 *   optionally bounds the whole call, retries and back-off included.
 * - Retries: on 5xx, timeouts and network errors only, never on a 4xx (429
 *   included), with jittered exponential back-off. Send an idempotency key with
 *   a commit-mode check so a retry replays the first result.
 * - Errors: every failure is a {@link GuardpostError}; its message never echoes
 *   request values, so it is safe to log.
 * - {@link failOpen}: the result, or a fallback on any GuardpostError.
 *
 * The request and response types are generated from openapi/guardpost.json
 * (src/schema.d.ts, `npm run generate`); this file is hand-written. It uses only
 * erasable TypeScript, so Node's type stripping can run it as is.
 */
import type { components } from "./schema.js";
type Schemas = components["schemas"];
export type CheckRequest = Schemas["CheckV2Request"];
export type CheckResponse = Schemas["CheckV2Response"];
export type Reason = Schemas["ReasonOut"];
export type Decision = CheckResponse["decision"];
export type Action = CheckResponse["actions"][number];
export type EventRequest = Schemas["EventRequest"];
export type EventType = EventRequest["type"];
export type EventResponse = Schemas["EventResponse"];
export type BanRequest = Schemas["BanV2Request"];
export type UnbanRequest = Schemas["UnbanV2Request"];
export type BanResponse = Schemas["BanV2Response"];
export type OverrideRequest = Schemas["OverrideRequest"];
export type OverrideResponse = Schemas["OverrideResponse"];
export type AccountImport = Schemas["AccountImport"];
export type BanImport = Schemas["BanImport"];
export type ReferralImport = Schemas["ReferralImport"];
export type IPReputationImport = Schemas["IPReputationImport"];
export type ImportResponse = Schemas["ImportResponse"];
export type AccountResponse = Schemas["AccountResponse"];
export type StatsResponse = Schemas["StatsV2Response"];
export type HealthResponse = Schemas["HealthResponse"];
export type { components, paths } from "./schema.js";
/** The client's version (sent as `User-Agent: guardpost-ts/<version>`). */
export declare const VERSION = "0.4.0";
/** Rows per import request; larger imports are split. */
export declare const IMPORT_MAX_ROWS = 1000;
export interface RetryOptions {
    /** Retries after the first attempt (default 2; 0 disables them). */
    retries?: number;
    /** Back-off base in ms (default 200): attempt n waits half to all of min(maxBackoffMs, backoffMs * 2^n). */
    backoffMs?: number;
    /** Back-off cap in ms (default 2000). */
    maxBackoffMs?: number;
}
export interface CallOptions extends RetryOptions {
    /** Per-attempt timeout in ms (overrides the client's). */
    timeoutMs?: number;
    /** Budget for the whole call in ms, retries and back-off included. */
    totalTimeoutMs?: number;
    /** Abort the call (an aborted call fails with code "aborted" and is not retried). */
    signal?: AbortSignal;
}
export interface CheckOptions extends CallOptions {
    /** Sent as the Idempotency-Key header (or set `idempotency_key` in the request). */
    idempotencyKey?: string;
}
export interface ImportOptions extends CallOptions {
    /** Rows per request, 1..1000 (default 1000). */
    chunkSize?: number;
}
export interface GuardpostOptions extends RetryOptions {
    /** e.g. "http://guardpost:8000". */
    baseUrl: string;
    /** A gpk_... key. */
    apiKey: string;
    /** Per-attempt timeout in ms (default 5000). */
    timeoutMs?: number;
    /** Budget for each whole call in ms (default: none). */
    totalTimeoutMs?: number;
    /** Extra headers on every request. */
    headers?: Record<string, string>;
    /** A fetch implementation (default: the global fetch). */
    fetch?: typeof fetch;
}
export interface GuardpostErrorInit {
    status: number | null;
    code: string | null;
    message: string;
    detail?: unknown;
    retryable?: boolean;
}
/**
 * A failed Guardpost call.
 *
 * - `status`: the HTTP status, or null when no response arrived.
 * - `code`: the v2 error code (`account_exists`, `check_expired`, ...) or one of
 *   `timeout`, `connection_error`, `aborted`, `invalid_response`.
 * - `detail`: the response's `detail` as sent. A 422's may contain request values: do not log it.
 * - `retryable`: 5xx, timeouts and connection errors.
 */
export declare class GuardpostError extends Error {
    readonly status: number | null;
    readonly code: string | null;
    readonly detail: unknown;
    readonly retryable: boolean;
    constructor(init: GuardpostErrorInit);
}
/** `await call`, or `fallback` when it rejects with a GuardpostError. Anything else is rethrown. */
export declare function failOpen<T, D>(call: Promise<T> | (() => Promise<T>), fallback: D, onError?: (error: GuardpostError) => void): Promise<T | D>;
export declare class GuardpostClient {
    #private;
    readonly baseUrl: string;
    readonly timeoutMs: number;
    readonly totalTimeoutMs: number | undefined;
    readonly retries: number;
    readonly backoffMs: number;
    readonly maxBackoffMs: number;
    constructor(options: GuardpostOptions);
    /** POST /api/v2/check: `mode: "evaluate"` (default, read-only) or `"commit"` (needs `account.id`). */
    checkV2(request: CheckRequest, options?: CheckOptions): Promise<CheckResponse>;
    /** POST /api/v2/accounts: commit an evaluated check (within 1 hour). */
    commit(checkId: string, accountId: string, options?: CallOptions): Promise<CheckResponse>;
    /** POST /api/v2/accounts/{id}/events: created, deleted, banned, paid, flagged, ... */
    event(accountId: string, event: EventRequest, options?: CallOptions): Promise<EventResponse>;
    /** PUT /api/v2/bans: ban an address (or its normalized sha256) for this tenant. */
    ban(request: BanRequest, options?: CallOptions): Promise<BanResponse>;
    /** DELETE /api/v2/bans. */
    unban(request: UnbanRequest, options?: CallOptions): Promise<BanResponse>;
    /** PUT /api/v2/ip-overrides/{ip_or_cidr}; `null` removes the override (DELETE). */
    ipOverride(target: string, override: OverrideRequest | null, options?: CallOptions): Promise<OverrideResponse>;
    /** POST /api/v2/import/accounts in chunks (backfill scope); the counts are summed. */
    importAccounts(rows: Iterable<AccountImport>, options?: ImportOptions): Promise<ImportResponse>;
    /** POST /api/v2/import/bans in chunks. */
    importBans(rows: Iterable<BanImport>, options?: ImportOptions): Promise<ImportResponse>;
    /** POST /api/v2/import/referrals in chunks. */
    importReferrals(rows: Iterable<ReferralImport>, options?: ImportOptions): Promise<ImportResponse>;
    /** POST /api/v2/admin/ip-reputation/import in chunks (admin scope; the table every tenant shares). */
    importIpReputation(rows: Iterable<IPReputationImport>, options?: ImportOptions): Promise<ImportResponse>;
    /** GET /api/v2/accounts/{id} (dashboard scope). */
    account(accountId: string, options?: CallOptions): Promise<AccountResponse>;
    /** GET /api/v2/stats (dashboard scope). */
    stats(days?: number, options?: CallOptions): Promise<StatsResponse>;
    /** GET /api/v1/health (any valid key): status and server version. */
    health(options?: CallOptions): Promise<HealthResponse>;
}
