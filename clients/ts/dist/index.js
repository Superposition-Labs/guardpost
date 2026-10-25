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
/** The client's version (sent as `User-Agent: guardpost-ts/<version>`). */
export const VERSION = "0.4.0";
/** Rows per import request; larger imports are split. */
export const IMPORT_MAX_ROWS = 1000;
/**
 * A failed Guardpost call.
 *
 * - `status`: the HTTP status, or null when no response arrived.
 * - `code`: the v2 error code (`account_exists`, `check_expired`, ...) or one of
 *   `timeout`, `connection_error`, `aborted`, `invalid_response`.
 * - `detail`: the response's `detail` as sent. A 422's may contain request values: do not log it.
 * - `retryable`: 5xx, timeouts and connection errors.
 */
export class GuardpostError extends Error {
    status;
    code;
    detail;
    retryable;
    constructor(init) {
        super(`${init.status !== null ? `HTTP ${init.status}` : (init.code ?? "error")}: ${init.message}`);
        this.name = "GuardpostError";
        this.status = init.status;
        this.code = init.code;
        this.detail = init.detail;
        this.retryable = init.retryable ?? (init.status === null || init.status >= 500);
    }
}
/** `await call`, or `fallback` when it rejects with a GuardpostError. Anything else is rethrown. */
export async function failOpen(call, fallback, onError) {
    try {
        return await (typeof call === "function" ? call() : call);
    }
    catch (error) {
        if (!(error instanceof GuardpostError))
            throw error;
        try {
            onError?.(error);
        }
        catch {
            // A failing error hook must not turn a fail-open call into a failure.
        }
        return fallback;
    }
}
/** A loggable message for an error `detail`: never the request's values (a 422 echoes each `input`). */
function summarize(detail) {
    if (typeof detail === "string")
        return detail;
    if (Array.isArray(detail)) {
        const parts = detail.slice(0, 5).map((item) => {
            const loc = Array.isArray(item?.loc) ? item.loc.filter((p) => p !== "body").join(".") : "";
            const msg = typeof item?.msg === "string" ? item.msg : "invalid";
            return loc ? `${loc}: ${msg}` : msg;
        });
        return parts.length ? `validation error: ${parts.join("; ")}` : "validation error";
    }
    if (detail && typeof detail === "object") {
        const d = detail;
        return String(d.message ?? d.code ?? "error");
    }
    return "error";
}
function codeOf(detail) {
    if (detail && typeof detail === "object" && !Array.isArray(detail)) {
        const code = detail.code;
        return typeof code === "string" ? code : null;
    }
    return null;
}
function pathSegments(value, what) {
    const trimmed = value.trim();
    if (!trimmed || /[?#]/.test(trimmed))
        throw new TypeError(`invalid ${what}`);
    return trimmed.split("/").map(encodeURIComponent).join("/");
}
function accountSegment(accountId) {
    if (!accountId || accountId.includes("/"))
        throw new TypeError("invalid account id");
    return encodeURIComponent(accountId);
}
function sleep(ms, signal) {
    if (ms <= 0)
        return Promise.resolve();
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            signal?.removeEventListener("abort", onAbort);
            resolve();
        }, ms);
        const onAbort = () => {
            clearTimeout(timer);
            reject(abortedError());
        };
        signal?.addEventListener("abort", onAbort, { once: true });
    });
}
function abortedError() {
    return new GuardpostError({ status: null, code: "aborted", message: "request aborted", retryable: false });
}
export class GuardpostClient {
    baseUrl;
    timeoutMs;
    totalTimeoutMs;
    retries;
    backoffMs;
    maxBackoffMs;
    #apiKey;
    #headers;
    #fetch;
    constructor(options) {
        if (!options.baseUrl)
            throw new TypeError("baseUrl is required");
        this.baseUrl = options.baseUrl.replace(/\/+$/, "");
        this.#apiKey = options.apiKey;
        this.timeoutMs = options.timeoutMs ?? 5000;
        this.totalTimeoutMs = options.totalTimeoutMs;
        this.retries = options.retries ?? 2;
        this.backoffMs = options.backoffMs ?? 200;
        this.maxBackoffMs = options.maxBackoffMs ?? 2000;
        if (this.retries < 0 || this.timeoutMs <= 0 || (this.totalTimeoutMs !== undefined && this.totalTimeoutMs <= 0)) {
            throw new TypeError("retries must be >= 0 and timeouts > 0");
        }
        this.#headers = { ...(options.headers ?? {}) };
        const fetchImpl = options.fetch ?? globalThis.fetch;
        if (typeof fetchImpl !== "function")
            throw new TypeError("no fetch implementation: pass options.fetch");
        this.#fetch = fetchImpl;
    }
    // --- v2 -----------------------------------------------------------------
    /** POST /api/v2/check: `mode: "evaluate"` (default, read-only) or `"commit"` (needs `account.id`). */
    checkV2(request, options = {}) {
        const { idempotencyKey, ...call } = options;
        if (idempotencyKey && request.idempotency_key && idempotencyKey !== request.idempotency_key) {
            throw new TypeError("idempotencyKey and request.idempotency_key differ");
        }
        const key = idempotencyKey ?? request.idempotency_key ?? undefined;
        const { idempotency_key: _omit, ...body } = request;
        return this.#send({ method: "POST", path: "/api/v2/check", body, headers: key ? { "Idempotency-Key": key } : {} }, call);
    }
    /** POST /api/v2/accounts: commit an evaluated check (within 1 hour). */
    commit(checkId, accountId, options = {}) {
        return this.#send({ method: "POST", path: "/api/v2/accounts", body: { check_id: checkId, account_id: accountId } }, options);
    }
    /** POST /api/v2/accounts/{id}/events: created, deleted, banned, paid, flagged, ... */
    event(accountId, event, options = {}) {
        return this.#send({ method: "POST", path: `/api/v2/accounts/${accountSegment(accountId)}/events`, body: event }, options);
    }
    /** PUT /api/v2/bans: ban an address (or its normalized sha256) for this tenant. */
    ban(request, options = {}) {
        return this.#send({ method: "PUT", path: "/api/v2/bans", body: request }, options);
    }
    /** DELETE /api/v2/bans. */
    unban(request, options = {}) {
        return this.#send({ method: "DELETE", path: "/api/v2/bans", body: request }, options);
    }
    /** PUT /api/v2/ip-overrides/{ip_or_cidr}; `null` removes the override (DELETE). */
    ipOverride(target, override, options = {}) {
        const path = `/api/v2/ip-overrides/${pathSegments(target, "override target")}`;
        return override === null
            ? this.#send({ method: "DELETE", path }, options)
            : this.#send({ method: "PUT", path, body: override }, options);
    }
    /** POST /api/v2/import/accounts in chunks (backfill scope); the counts are summed. */
    importAccounts(rows, options = {}) {
        return this.#import("/api/v2/import/accounts", rows, options);
    }
    /** POST /api/v2/import/bans in chunks. */
    importBans(rows, options = {}) {
        return this.#import("/api/v2/import/bans", rows, options);
    }
    /** POST /api/v2/import/referrals in chunks. */
    importReferrals(rows, options = {}) {
        return this.#import("/api/v2/import/referrals", rows, options);
    }
    /** POST /api/v2/admin/ip-reputation/import in chunks (admin scope; the table every tenant shares). */
    importIpReputation(rows, options = {}) {
        return this.#import("/api/v2/admin/ip-reputation/import", rows, options);
    }
    /** GET /api/v2/accounts/{id} (dashboard scope). */
    account(accountId, options = {}) {
        return this.#send({ method: "GET", path: `/api/v2/accounts/${accountSegment(accountId)}` }, options);
    }
    /** GET /api/v2/stats (dashboard scope). */
    stats(days = 30, options = {}) {
        return this.#send({ method: "GET", path: "/api/v2/stats", query: { days: String(days) } }, options);
    }
    /** GET /api/v1/health (any valid key): status and server version. */
    health(options = {}) {
        return this.#send({ method: "GET", path: "/api/v1/health" }, options);
    }
    // --- transport ------------------------------------------------------------
    async #import(path, rows, options) {
        const { chunkSize = IMPORT_MAX_ROWS, ...call } = options;
        if (!Number.isInteger(chunkSize) || chunkSize < 1 || chunkSize > IMPORT_MAX_ROWS) {
            throw new TypeError(`chunkSize must be 1..${IMPORT_MAX_ROWS}`);
        }
        const all = Array.from(rows);
        const total = { received: 0, inserted: 0, updated: 0 };
        for (let i = 0; i < all.length; i += chunkSize) {
            const result = await this.#send({ method: "POST", path, body: { rows: all.slice(i, i + chunkSize) } }, call);
            total.received += result.received;
            total.inserted += result.inserted;
            total.updated += result.updated;
        }
        return total;
    }
    async #send(request, options) {
        const timeoutMs = options.timeoutMs ?? this.timeoutMs;
        const totalMs = options.totalTimeoutMs ?? this.totalTimeoutMs;
        const retries = options.retries ?? this.retries;
        const backoffMs = options.backoffMs ?? this.backoffMs;
        const maxBackoffMs = options.maxBackoffMs ?? this.maxBackoffMs;
        const deadline = totalMs === undefined ? undefined : performance.now() + totalMs;
        const url = this.baseUrl + request.path + (request.query ? `?${new URLSearchParams(request.query)}` : "");
        const headers = {
            Accept: "application/json",
            "User-Agent": `guardpost-ts/${VERSION}`,
            ...this.#headers,
            ...(request.headers ?? {}),
            Authorization: `Bearer ${this.#apiKey}`,
        };
        if (request.body !== undefined)
            headers["Content-Type"] = "application/json";
        const body = request.body === undefined ? undefined : JSON.stringify(request.body);
        for (let attempt = 0;; attempt++) {
            let attemptMs = timeoutMs;
            if (deadline !== undefined) {
                const remaining = deadline - performance.now();
                if (remaining < 1) {
                    throw new GuardpostError({ status: null, code: "timeout", message: "totalTimeoutMs exceeded", retryable: true });
                }
                attemptMs = Math.min(attemptMs, remaining);
            }
            if (options.signal?.aborted)
                throw abortedError();
            const timeout = AbortSignal.timeout(Math.max(1, Math.floor(attemptMs)));
            const signal = options.signal ? AbortSignal.any([timeout, options.signal]) : timeout;
            let error;
            try {
                const response = await this.#fetch(url, { method: request.method, headers, body, signal });
                if (response.ok)
                    return (await this.#json(response));
                error = await this.#error(response);
            }
            catch (thrown) {
                if (thrown instanceof GuardpostError && thrown.code === "invalid_response")
                    throw thrown;
                error = this.#transportError(thrown, options.signal, timeout);
            }
            if (!error.retryable || attempt >= retries)
                throw error;
            const cap = Math.min(maxBackoffMs, backoffMs * 2 ** attempt);
            const delay = cap > 0 ? cap / 2 + Math.random() * (cap / 2) : 0;
            if (deadline !== undefined && performance.now() + delay >= deadline)
                throw error;
            await sleep(delay, options.signal);
        }
    }
    async #json(response) {
        try {
            return await response.json();
        }
        catch (thrown) {
            if (thrown instanceof Error && (thrown.name === "TimeoutError" || thrown.name === "AbortError"))
                throw thrown;
            throw new GuardpostError({
                status: response.status,
                code: "invalid_response",
                message: "response is not JSON",
                retryable: false,
            });
        }
    }
    async #error(response) {
        let detail;
        try {
            const text = await response.text();
            try {
                const parsed = JSON.parse(text);
                detail = parsed && typeof parsed === "object" && "detail" in parsed ? parsed.detail : text;
            }
            catch {
                detail = text || response.statusText;
            }
        }
        catch {
            detail = response.statusText;
        }
        return new GuardpostError({ status: response.status, code: codeOf(detail), message: summarize(detail), detail });
    }
    #transportError(thrown, callerSignal, timeout) {
        if (callerSignal?.aborted)
            return abortedError();
        if (timeout.aborted || (thrown instanceof Error && thrown.name === "TimeoutError")) {
            return new GuardpostError({ status: null, code: "timeout", message: "request timed out", retryable: true });
        }
        const name = thrown instanceof Error ? thrown.name : "Error";
        const cause = thrown instanceof Error && thrown.cause instanceof Error ? `: ${thrown.cause.message}` : "";
        return new GuardpostError({ status: null, code: "connection_error", message: `${name}${cause}`, retryable: true });
    }
}
