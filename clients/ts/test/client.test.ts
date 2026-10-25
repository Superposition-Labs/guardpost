import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  type CheckRequest,
  type CheckResponse,
  failOpen,
  GuardpostClient,
  GuardpostError,
  type GuardpostOptions,
  IMPORT_MAX_ROWS,
  VERSION,
} from "../src/index.ts";

type Step = { status: number; body?: unknown; text?: string } | Error | "hang";

interface Seen {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

/** A fetch that replays scripted steps (the last one repeats) and records each request. */
function mockFetch(...steps: Step[]) {
  const seen: Seen[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    seen.push({
      url: String(input),
      method: init.method ?? "GET",
      headers: { ...(init.headers as Record<string, string>) },
      body: typeof init.body === "string" ? JSON.parse(init.body) : undefined,
    });
    const step = steps.length > 1 ? steps.shift()! : steps[0]!;
    if (step === "hang") {
      return new Promise<Response>((_, reject) => {
        init.signal?.addEventListener("abort", () => reject(init.signal!.reason), { once: true });
      });
    }
    if (step instanceof Error) throw step;
    const payload = step.text ?? JSON.stringify(step.body ?? {});
    return new Response(payload, { status: step.status, headers: { "Content-Type": "application/json" } });
  }) as typeof fetch;
  return { fetchImpl, seen };
}

function client(fetchImpl: typeof fetch, options: Partial<GuardpostOptions> = {}) {
  return new GuardpostClient({
    baseUrl: "http://gp.test/",
    apiKey: "gpk_test_secret",
    fetch: fetchImpl,
    backoffMs: 0,
    ...options,
  });
}

const checkBody: CheckResponse = {
  check_id: "chk_1",
  decision: "allow",
  block_code: null,
  risk_score: 0,
  reasons: [],
  hard_reasons: [],
  soft_reasons: [],
  weak_reasons: [],
  actions: [],
  referral: null,
  suggestion: null,
  signals: {
    method: "email",
    returning_user: false,
    ip_status: "clean",
    ip_reason: null,
    subnet_status: "clean",
    subnet_reason: null,
    ip_override: null,
    global_ip: true,
    fingerprint: true,
    name_key: false,
    typo_source: null,
  },
  mode: "commit",
  committed: true,
  account_id: "u1",
  occurred_at: "2026-10-01T00:00:00Z",
  ruleset: "test",
  engine_version: "0.0.0",
};

const signup: CheckRequest = {
  mode: "commit",
  email: "person@gmail.com",
  ip: "198.51.100.7",
  device: { user_agent: "UA", accept_language: "en" },
  account: { id: "u1" },
};

describe("requests", () => {
  it("sends Bearer auth, the Idempotency-Key header and the body", async () => {
    const { fetchImpl, seen } = mockFetch({ status: 200, body: checkBody });
    const result = await client(fetchImpl).checkV2(signup, { idempotencyKey: "signup:u1" });
    expect(result.decision).toBe("allow");
    const [req] = seen;
    expect(req!.url).toBe("http://gp.test/api/v2/check");
    expect(req!.method).toBe("POST");
    expect(req!.headers.Authorization).toBe("Bearer gpk_test_secret");
    expect(req!.headers["Idempotency-Key"]).toBe("signup:u1");
    expect(req!.headers["User-Agent"]).toBe(`guardpost-ts/${VERSION}`);
    expect(req!.headers["Content-Type"]).toBe("application/json");
    expect(req!.body).toEqual(signup);
  });

  it("moves a body idempotency_key into the header and refuses two different keys", async () => {
    const { fetchImpl, seen } = mockFetch({ status: 200, body: checkBody });
    const gp = client(fetchImpl);
    await gp.checkV2({ ...signup, idempotency_key: "k1" });
    expect(seen[0]!.headers["Idempotency-Key"]).toBe("k1");
    expect(seen[0]!.body).not.toHaveProperty("idempotency_key");
    expect(() => gp.checkV2({ ...signup, idempotency_key: "k1" }, { idempotencyKey: "k2" })).toThrow(TypeError);
  });

  it("builds the other routes", async () => {
    const { fetchImpl, seen } = mockFetch({ status: 200, body: {} });
    const gp = client(fetchImpl);
    await gp.commit("chk_1", "u1");
    await gp.event("acc:1", { type: "paid", idempotency_key: "paid:acc:1" });
    await gp.ban({ email: "bad@example.com", reason: "abuse" });
    await gp.unban({ email_sha256: "a".repeat(64) });
    await gp.ipOverride("203.0.113.0/24", { action: "block" });
    await gp.ipOverride("2001:db8::1", null);
    await gp.account("u1");
    await gp.stats(7);
    await gp.health();
    expect(seen.map((r) => `${r.method} ${r.url.replace("http://gp.test", "")}`)).toEqual([
      "POST /api/v2/accounts",
      "POST /api/v2/accounts/acc%3A1/events",
      "PUT /api/v2/bans",
      "DELETE /api/v2/bans",
      "PUT /api/v2/ip-overrides/203.0.113.0/24",
      "DELETE /api/v2/ip-overrides/2001%3Adb8%3A%3A1",
      "GET /api/v2/accounts/u1",
      "GET /api/v2/stats?days=7",
      "GET /api/v1/health",
    ]);
    expect(seen[0]!.body).toEqual({ check_id: "chk_1", account_id: "u1" });
    expect(seen[1]!.body).toEqual({ type: "paid", idempotency_key: "paid:acc:1" });
    expect(seen[6]!.headers["Content-Type"]).toBeUndefined();
    expect(() => gp.event("../admin", { type: "paid" })).toThrow(TypeError);
  });

  it("chunks imports and sums the counts", async () => {
    const { fetchImpl, seen } = mockFetch(
      { status: 200, body: { received: 2, inserted: 2, updated: 0 } },
      { status: 200, body: { received: 1, inserted: 0, updated: 1 } },
    );
    const rows = [0, 1, 2].map((i) => ({ email_sha256: String(i).padStart(64, "0") }));
    const result = await client(fetchImpl).importBans(rows, { chunkSize: 2 });
    expect(result).toEqual({ received: 3, inserted: 2, updated: 1 });
    expect(seen.map((r) => (r.body as { rows: unknown[] }).rows.length)).toEqual([2, 1]);
    await expect(client(fetchImpl).importBans(rows, { chunkSize: IMPORT_MAX_ROWS + 1 })).rejects.toThrow(TypeError);
  });
});

describe("retries", () => {
  it("retries 5xx, then succeeds", async () => {
    const { fetchImpl, seen } = mockFetch({ status: 503, body: { detail: "Guardpost not initialized" } }, { status: 500 }, {
      status: 200,
      body: checkBody,
    });
    expect((await client(fetchImpl).checkV2(signup)).committed).toBe(true);
    expect(seen).toHaveLength(3);
  });

  it("gives up after the configured retries", async () => {
    const { fetchImpl, seen } = mockFetch({ status: 502, body: { detail: "bad gateway" } });
    const error = await client(fetchImpl, { retries: 2 }).health().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(GuardpostError);
    expect((error as GuardpostError).status).toBe(502);
    expect(seen).toHaveLength(3);
  });

  it.each([400, 401, 403, 404, 409, 422, 429])("never retries %i", async (status) => {
    const { fetchImpl, seen } = mockFetch({ status, body: { detail: { code: "nope", message: "no" } } });
    const error = (await client(fetchImpl, { retries: 3 }).checkV2(signup).catch((e: unknown) => e)) as GuardpostError;
    expect(error.status).toBe(status);
    expect(error.code).toBe("nope");
    expect(error.retryable).toBe(false);
    expect(seen).toHaveLength(1);
  });

  it("retries network errors", async () => {
    const { fetchImpl, seen } = mockFetch(new TypeError("fetch failed"), { status: 200, body: { status: "ok", version: "0.4.0" } });
    expect((await client(fetchImpl).health()).version).toBe("0.4.0");
    expect(seen).toHaveLength(2);
  });

  it("times out each attempt and retries", async () => {
    const { fetchImpl, seen } = mockFetch("hang");
    const error = (await client(fetchImpl, { timeoutMs: 20, retries: 1 }).health().catch((e: unknown) => e)) as GuardpostError;
    expect(error.code).toBe("timeout");
    expect(error.status).toBeNull();
    expect(seen).toHaveLength(2);
  });

  it("caps the whole call with totalTimeoutMs", async () => {
    const { fetchImpl } = mockFetch("hang");
    const started = performance.now();
    const error = (await client(fetchImpl, { timeoutMs: 5000, retries: 5 })
      .health({ totalTimeoutMs: 60 })
      .catch((e: unknown) => e)) as GuardpostError;
    expect(error.code).toBe("timeout");
    expect(performance.now() - started).toBeLessThan(1000);
  });

  it("does not retry a call the caller aborted", async () => {
    const { fetchImpl, seen } = mockFetch("hang");
    const controller = new AbortController();
    const pending = client(fetchImpl, { retries: 3 }).health({ signal: controller.signal }).catch((e: unknown) => e);
    controller.abort();
    const error = (await pending) as GuardpostError;
    expect(error.code).toBe("aborted");
    expect(seen).toHaveLength(1);
  });
});

describe("errors", () => {
  it("keeps request values out of the message", async () => {
    const detail = [{ type: "value_error", loc: ["body", "ip"], msg: "Value error, invalid IP address", input: "secret.person@gmail.com" }];
    const { fetchImpl } = mockFetch({ status: 422, body: { detail } });
    const error = (await client(fetchImpl).checkV2(signup).catch((e: unknown) => e)) as GuardpostError;
    expect(error.message).toBe("HTTP 422: validation error: ip: Value error, invalid IP address");
    expect(error.message).not.toContain("secret.person");
    expect(error.detail).toEqual(detail);
  });

  it("reports a non-JSON success as invalid_response", async () => {
    const { fetchImpl, seen } = mockFetch({ status: 200, text: "<html>" });
    const error = (await client(fetchImpl).health().catch((e: unknown) => e)) as GuardpostError;
    expect(error.code).toBe("invalid_response");
    expect(seen).toHaveLength(1);
  });

  it("validates options", () => {
    const { fetchImpl } = mockFetch({ status: 200 });
    expect(() => client(fetchImpl, { retries: -1 })).toThrow(TypeError);
    expect(() => client(fetchImpl, { timeoutMs: 0 })).toThrow(TypeError);
  });
});

describe("failOpen", () => {
  it("returns the fallback on a GuardpostError", async () => {
    const { fetchImpl } = mockFetch({ status: 503 });
    const seen: GuardpostError[] = [];
    const result = await failOpen(client(fetchImpl, { retries: 0 }).checkV2(signup), null, (e) => seen.push(e));
    expect(result).toBeNull();
    expect(seen[0]!.status).toBe(503);
  });

  it("passes results through and accepts a thunk", async () => {
    const { fetchImpl } = mockFetch({ status: 200, body: checkBody });
    const gp = client(fetchImpl);
    expect((await failOpen(() => gp.checkV2(signup), "fallback")) as CheckResponse).toMatchObject({ decision: "allow" });
  });

  it("returns the fallback on a timeout and survives a throwing hook", async () => {
    const { fetchImpl } = mockFetch("hang");
    const gp = client(fetchImpl, { timeoutMs: 10, retries: 0 });
    const result = await failOpen(gp.health(), "down", () => {
      throw new Error("hook");
    });
    expect(result).toBe("down");
  });

  it("rethrows anything that is not a GuardpostError", async () => {
    await expect(failOpen(Promise.reject(new RangeError("bug")), null)).rejects.toThrow(RangeError);
  });
});

describe("package", () => {
  it("VERSION matches package.json", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
    expect(VERSION).toBe(pkg.version);
  });
});
