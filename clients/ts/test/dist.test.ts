// The committed dist/ is what Factory v2 vendors: it must behave like the source.
import { describe, expect, it } from "vitest";

import { failOpen, GuardpostClient, GuardpostError, VERSION } from "../dist/index.js";
import * as source from "../src/index.ts";

describe("dist", () => {
  it("exports the source's API", () => {
    expect(VERSION).toBe(source.VERSION);
    expect(Object.keys(GuardpostClient.prototype)).toEqual(Object.keys(source.GuardpostClient.prototype));
    expect(Object.getOwnPropertyNames(GuardpostClient.prototype).sort()).toEqual(
      Object.getOwnPropertyNames(source.GuardpostClient.prototype).sort(),
    );
  });

  it("retries a 5xx and fails open", async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls += 1;
      return new Response("{}", { status: 503 });
    }) as typeof fetch;
    const gp = new GuardpostClient({ baseUrl: "http://gp.test", apiKey: "k", fetch: fetchImpl, retries: 1, backoffMs: 0 });
    const error = await gp.health().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(GuardpostError);
    expect(calls).toBe(2);
    expect(await failOpen(gp.health(), "fallback")).toBe("fallback");
  });
});
