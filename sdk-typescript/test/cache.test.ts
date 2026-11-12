import { describe, expect, it } from "vitest";
import { DecisionCache, makeKey } from "../src/decisionCache.js";
import { FakeTime } from "./helpers.js";

function setup() {
  const t = new FakeTime();
  const cache = new DecisionCache({ clock: t.clock, wallClock: t.wallClock });
  return { t, cache };
}

const key = (over: Partial<{ tenant: string; ptype: string; pid: string; purpose: string; ctx: string; ver: string | null; pol: string }> = {}) =>
  makeKey(
    over.tenant ?? "t1",
    over.ptype ?? "user",
    over.pid ?? "alice",
    over.purpose ?? "rag",
    over.ctx ?? "c1",
    over.ver === undefined ? "1" : over.ver,
    over.pol ?? "p1",
  );

describe("DecisionCache", () => {
  it("isolates by tenant and principal type (and every other key part)", () => {
    const { cache } = setup();
    expect(cache.put(key(), "ALLOW", 1)).toBe(true);
    expect(cache.get(key())).toBe(1);
    expect(cache.get(key({ tenant: "t2" }))).toBeNull();
    expect(cache.get(key({ ptype: "service" }))).toBeNull();
    expect(cache.get(key({ pid: "bob" }))).toBeNull();
    expect(cache.get(key({ purpose: "other" }))).toBeNull();
    expect(cache.get(key({ ctx: "c2" }))).toBeNull();
    expect(cache.get(key({ ver: "2" }))).toBeNull();
    expect(cache.get(key({ ver: null }))).toBeNull();
    expect(cache.get(key({ pol: "p2" }))).toBeNull();
  });

  it("key components cannot collide through delimiters", () => {
    expect(key({ pid: "a|b", purpose: "c" })).not.toBe(key({ pid: "a", purpose: "b|c" }));
  });

  it("invalidates entries when the epoch advances and refuses stale-epoch puts", () => {
    const { cache } = setup();
    cache.put(key(), "ALLOW", 1);
    cache.put(key({ ctx: "c2" }), "ALLOW", 1);
    expect(cache.invalidateIfEpochAdvanced(2)).toBe(2);
    expect(cache.size).toBe(0);
    expect(cache.get(key())).toBeNull();
    expect(cache.put(key(), "ALLOW", 1)).toBe(false); // older than latest epoch (2)
    expect(cache.put(key(), "ALLOW", 2)).toBe(true);
    expect(cache.latestEpoch).toBe(2);
  });

  it("an entry issued before a later-observed epoch is dropped on get", () => {
    const { cache } = setup();
    cache.put(key(), "ALLOW", 1);
    cache.put(key({ ctx: "c2" }), "ALLOW", 3); // advances latestEpoch
    expect(cache.get(key())).toBeNull();
    expect(cache.get(key({ ctx: "c2" }))).toBe(3);
  });

  it.each(["DENY", "UNKNOWN", "REFRESH", "REDACT", "QUARANTINE", "HUMAN_REVIEW", "allow"])(
    "never caches %s",
    (decision) => {
      const { cache } = setup();
      expect(cache.put(key(), decision, 1)).toBe(false);
      expect(cache.size).toBe(0);
      expect(cache.get(key())).toBeNull();
    },
  );

  it("caps the TTL at 30 seconds", () => {
    const { t, cache } = setup();
    cache.put(key(), "ALLOW", 1, { ttl: 999 });
    t.mono += 29.9;
    expect(cache.get(key())).toBe(1);
    t.mono += 0.2;
    expect(cache.get(key())).toBeNull();
  });

  it("honours a shorter explicit TTL", () => {
    const { t, cache } = setup();
    cache.put(key(), "ALLOW", 1, { ttl: 5 });
    t.mono += 5.1;
    expect(cache.get(key())).toBeNull();
  });

  it("refuses an ALLOW already within the 30s skew window of valid_until", () => {
    const { t, cache } = setup();
    expect(cache.put(key({ ctx: "a" }), "ALLOW", 1, { validUntil: t.wall + 10 })).toBe(false);
    expect(cache.put(key({ ctx: "b" }), "ALLOW", 1, { validUntil: t.wall + 30 })).toBe(false); // boundary: >= refuses
    expect(cache.put(key({ ctx: "c" }), "ALLOW", 1, { validUntil: t.wall + 31 })).toBe(true);
    expect(cache.put(key({ ctx: "d" }), "ALLOW", 1, { validUntil: t.wall - 5 })).toBe(false);
  });

  it("stops serving an entry skew-seconds before valid_until", () => {
    const { t, cache } = setup();
    cache.put(key(), "ALLOW", 1, { validUntil: t.wall + 100 });
    t.wall += 69; // 31s before valid_until: still served
    expect(cache.get(key())).toBe(1);
    t.wall += 1; // 30s before valid_until: refused
    expect(cache.get(key())).toBeNull();
  });

  it("invalidateContext removes every entry for a context", () => {
    const { cache } = setup();
    cache.put(key({ pid: "a" }), "ALLOW", 1);
    cache.put(key({ pid: "b" }), "ALLOW", 1);
    cache.put(key({ ctx: "other" }), "ALLOW", 1);
    expect(cache.invalidateContext("c1")).toBe(2);
    expect(cache.size).toBe(1);
  });
});
