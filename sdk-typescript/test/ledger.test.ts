import { afterEach, describe, expect, it, vi } from "vitest";
import { InvariantClient, enforce, type InvariantClientOptions } from "../src/index.js";
import { AuthorizeResult } from "../src/client.js";
import { makeKey } from "../src/decisionCache.js";
import { FakeTime, TENANT, bodyOf, json, makeSigner, snapshotPayload, stubFetch } from "./helpers.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

const alice = { type: "user", id: "alice" };

function make(t: FakeTime, over: Partial<InvariantClientOptions> = {}) {
  return new InvariantClient({
    baseUrl: "http://ales.test/",
    tenantId: TENANT,
    authToken: "secret-token",
    clock: t.clock,
    wallClock: t.wallClock,
    sleep: () => Promise.resolve(),
    random: () => 0.5,
    maxRetries: 0,
    ...over,
  });
}

interface Fake {
  revokedVersions: Set<string>; // "cid@ver"
  denyAgents: Set<string>;
  latest: Record<string, string>;
  policy: string;
  authCalls: number;
}

/** Version- and agent-aware authorize fake; echoes the (resolved) version on every verdict. */
function fakeServer(): Fake {
  const st: Fake = { revokedVersions: new Set(), denyAgents: new Set(), latest: {}, policy: "p1", authCalls: 0 };
  stubFetch((_url, init) => {
    st.authCalls++;
    const body = bodyOf(init);
    const agent = body["agent_id"] as string | undefined;
    const objs = (body["objects"] as { context_id: string; version?: string }[]).map((o) => {
      const ver = o.version ?? st.latest[o.context_id];
      const deny = st.revokedVersions.has(`${o.context_id}@${ver ?? ""}`) || (agent !== undefined && st.denyAgents.has(agent));
      const v: Record<string, unknown> = {
        context_id: o.context_id,
        decision: deny ? "DENY" : "ALLOW",
        reason: [deny ? "ANCESTOR_ACL_REVOKED" : "OK"],
      };
      if (ver !== undefined) v["version"] = ver;
      return v;
    });
    const all = objs.every((o) => o["decision"] === "ALLOW");
    return json({
      decision: all ? "ALLOW" : "DENY",
      reason: [all ? "OK" : "ANCESTOR_ACL_REVOKED"],
      revocation_epoch: 1,
      policy_version: st.policy,
      trace_id: "trace-1",
      objects: objs,
    });
  });
  return st;
}

describe("ledger: agent_id in the cache key", () => {
  it("key has an agent component", () => {
    expect(makeKey("t", "user", "u", "p", "c", "1", "pv", "a")).not.toBe(makeKey("t", "user", "u", "p", "c", "1", "pv", "b"));
    expect(JSON.parse(makeKey("t", "user", "u", "p", "c", null, "pv")) as unknown[]).toHaveLength(8);
  });

  it("an ALLOW cached for one agent never serves another", async () => {
    const st = fakeServer();
    const c = make(new FakeTime());
    expect((await c.authorize(alice, "rag", ["c1"], { agentId: "agent-a" })).allowed).toBe(true);
    const n = st.authCalls;
    expect((await c.authorize(alice, "rag", ["c1"], { agentId: "agent-a" })).fromCache).toBe(true);
    expect(st.authCalls).toBe(n);
    st.denyAgents.add("agent-b");
    const r = await c.authorize(alice, "rag", ["c1"], { agentId: "agent-b" });
    expect(r.fromCache).toBe(false);
    expect(r.decision).toBe("DENY");
    expect((await c.authorize(alice, "rag", ["c1"])).fromCache).toBe(false);
  });
});

describe("ledger: version-exact verdicts", () => {
  it("verdictFor matches exact versions only", () => {
    const mk = (decision: string, version: string | null) => ({ contextId: "c", decision, reason: [], version, validUntil: null });
    const r = new AuthorizeResult({
      decision: "DENY",
      reason: [],
      revocationEpoch: 1,
      policyVersion: "p",
      traceId: "t",
      objects: [mk("ALLOW", "1"), mk("DENY", "2")],
    });
    expect(r.verdictFor("c", "1")?.decision).toBe("ALLOW");
    expect(r.verdictFor("c", "2")?.decision).toBe("DENY");
    expect(r.verdictFor("c", "3")).toBeUndefined();
    expect(r.verdictFor("c")?.decision).toBe("DENY");
  });

  it("a mixed-version batch is mapped and cached per version", async () => {
    const st = fakeServer();
    st.revokedVersions.add("c1@1");
    const c = make(new FakeTime());
    const r = await c.authorize(alice, "rag", [["c1", "1"], ["c1", "2"]]); // revoked v1 first, allowed v2 second
    expect(r.verdictFor("c1", "1")?.decision).toBe("DENY");
    expect(r.verdictFor("c1", "2")?.decision).toBe("ALLOW");
    const n = st.authCalls;
    const r1 = await c.authorize(alice, "rag", [["c1", "1"]]);
    expect(r1.decision).toBe("DENY");
    expect(r1.fromCache).toBe(false); // v2's ALLOW must never be cached under v1
    expect(st.authCalls).toBe(n + 1);
    expect((await c.authorize(alice, "rag", [["c1", "2"]])).fromCache).toBe(true);
  });

  it("an omitted version is matched by the response version", async () => {
    const st = fakeServer();
    st.latest["c1"] = "7";
    st.revokedVersions.add("c1@7");
    const c = make(new FakeTime());
    expect((await c.authorize(alice, "rag", ["c1"])).decision).toBe("DENY");
    st.revokedVersions.clear();
    const r = await c.authorize(alice, "rag", ["c1"]);
    expect(r.verdictFor("c1", "7")?.decision).toBe("ALLOW");
    expect(r.verdictFor("c1")?.version).toBe("7");
  });
});

describe("ledger: versioned session taint", () => {
  it("tainted v1 is fine while v2 is revoked, and vice versa", async () => {
    const st = fakeServer();
    const c = make(new FakeTime());
    c.sessionTaint.record("a", [["c1", "1"]], { principal: alice, purpose: "rag" });
    c.sessionTaint.record("b", [["c1", "2"]], { principal: alice, purpose: "rag" });
    c.sessionTaint.record("both", [["c1", "1"], ["c1", "2"]], { principal: alice, purpose: "rag" });
    st.revokedVersions.add("c1@2");
    expect((await enforce("a", c)).resetRequired).toBe(false);
    expect((await enforce("b", c)).resetRequired).toBe(true);
    const both = await enforce("both", c);
    expect(both.resetRequired).toBe(true);
    expect(both.checked).toBe(2);
    expect(both.revoked.map((v) => v.version)).toEqual(["2"]);
    st.revokedVersions.clear();
    st.revokedVersions.add("c1@1");
    c.cache.clear(); // the fake flips revocation without an epoch bump
    expect((await enforce("a", c)).resetRequired).toBe(true);
    expect((await enforce("b", c)).resetRequired).toBe(false);
  });
});

describe("ledger: policy_version coupling to the snapshot", () => {
  it("a response under a new policy drops the held snapshot and its offline cache", async () => {
    const t = new FakeTime();
    const signer = await makeSigner();
    let policy = "p1";
    let up = true;
    let snapOk = true;
    stubFetch(async (url) => {
      if (!up) throw new TypeError("fetch failed");
      if (url.pathname === "/v1/snapshot") {
        if (!snapOk) return json({ detail: "no snapshot" }, 500);
        return json(await signer.sign(snapshotPayload({ revocation_epoch: 1, policy_version: policy }, t.wall), "k1"));
      }
      return json({
        decision: "ALLOW",
        reason: ["OK"],
        revocation_epoch: 1,
        policy_version: policy,
        trace_id: "x",
        objects: [{ context_id: "c1", decision: "ALLOW", reason: ["OK"] }],
      });
    });
    const c = make(t, { failMode: "BOUNDED_OFFLINE", snapshotPublicKey: { k1: signer.publicKeyB64 } });
    expect((await c.authorize(alice, "rag", ["c1"])).allowed).toBe(true);
    expect(c.snapshot?.policyVersion).toBe("p1");
    policy = "p2";
    snapOk = false;
    expect((await c.authorize(alice, "rag2", ["c1"])).allowed).toBe(true); // response carries p2
    expect(c.snapshot).toBeNull();
    up = false;
    const r = await c.authorize(alice, "rag2", ["c1"]);
    expect(r.decision).toBe("UNKNOWN");
    expect(r.fromCache).toBe(false);
  });
});
