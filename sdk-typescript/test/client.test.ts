import { afterEach, describe, expect, it, vi } from "vitest";
import {
  AlesConnectionError,
  AlesTimeoutError,
  AuthError,
  ConfigError,
  InvalidRequestError,
  InvariantClient,
  RequestTooLargeError,
  ResponseError,
  ServerUnavailableError,
  TenantMismatchError,
  SessionTaint,
  enforce,
  type ContextEnvelope,
  type InvariantClientOptions,
} from "../src/index.js";
import {
  FakeTime,
  TENANT,
  authResponse,
  bodyOf,
  headerOf,
  json,
  makeSigner,
  snapshotPayload,
  stubFetch,
  urlString,
} from "./helpers.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

function make(t: FakeTime, over: Partial<InvariantClientOptions> = {}) {
  const sleeps: number[] = [];
  const client = new InvariantClient({
    baseUrl: "http://ales.test/",
    tenantId: TENANT,
    authToken: "secret-token",
    clock: t.clock,
    wallClock: t.wallClock,
    sleep: (s) => {
      sleeps.push(s);
      return Promise.resolve();
    },
    random: () => 0.5,
    ...over,
  });
  return { client, sleeps };
}

const alice = { type: "user", id: "alice" };

describe("construction", () => {
  it("requires an authToken unless allowAnonymous", () => {
    expect(() => new InvariantClient({ baseUrl: "http://x", tenantId: "t" })).toThrow(ConfigError);
    expect(() => new InvariantClient({ baseUrl: "http://x", tenantId: "t", authToken: "  " })).toThrow(ConfigError);
    expect(() => new InvariantClient({ baseUrl: "http://x", tenantId: "t", authToken: "a b" })).toThrow(ConfigError);
    expect(() => new InvariantClient({ baseUrl: "http://x", tenantId: "t", allowAnonymous: true })).not.toThrow();
  });

  it("validates fail mode, retries and BOUNDED_OFFLINE key requirement", () => {
    const base = { baseUrl: "http://x", tenantId: "t", authToken: "k" };
    expect(() => new InvariantClient({ ...base, failMode: "NOPE" })).toThrow(ConfigError);
    expect(() => new InvariantClient({ ...base, maxRetries: -1 })).toThrow(ConfigError);
    expect(() => new InvariantClient({ ...base, failMode: "BOUNDED_OFFLINE" })).toThrow(ConfigError);
    expect(() => new InvariantClient({ ...base, tenantId: "" })).toThrow(ConfigError);
  });

  it("does not leak the token in its string form", () => {
    const { client } = make(new FakeTime());
    expect(String(client)).not.toContain("secret-token");
  });
});

describe("transport", () => {
  it("sends the bearer token, tenant header and a JSON content type", async () => {
    const t = new FakeTime();
    const f = stubFetch(() => json({ context_id: "c1", object_version: "1", tenant_id: TENANT }));
    const { client } = make(t);
    await client.registerSource(envelope("c1"));
    const [url, init] = f.mock.calls[0] ?? [];
    expect(urlString(url)).toBe("http://ales.test/v1/sources");
    expect(init?.method).toBe("POST");
    expect(headerOf(init, "Authorization")).toBe("Bearer secret-token");
    expect(headerOf(init, "X-Tenant-Id")).toBe(TENANT);
    expect(headerOf(init, "Content-Type")).toBe("application/json");
  });

  it("omits Authorization in anonymous mode", async () => {
    const f = stubFetch(() => json({ status: "ok" }));
    const client = new InvariantClient({ baseUrl: "http://ales.test", tenantId: TENANT, allowAnonymous: true });
    await client.healthz();
    expect(headerOf(f.mock.calls[0]?.[1], "Authorization")).toBeUndefined();
  });

  it("retries a GET on transient 503 and then succeeds, with jittered backoff", async () => {
    const t = new FakeTime();
    let n = 0;
    const f = stubFetch(() => (++n < 3 ? json({ detail: "busy" }, 503) : json({ context_id: "c1", ancestors: [] })));
    const { client, sleeps } = make(t, { retryBackoff: 0.1 });
    const out = await client.lineage("c1");
    expect(out["context_id"]).toBe("c1");
    expect(f).toHaveBeenCalledTimes(3);
    // full jitter with random()=0.5: 0.5 * 0.1 * 2^attempt
    expect(sleeps).toEqual([0.05, 0.1]);
    expect(urlString(f.mock.calls[0]?.[0])).toBe(`http://ales.test/v1/lineage/c1?tenant_id=${TENANT}`);
  });

  it("retries on 429/502/504 and on transport errors", async () => {
    for (const status of [429, 502, 504]) {
      let n = 0;
      const f = stubFetch(() => (++n < 2 ? json({}, status) : json({ ok: true })));
      const { client } = make(new FakeTime());
      await client.lineage("c1");
      expect(f).toHaveBeenCalledTimes(2);
    }
    let n = 0;
    const f = stubFetch(() => {
      if (++n < 2) throw new TypeError("fetch failed");
      return json({ ok: true });
    });
    await make(new FakeTime()).client.lineage("c1");
    expect(f).toHaveBeenCalledTimes(2);
  });

  it("gives up after maxRetries with the typed error", async () => {
    const f = stubFetch(() => json({ detail: "down" }, 503));
    const { client } = make(new FakeTime(), { maxRetries: 2 });
    await expect(client.lineage("c1")).rejects.toBeInstanceOf(ServerUnavailableError);
    expect(f).toHaveBeenCalledTimes(3);
    stubFetch(() => {
      throw new TypeError("fetch failed");
    });
    await expect(client.lineage("c1")).rejects.toBeInstanceOf(AlesConnectionError);
  });

  it("does not retry non-idempotent POSTs (register / revoke)", async () => {
    const f = stubFetch(() => json({ detail: "busy" }, 503));
    const { client } = make(new FakeTime());
    await expect(client.registerSource(envelope("c1"))).rejects.toBeInstanceOf(ServerUnavailableError);
    await expect(client.submitRevocation({ source_id: "c1", reason: "deleted" })).rejects.toBeInstanceOf(ServerUnavailableError);
    expect(f).toHaveBeenCalledTimes(2);
  });

  it("does not retry 4xx", async () => {
    const f = stubFetch(() => json({ detail: "nope" }, 404));
    await expect(make(new FakeTime()).client.lineage("c1")).rejects.toMatchObject({ statusCode: 404 });
    expect(f).toHaveBeenCalledTimes(1);
  });

  it("maps 401/403 to AuthError and a tenant 403 to TenantMismatchError (never retried)", async () => {
    let f = stubFetch(() => json({ detail: "invalid token" }, 401));
    const { client } = make(new FakeTime());
    await expect(client.lineage("c1")).rejects.toBeInstanceOf(AuthError);
    expect(f).toHaveBeenCalledTimes(1);
    f = stubFetch(() => json({ error: "forbidden", detail: "tenant mismatch with credential" }, 403));
    const err = await client.lineage("c1").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(TenantMismatchError);
    expect(err).toBeInstanceOf(AuthError);
    expect(f).toHaveBeenCalledTimes(1);
    stubFetch(() => json({ detail: "role required: ingest" }, 403));
    const err2 = await client.lineage("c1").catch((e: unknown) => e);
    expect(err2).toBeInstanceOf(AuthError);
    expect(err2).not.toBeInstanceOf(TenantMismatchError);
  });

  it("guards request size client-side without calling the network", async () => {
    const f = stubFetch(() => json({}));
    const { client } = make(new FakeTime());
    const big = { ...envelope("c1"), source_system: "x".repeat(1_100_000) };
    await expect(client.registerSource(big)).rejects.toBeInstanceOf(RequestTooLargeError);
    await expect(client.registerSource(big)).rejects.toBeInstanceOf(InvalidRequestError);
    expect(f).not.toHaveBeenCalled();
  });

  it("rejects non-JSON-serialisable bodies", async () => {
    stubFetch(() => json({}));
    const { client } = make(new FakeTime());
    await expect(
      client.registerSource({ ...envelope("c1"), expires_at: undefined, parent_refs: [{ n: Number.NaN }] as never }),
    ).rejects.toBeInstanceOf(InvalidRequestError);
  });

  it("ResponseError on a 2xx non-JSON body", async () => {
    stubFetch(() => new Response("<html>", { status: 200 }));
    await expect(make(new FakeTime()).client.lineage("c1")).rejects.toBeInstanceOf(ResponseError);
  });

  it("times out with AlesTimeoutError", async () => {
    stubFetch(
      (_u, init) =>
        new Promise<Response>((_res, rej) => {
          init.signal?.addEventListener("abort", () => rej(new DOMException("aborted", "AbortError")));
        }),
    );
    const { client } = make(new FakeTime(), { timeoutMs: 20, maxRetries: 0 });
    await expect(client.lineage("c1")).rejects.toBeInstanceOf(AlesTimeoutError);
  });
});

describe("authorize + decision cache", () => {
  it("caches ALLOW and serves the second call without the server", async () => {
    const t = new FakeTime();
    const f = stubFetch(() => json(authResponse({ ids: ["c1"] })));
    const { client } = make(t);
    const r1 = await client.authorize(alice, "rag", ["c1"]);
    expect(r1.allowed).toBe(true);
    expect(r1.fromCache).toBe(false);
    const r2 = await client.authorize(alice, "rag", ["c1"]);
    expect(r2.allowed).toBe(true);
    expect(r2.fromCache).toBe(true);
    expect(f).toHaveBeenCalledTimes(1);
    const body = bodyOf(f.mock.calls[0]?.[1]);
    expect(body).toMatchObject({ tenant_id: TENANT, principal: { type: "user", id: "alice" }, purpose: "rag", objects: [{ context_id: "c1" }] });
  });

  it("isolates cache entries by principal type, tenant-bound key and purpose", async () => {
    const f = stubFetch(() => json(authResponse({ ids: ["c1"] })));
    const { client } = make(new FakeTime());
    await client.authorize({ type: "user", id: "x" }, "rag", ["c1"]);
    await client.authorize({ type: "service", id: "x" }, "rag", ["c1"]);
    await client.authorize({ type: "user", id: "x" }, "other", ["c1"]);
    expect(f).toHaveBeenCalledTimes(3);
  });

  it("never caches DENY", async () => {
    const f = stubFetch(() => json(authResponse({ decision: "DENY", ids: ["c1"] })));
    const { client } = make(new FakeTime());
    expect((await client.authorize(alice, "rag", ["c1"])).decision).toBe("DENY");
    expect((await client.authorize(alice, "rag", ["c1"])).decision).toBe("DENY");
    expect(f).toHaveBeenCalledTimes(2);
    expect(client.cache.size).toBe(0);
  });

  it("epoch advance (via revocation response) invalidates cached ALLOWs", async () => {
    let revoked = false;
    const f = stubFetch((url) => {
      if (url.pathname === "/v1/revocations") {
        revoked = true;
        return json({ event_id: "e", revocation_epoch: 2 });
      }
      return json(authResponse({ decision: revoked ? "DENY" : "ALLOW", ids: ["c1"], epoch: revoked ? 2 : 1 }));
    });
    const { client } = make(new FakeTime());
    expect((await client.authorize(alice, "rag", ["c1"])).allowed).toBe(true);
    await client.submitRevocation({ source_id: "c1", reason: "deleted" });
    expect((await client.authorize(alice, "rag", ["c1"])).decision).toBe("DENY");
    expect(f.mock.calls.filter(([u]) => urlString(u).endsWith("/v1/authorize"))).toHaveLength(2);
  });

  it("refuses to cache an ALLOW whose valid_until is inside the skew window, and an unparseable one", async () => {
    const t = new FakeTime();
    const soon = new Date((t.wall + 10) * 1000).toISOString();
    const f = stubFetch(() => json(authResponse({ ids: ["c1"], validUntil: soon })));
    const { client } = make(t);
    await client.authorize(alice, "rag", ["c1"]);
    await client.authorize(alice, "rag", ["c1"]);
    expect(f).toHaveBeenCalledTimes(2);
    stubFetch(() => json(authResponse({ ids: ["c2"], validUntil: "garbage" })));
    await client.authorize(alice, "rag", ["c2"]);
    expect(client.cache.size).toBe(0);
  });

  it("caches an ALLOW with a distant valid_until, then stops serving it near the cutover", async () => {
    const t = new FakeTime();
    const far = new Date((t.wall + 600) * 1000).toISOString();
    const f = stubFetch(() => json(authResponse({ ids: ["c1"], validUntil: far })));
    const { client } = make(t);
    await client.authorize(alice, "rag", ["c1"]);
    t.advance(10);
    expect((await client.authorize(alice, "rag", ["c1"])).fromCache).toBe(true);
    t.wall += 561; // inside 30s of valid_until, monotonic TTL untouched
    t.mono -= 0;
    expect((await client.authorize(alice, "rag", ["c1"])).fromCache).toBe(false);
    expect(f).toHaveBeenCalledTimes(2);
  });

  it("a policy_version change clears the cache", async () => {
    let pv = "p1";
    const f = stubFetch(() => json(authResponse({ ids: ["c1", "c2"], policy: pv })));
    const { client } = make(new FakeTime());
    await client.authorize(alice, "rag", ["c1"]);
    pv = "p2";
    await client.authorize(alice, "rag", ["c2"]); // new policy seen -> old entries cleared
    pv = "p2";
    await client.authorize(alice, "rag", ["c1"]);
    expect(f).toHaveBeenCalledTimes(3);
  });

  it("a partially cached batch goes to the server", async () => {
    const f = stubFetch((_u, init) => json(authResponse({ ids: (bodyOf(init)["objects"] as { context_id: string }[]).map((o) => o.context_id) })));
    const { client } = make(new FakeTime());
    await client.authorize(alice, "rag", ["c1"]);
    await client.authorize(alice, "rag", ["c1", "c2"]);
    expect(f).toHaveBeenCalledTimes(2);
  });

  it("retries authorize on transient 503 then succeeds", async () => {
    let n = 0;
    const f = stubFetch(() => (++n === 1 ? json({ detail: "busy" }, 503) : json(authResponse({ ids: ["c1"] }))));
    const { client, sleeps } = make(new FakeTime());
    expect((await client.authorize(alice, "rag", ["c1"])).allowed).toBe(true);
    expect(f).toHaveBeenCalledTimes(2);
    expect(sleeps).toHaveLength(1);
  });

  it("UNKNOWN (fail closed) when the server is unreachable in every non-offline mode", async () => {
    for (const failMode of ["OBSERVE", "WARN", "ENFORCE"]) {
      stubFetch(() => {
        throw new TypeError("fetch failed");
      });
      const { client } = make(new FakeTime(), { failMode, maxRetries: 1 });
      const r = await client.authorize(alice, "rag", ["c1"]);
      expect(r.decision).toBe("UNKNOWN");
      expect(r.offline).toBe(true);
      expect(r.reason).toEqual(["POLICY_SNAPSHOT_STALE"]);
      expect(r.objects[0]?.decision).toBe("UNKNOWN");
    }
  });

  it("surfaces auth failures instead of treating them as offline", async () => {
    stubFetch(() => json({ detail: "bad token" }, 401));
    await expect(make(new FakeTime()).client.authorize(alice, "rag", ["c1"])).rejects.toBeInstanceOf(AuthError);
  });

  it("validates inputs", async () => {
    const { client } = make(new FakeTime());
    await expect(client.authorize(alice, "rag", [])).rejects.toBeInstanceOf(InvalidRequestError);
    await expect(client.authorize({ id: "" }, "rag", ["c1"])).rejects.toBeInstanceOf(InvalidRequestError);
  });

  it("malformed authorize response -> ResponseError", async () => {
    stubFetch(() => json({ decision: "ALLOW" }));
    await expect(make(new FakeTime()).client.authorize(alice, "rag", ["c1"])).rejects.toBeInstanceOf(ResponseError);
  });

  it("accepts object refs as tuples and objects, forwarding versions", async () => {
    const f = stubFetch(() => json(authResponse({ ids: ["c1", "c2"] })));
    const { client } = make(new FakeTime());
    await client.authorize(alice, "rag", [["c1", "3"], { context_id: "c2", version: "4" }], { agentId: "ag", sessionId: "s1" });
    const body = bodyOf(f.mock.calls[0]?.[1]);
    expect(body["objects"]).toEqual([
      { context_id: "c1", version: "3" },
      { context_id: "c2", version: "4" },
    ]);
    expect(body["agent_id"]).toBe("ag");
    expect(body["session_id"]).toBe("s1");
  });
});

describe("BOUNDED_OFFLINE", () => {
  async function setup() {
    const t = new FakeTime();
    const signer = await makeSigner();
    let serverUp = true;
    let epoch = 1;
    const f = stubFetch(async (url) => {
      if (!serverUp) throw new TypeError("fetch failed");
      if (url.pathname === "/v1/snapshot") {
        return json(await signer.sign(snapshotPayload({ revocation_epoch: epoch, lease_seconds: 60 }, t.wall), "k1"));
      }
      return json(authResponse({ ids: ["c1"], epoch }));
    });
    const { client } = make(t, {
      failMode: "BOUNDED_OFFLINE",
      snapshotPublicKey: { k1: signer.publicKeyB64 },
      maxRetries: 0,
    });
    return {
      t,
      client,
      f,
      down: () => {
        serverUp = false;
      },
      setEpoch: (e: number) => {
        epoch = e;
      },
    };
  }

  it("serves a cached ALLOW offline only inside the verified lease", async () => {
    const { t, client, down, f } = await setup();
    expect((await client.authorize(alice, "rag", ["c1"])).allowed).toBe(true);
    expect(client.snapshotValid()).toBe(true);
    down();
    t.advance(20);
    const offline = await client.authorize(alice, "rag", ["c1"]);
    expect(offline.allowed).toBe(true);
    expect(offline.fromCache).toBe(true);
    const calls = f.mock.calls.length;
    t.advance(45); // lease (60s) exhausted
    const expired = await client.authorize(alice, "rag", ["c1"]);
    expect(expired.decision).toBe("UNKNOWN");
    expect(expired.reason).toEqual(["POLICY_SNAPSHOT_STALE"]);
    expect(expired.leaseOk).toBe(false);
    expect(f.mock.calls.length).toBeGreaterThan(calls);
  });

  it("denies offline with no snapshot ever obtained", async () => {
    const t = new FakeTime();
    const signer = await makeSigner();
    stubFetch(() => {
      throw new TypeError("fetch failed");
    });
    const { client } = make(t, { failMode: "BOUNDED_OFFLINE", snapshotPublicKey: signer.publicKeyB64, maxRetries: 0 });
    const r = await client.authorize(alice, "rag", ["c1"]);
    expect(r.decision).toBe("UNKNOWN");
    expect(r.leaseOk).toBe(false);
  });

  it("an epoch advance observed at the server is never masked by the cache", async () => {
    const { client, setEpoch, f } = await setup();
    await client.authorize(alice, "rag", ["c1"]);
    setEpoch(2); // server revoked something: new snapshot + decision epoch
    await client.refreshSnapshot();
    const before = f.mock.calls.length;
    const r = await client.authorize(alice, "rag", ["c1"]); // epoch-1 cache entry was invalidated
    expect(r.fromCache).toBe(false);
    expect(f.mock.calls.length).toBeGreaterThan(before);
  });
});

describe("session taint", () => {
  it("enforce re-authorizes recorded exposures and flags revoked ones", async () => {
    const t = new FakeTime();
    let revoked = false;
    stubFetch((_u, init) => {
      const ids = (bodyOf(init)["objects"] as { context_id: string }[]).map((o) => o.context_id);
      return json(authResponse({ ids, perObject: revoked ? { c2: "DENY" } : {}, epoch: revoked ? 2 : 1 }));
    });
    const { client } = make(t);
    client.sessionTaint.record("s1", ["c1", "c2"], { principal: alice, purpose: "rag", versions: { c1: "1" } });
    const ok = await enforce("s1", client);
    expect(ok.resetRequired).toBe(false);
    expect(ok.checked).toBe(2);
    revoked = true;
    t.advance(31); // let the cached ALLOWs lapse (TTL cap 30s)
    const bad = await enforce("s1", client);
    expect(bad.resetRequired).toBe(true);
    expect(bad.revoked.map((v) => v.contextId)).toEqual(["c2"]);
  });

  it("exposures recorded without principal/purpose are unverifiable and force a reset", async () => {
    const f = stubFetch(() => json(authResponse({ ids: ["c1"] })));
    const { client } = make(new FakeTime());
    client.sessionTaint.record("s1", ["c1"]);
    const v = await enforce("s1", client);
    expect(v.resetRequired).toBe(true);
    expect(v.unverifiable).toEqual(["c1"]);
    expect(f).not.toHaveBeenCalled();
    const fixed = await enforce("s1", client, { principal: alice, purpose: "rag" });
    expect(fixed.resetRequired).toBe(false);
    await expect(enforce("s1", client, { principal: alice })).rejects.toBeInstanceOf(TypeError);
  });

  it("a missing verdict fails closed; isTainted / clear work", async () => {
    stubFetch(() => json(authResponse({ ids: [] })));
    const { client } = make(new FakeTime());
    client.sessionTaint.record("s1", ["c1"], { principal: alice, purpose: "rag" });
    const v = await enforce("s1", client);
    expect(v.resetRequired).toBe(true);
    expect(v.revoked[0]?.reason).toEqual(["OBJECT_UNKNOWN"]);
    const st = new SessionTaint();
    st.record("s", ["a", "b"]);
    expect(st.isTainted("s", ["b"])).toBe(true);
    expect(st.isTainted("s", ["z"])).toBe(false);
    st.clear("s");
    expect(st.isTainted("s", ["b"])).toBe(false);
  });
});

function envelope(id: string): ContextEnvelope {
  return {
    context_id: id,
    tenant_id: TENANT,
    object_id: "doc",
    object_version: "1",
    content_digest: "sha256:" + "0".repeat(64),
    kind: "source",
    source_system: "test",
    classification: "internal",
    trust_state: "verified",
    parent_refs: [],
    policy_version: "v1",
    valid_from: "2026-01-01T00:00:00Z",
  };
}
