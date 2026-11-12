import { afterEach, describe, expect, it, vi } from "vitest";
import { ConfigError, SnapshotError } from "../src/errors.js";
import { SnapshotKeys, b64encode, parsePublicKey, snapshotValidAt, verifySnapshot } from "../src/snapshot.js";
import { InvariantClient } from "../src/client.js";
import { FakeTime, T0_WALL, TENANT, json, makeSigner, snapshotPayload, stubFetch } from "./helpers.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

async function verify(data: unknown, keys: SnapshotKeys, over: { wall?: number; tenant?: string } = {}) {
  return verifySnapshot(data, {
    keys,
    tenantId: over.tenant ?? TENANT,
    receivedAt: 500,
    wallNow: over.wall ?? T0_WALL,
  });
}

async function reason(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    if (e instanceof SnapshotError) return e.reason;
    throw e;
  }
  return "no error";
}

describe("verifySnapshot", () => {
  it("accepts a correctly signed snapshot", async () => {
    const s = await makeSigner();
    const keys = new SnapshotKeys(s.publicKeyB64);
    const snap = await verify(await s.sign(snapshotPayload({ revocation_epoch: 7 })), keys);
    expect(snap.revocationEpoch).toBe(7);
    expect(snap.policyVersion).toBe("p1");
    expect(snap.effectiveLease).toBe(60);
    expect(snapshotValidAt(snap, 559.9)).toBe(true);
    expect(snapshotValidAt(snap, 560)).toBe(false);
  });

  it("key_id and signature are not part of the signed bytes", async () => {
    const s = await makeSigner();
    const keys = new SnapshotKeys({ k1: s.publicKeyB64 });
    const signed = await s.sign(snapshotPayload(), "k1");
    expect((await verify(signed, keys)).keyId).toBe("k1");
    expect(await reason(verify({ ...signed, key_id: "other" }, keys))).toBe("unknown_key_id");
  });

  it("rejects a tampered payload", async () => {
    const s = await makeSigner();
    const keys = new SnapshotKeys(s.publicKeyB64);
    const signed = await s.sign(snapshotPayload({ revocation_epoch: 1 }));
    expect(await reason(verify({ ...signed, revocation_epoch: 0 }, keys))).toBe("bad_signature");
    expect(await reason(verify({ ...signed, lease_seconds: 3600 }, keys))).toBe("bad_signature");
    expect(await reason(verify({ ...signed, extra: "member" }, keys))).toBe("bad_signature");
  });

  it("rejects a signature from a different key", async () => {
    const a = await makeSigner();
    const b = await makeSigner();
    expect(await reason(verify(await a.sign(snapshotPayload()), new SnapshotKeys(b.publicKeyB64)))).toBe("bad_signature");
  });

  it("rejects a missing or malformed signature", async () => {
    const s = await makeSigner();
    const keys = new SnapshotKeys(s.publicKeyB64);
    expect(await reason(verify(snapshotPayload(), keys))).toBe("missing_signature");
    expect(await reason(verify({ ...snapshotPayload(), signature: "!!!notbase64" }, keys))).toBe("bad_signature");
    expect(await reason(verify({ ...snapshotPayload(), signature: "AAAA" }, keys))).toBe("bad_signature");
  });

  it("rejects an expired snapshot (lease spent on arrival)", async () => {
    const s = await makeSigner();
    const keys = new SnapshotKeys(s.publicKeyB64);
    const old = await s.sign(snapshotPayload({ lease_seconds: 60 }, T0_WALL - 3600));
    expect(await reason(verify(old, keys))).toBe("expired");
  });

  it("deducts replay age beyond the 30s skew from the lease", async () => {
    const s = await makeSigner();
    const keys = new SnapshotKeys(s.publicKeyB64);
    const signed = await s.sign(snapshotPayload({ lease_seconds: 60 }, T0_WALL - 50)); // age 50 -> deduct 20
    const snap = await verify(signed, keys);
    expect(snap.effectiveLease).toBeCloseTo(40, 3);
    const young = await s.sign(snapshotPayload({ lease_seconds: 60 }, T0_WALL - 20)); // within skew
    expect((await verify(young, keys)).effectiveLease).toBe(60);
  });

  it("rejects a snapshot for another tenant", async () => {
    const s = await makeSigner();
    const keys = new SnapshotKeys(s.publicKeyB64);
    expect(await reason(verify(await s.sign(snapshotPayload({ tenant_id: "other" })), keys))).toBe("tenant_mismatch");
  });

  it("rejects malformed fields (even when validly signed)", async () => {
    const s = await makeSigner();
    const keys = new SnapshotKeys(s.publicKeyB64);
    for (const over of [
      { revocation_epoch: -1 },
      { revocation_epoch: "1" },
      { lease_seconds: 0 },
      { issued_at: "not-a-date" },
      { issued_at: "2026-01-01T00:00:00" }, // no timezone
      { policy_version: 3 },
    ]) {
      expect(await reason(verify(await s.sign(snapshotPayload(over)), keys))).toBe("bad_format");
    }
    expect(await reason(verify(await s.sign(snapshotPayload({ revocation_epoch: 1.5 })), keys))).toBe("bad_format");
    expect(await reason(verify("nope", keys))).toBe("bad_format");
  });

  it("accepts +00:00 offsets as produced by the Python server", async () => {
    const s = await makeSigner();
    const keys = new SnapshotKeys(s.publicKeyB64);
    const iso = new Date(T0_WALL * 1000).toISOString().replace(/\.\d+Z$/, "+00:00");
    expect((await verify(await s.sign(snapshotPayload({ issued_at: iso })), keys)).leaseSeconds).toBe(60);
  });
});

describe("public key parsing", () => {
  it("accepts base64, url-safe base64, raw bytes and PEM; rejects wrong sizes", async () => {
    const s = await makeSigner();
    const raw = parsePublicKey(s.publicKeyB64);
    expect(raw).toEqual(s.publicKeyRaw);
    expect(parsePublicKey(s.publicKeyRaw)).toEqual(s.publicKeyRaw);
    expect(parsePublicKey(s.publicKeyB64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""))).toEqual(s.publicKeyRaw);
    const spki = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, ...s.publicKeyRaw]);
    const pem = `-----BEGIN PUBLIC KEY-----\n${b64encode(spki)}\n-----END PUBLIC KEY-----\n`;
    expect(parsePublicKey(pem)).toEqual(s.publicKeyRaw);
    expect(() => parsePublicKey("AAAA")).toThrow(ConfigError);
    expect(() => parsePublicKey(new Uint8Array(31))).toThrow(ConfigError);
    expect(() => parsePublicKey("***")).toThrow(ConfigError);
    expect(() => new SnapshotKeys({})).toThrow(ConfigError);
  });
});

describe("client snapshot refresh", () => {
  function makeClient(s: Awaited<ReturnType<typeof makeSigner>>, t: FakeTime) {
    return new InvariantClient({
      baseUrl: "http://ales.test",
      tenantId: TENANT,
      authToken: "tok",
      failMode: "BOUNDED_OFFLINE",
      snapshotPublicKey: s.publicKeyB64,
      clock: t.clock,
      wallClock: t.wallClock,
      sleep: () => Promise.resolve(),
      random: () => 0,
    });
  }

  it("rejects epoch regression, discards the held snapshot, and records the error", async () => {
    const s = await makeSigner();
    const t = new FakeTime();
    const epochs = [5, 3];
    stubFetch(async () => json(await s.sign(snapshotPayload({ revocation_epoch: epochs.shift() ?? 0 }, t.wall))));
    const c = makeClient(s, t);
    expect((await c.refreshSnapshot()).revocationEpoch).toBe(5);
    expect(c.snapshotValid()).toBe(true);
    await expect(c.refreshSnapshot()).rejects.toMatchObject({ reason: "epoch_regression" });
    expect(c.snapshot).toBeNull();
    expect(c.snapshotValid()).toBe(false);
    expect(c.lastSnapshotError?.reason).toBe("epoch_regression");
  });

  it("fails closed on a tampered snapshot", async () => {
    const s = await makeSigner();
    const t = new FakeTime();
    stubFetch(async () => json({ ...(await s.sign(snapshotPayload({}, t.wall))), revocation_epoch: 99 }));
    const c = makeClient(s, t);
    await expect(c.refreshSnapshot()).rejects.toMatchObject({ reason: "bad_signature" });
    expect(c.snapshot).toBeNull();
  });

  it("the lease lapses on the monotonic clock", async () => {
    const s = await makeSigner();
    const t = new FakeTime();
    stubFetch(async () => json(await s.sign(snapshotPayload({ lease_seconds: 60 }, t.wall))));
    const c = makeClient(s, t);
    await c.refreshSnapshot();
    t.mono += 59;
    expect(c.snapshotValid()).toBe(true);
    t.mono += 2;
    expect(c.snapshotValid()).toBe(false);
  });
});
