/**
 * Signed policy snapshot verification (SPEC v0.2). Port of ales_sdk.snapshot.
 *
 * `GET /v1/snapshot` returns `{tenant_id, revocation_epoch, policy_version, issued_at, lease_seconds,
 * signature, key_id?}`. The signature is Ed25519 over the RFC 8785 canonical JSON of the object minus
 * `signature` and `key_id`. All failures fail closed with {@link SnapshotError}.
 *
 * Caveat: JSON has one number type, so `1.0` and `1` are indistinguishable once parsed in JS. A signed
 * value such as `1.5` is rejected (`bad_format`); a float written as `1.0` cannot be told from `1`.
 */

import { ConfigError, SnapshotError } from "./errors.js";
import { canonicalBytes } from "./jcs.js";

export const UNSIGNED_FIELDS: readonly string[] = ["signature", "key_id"];
export const DEFAULT_MAX_CLOCK_SKEW = 30;

/** A snapshot public key: base64 (std or url-safe) of the raw 32 bytes, raw 32 bytes, or a PEM SPKI. */
export type PublicKeyInput = string | Uint8Array;
/** One key (matches any/absent key_id) or `{key_id: key}` for rotation. */
export type SnapshotPublicKeySpec = PublicKeyInput | Readonly<Record<string, PublicKeyInput>>;

/** Verified snapshot plus the client-side timing needed to judge its lease. */
export interface Snapshot {
  readonly tenantId: string;
  readonly revocationEpoch: number;
  readonly policyVersion: string;
  readonly issuedAt: Date;
  readonly leaseSeconds: number;
  readonly keyId: string | null;
  /** Client monotonic clock (seconds) at receipt. */
  readonly receivedAt: number;
  /** Lease actually granted after replay-age deduction. */
  readonly effectiveLease: number;
}

export function snapshotDeadline(snap: Snapshot, maxLease?: number): number {
  const lease = maxLease === undefined ? snap.effectiveLease : Math.min(snap.effectiveLease, maxLease);
  return snap.receivedAt + lease;
}

/** True while the monotonic clock `now` is strictly before the lease deadline. */
export function snapshotValidAt(snap: Snapshot, now: number, maxLease?: number): boolean {
  return now < snapshotDeadline(snap, maxLease);
}

export function canonicalSnapshotBytes(payload: Readonly<Record<string, unknown>>): Bytes {
  const obj: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(payload)) if (!UNSIGNED_FIELDS.includes(k)) obj[k] = v;
  rejectFloats(obj);
  return canonicalBytes(obj);
}

function rejectFloats(v: unknown): void {
  if (typeof v === "number" && !Number.isInteger(v)) {
    throw new SnapshotError("bad_format", "floats are not permitted in a signed snapshot");
  }
  if (Array.isArray(v)) for (const x of v) rejectFloats(x);
  else if (v !== null && typeof v === "object") for (const x of Object.values(v)) rejectFloats(x);
}

export type Bytes = Uint8Array<ArrayBuffer>;

export function b64decode(input: string): Bytes {
  const t = input.trim();
  if (!/^[A-Za-z0-9+/_-]*={0,2}$/.test(t) || (/[+/]/.test(t) && /[-_]/.test(t))) throw new Error("invalid base64");
  let s = t.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (s.length % 4 === 1) throw new Error("invalid base64");
  s += "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64encode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

const SPKI_ED25519_PREFIX = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);

/** Parse a public key into raw 32 bytes. Throws {@link ConfigError}. */
export function parsePublicKey(key: PublicKeyInput): Bytes {
  try {
    if (key instanceof Uint8Array) {
      if (key.length !== 32) throw new ConfigError(`snapshotPublicKey must be 32 bytes, got ${String(key.length)}`);
      return new Uint8Array(key);
    }
    if (key.includes("BEGIN PUBLIC KEY")) {
      const body = key.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");
      const der = b64decode(body);
      const prefixOk = SPKI_ED25519_PREFIX.every((b, i) => der[i] === b);
      if (der.length !== 44 || !prefixOk) throw new ConfigError("snapshotPublicKey PEM is not an Ed25519 key");
      return der.slice(12);
    }
    const raw = b64decode(key);
    if (raw.length !== 32) throw new ConfigError(`snapshotPublicKey must decode to 32 bytes, got ${String(raw.length)}`);
    return raw;
  } catch (e) {
    if (e instanceof ConfigError) throw e;
    throw new ConfigError(`invalid snapshotPublicKey: ${e instanceof Error ? e.message : String(e)}`, { cause: e });
  }
}

/** Configured verification keys; the single-key form is stored under `null`. */
export class SnapshotKeys {
  private readonly raw = new Map<string | null, Bytes>();
  private readonly imported = new Map<string | null, Promise<CryptoKey>>();

  constructor(spec: SnapshotPublicKeySpec) {
    if (typeof spec === "string" || spec instanceof Uint8Array) {
      this.raw.set(null, parsePublicKey(spec));
    } else {
      const entries = Object.entries(spec);
      if (entries.length === 0) throw new ConfigError("snapshotPublicKey mapping is empty");
      for (const [id, k] of entries) this.raw.set(id, parsePublicKey(k));
    }
  }

  has(keyId: string | null): boolean {
    return this.raw.has(keyId);
  }

  /** Key selection: a single configured key matches any/absent key_id; otherwise key_id must be configured. */
  select(keyId: string | null): string | null | undefined {
    if (this.raw.has(null)) return null;
    if (keyId !== null && this.raw.has(keyId)) return keyId;
    return undefined;
  }

  importKey(id: string | null): Promise<CryptoKey> {
    let p = this.imported.get(id);
    if (p === undefined) {
      const raw = this.raw.get(id);
      if (raw === undefined) return Promise.reject(new ConfigError("no such snapshot key"));
      p = crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
      this.imported.set(id, p);
    }
    return p;
  }
}

export interface VerifySnapshotOptions {
  keys: SnapshotKeys;
  tenantId: string;
  /** Client monotonic seconds at receipt. */
  receivedAt: number;
  /** Wall-clock epoch seconds now. */
  wallNow: number;
  maxClockSkew?: number;
}

/** Verify a `/v1/snapshot` response. Throws {@link SnapshotError} on any problem. */
export async function verifySnapshot(data: unknown, opts: VerifySnapshotOptions): Promise<Snapshot> {
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new SnapshotError("bad_format", "snapshot is not a JSON object");
  }
  const rec = data as Record<string, unknown>;
  const sigS = rec["signature"];
  if (typeof sigS !== "string" || sigS === "") throw new SnapshotError("missing_signature");
  const keyIdRaw = rec["key_id"];
  if (keyIdRaw !== undefined && keyIdRaw !== null && typeof keyIdRaw !== "string") {
    throw new SnapshotError("bad_format", "key_id must be a string");
  }
  const keyId = typeof keyIdRaw === "string" ? keyIdRaw : null;
  const selected = opts.keys.select(keyId);
  if (selected === undefined) {
    throw new SnapshotError("unknown_key_id", `key_id ${JSON.stringify(keyId)} is not a configured snapshot key`);
  }
  let ok = false;
  try {
    const sig = b64decode(sigS);
    const key = await opts.keys.importKey(selected);
    ok = sig.length === 64 && (await crypto.subtle.verify({ name: "Ed25519" }, key, sig, canonicalSnapshotBytes(rec)));
  } catch (e) {
    if (e instanceof SnapshotError) throw e; // floats -> bad_format
    ok = false;
  }
  if (!ok) throw new SnapshotError("bad_signature", "signature does not verify");

  // Fields are only trusted after the signature has verified.
  const tid = rec["tenant_id"];
  const epoch = rec["revocation_epoch"];
  const pv = rec["policy_version"];
  const issued = rec["issued_at"];
  const lease = rec["lease_seconds"];
  if (typeof tid !== "string" || typeof pv !== "string" || typeof issued !== "string") {
    throw new SnapshotError("bad_format", "tenant_id/policy_version/issued_at must be strings");
  }
  if (typeof epoch !== "number" || !Number.isSafeInteger(epoch) || epoch < 0) {
    throw new SnapshotError("bad_format", "revocation_epoch must be a non-negative integer");
  }
  if (typeof lease !== "number" || !Number.isSafeInteger(lease) || lease <= 0) {
    throw new SnapshotError("bad_format", "lease_seconds must be a positive integer");
  }
  if (tid !== opts.tenantId) {
    throw new SnapshotError(
      "tenant_mismatch",
      `snapshot is for tenant ${JSON.stringify(tid)}, client is ${JSON.stringify(opts.tenantId)}`,
    );
  }
  const issuedAt = parseRfc3339(issued);
  const skew = opts.maxClockSkew ?? DEFAULT_MAX_CLOCK_SKEW;
  const age = opts.wallNow - issuedAt.getTime() / 1000;
  const effective = lease - Math.max(0, age - skew);
  if (effective <= 0) {
    throw new SnapshotError("expired", `snapshot lease already spent on arrival (age ${age.toFixed(0)}s)`);
  }
  return {
    tenantId: tid,
    revocationEpoch: epoch,
    policyVersion: pv,
    issuedAt,
    leaseSeconds: lease,
    keyId,
    receivedAt: opts.receivedAt,
    effectiveLease: effective,
  };
}

const RFC3339 = /^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})?$/;

/** Parse an RFC 3339 timestamp that carries an explicit timezone, else throw SnapshotError(bad_format). */
export function parseRfc3339(value: string): Date {
  const m = RFC3339.exec(value);
  if (m === null) throw new SnapshotError("bad_format", `issued_at is not an RFC 3339 timestamp: ${JSON.stringify(value)}`);
  if (m[2] === undefined) throw new SnapshotError("bad_format", "issued_at must carry a timezone");
  const d = new Date(value.replace(" ", "T"));
  if (Number.isNaN(d.getTime())) {
    throw new SnapshotError("bad_format", `issued_at is not an RFC 3339 timestamp: ${JSON.stringify(value)}`);
  }
  return d;
}
