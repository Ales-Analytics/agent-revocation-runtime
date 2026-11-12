import { vi, type Mock } from "vitest";
import { b64encode } from "../src/snapshot.js";
import { canonicalBytes } from "../src/jcs.js";

export const TENANT = "tenant-1";
export const T0_WALL = 1_700_000_000;

/** Controllable clocks shared by the client and cache. */
export class FakeTime {
  mono = 1000;
  wall = T0_WALL;
  readonly clock = (): number => this.mono;
  readonly wallClock = (): number => this.wall;
  advance(seconds: number): void {
    this.mono += seconds;
    this.wall += seconds;
  }
}

export interface Signer {
  publicKeyB64: string;
  publicKeyRaw: Uint8Array;
  sign(payload: Record<string, unknown>, keyId?: string): Promise<Record<string, unknown>>;
}

export async function makeSigner(): Promise<Signer> {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return {
    publicKeyB64: b64encode(raw),
    publicKeyRaw: raw,
    async sign(payload, keyId) {
      const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, canonicalBytes(payload)));
      const out: Record<string, unknown> = { ...payload, signature: b64encode(sig) };
      if (keyId !== undefined) out["key_id"] = keyId;
      return out;
    },
  };
}

export function snapshotPayload(over: Partial<Record<string, unknown>> = {}, wall = T0_WALL): Record<string, unknown> {
  return {
    tenant_id: TENANT,
    revocation_epoch: 1,
    policy_version: "p1",
    issued_at: new Date(wall * 1000).toISOString(),
    lease_seconds: 60,
    ...over,
  };
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

export function authResponse(opts: {
  decision?: string;
  epoch?: number;
  policy?: string;
  ids: string[];
  perObject?: Record<string, string>;
  validUntil?: string | null;
}): Record<string, unknown> {
  const decision = opts.decision ?? "ALLOW";
  const objects = opts.ids.map((id) => {
    const d = opts.perObject?.[id] ?? decision;
    const o: Record<string, unknown> = { context_id: id, decision: d, reason: [d === "ALLOW" ? "OK" : "ANCESTOR_ACL_REVOKED"] };
    if (opts.validUntil !== undefined) o["valid_until"] = opts.validUntil;
    return o;
  });
  const overall = objects.every((o) => o["decision"] === "ALLOW") ? "ALLOW" : decision === "ALLOW" ? "DENY" : decision;
  return {
    decision: overall,
    reason: [overall === "ALLOW" ? "OK" : "ANCESTOR_ACL_REVOKED"],
    revocation_epoch: opts.epoch ?? 1,
    policy_version: opts.policy ?? "p1",
    trace_id: "trace-1",
    objects,
  };
}

export type Handler = (url: URL, init: RequestInit) => Response | Promise<Response>;

/** Install a router-based fetch mock via vi.stubGlobal; returns the vi.fn for call inspection. */
export function stubFetch(handler: Handler): Mock<typeof fetch> {
  const fn = vi.fn<typeof fetch>((input, init) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    return Promise.resolve(handler(url, init ?? {}));
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}

export function urlString(input: unknown): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  if (input instanceof Request) return input.url;
  throw new Error("unexpected fetch input");
}

export function headerOf(init: RequestInit | undefined, name: string): string | undefined {
  const h = init?.headers as Record<string, string> | undefined;
  return h?.[name];
}

export function bodyOf(init: RequestInit | undefined): Record<string, unknown> {
  const b = init?.body;
  if (!(b instanceof Uint8Array)) throw new Error("expected Uint8Array body");
  return JSON.parse(new TextDecoder().decode(b)) as Record<string, unknown>;
}
