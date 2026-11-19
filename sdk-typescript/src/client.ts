/** HTTP client for the ALES INVARIANT decision API using the native fetch implementation. */

import {
  DecisionCache,
  makeKey,
  monotonicNow,
  wallNow,
  type CacheKey,
  type Clock,
} from "./decisionCache.js";
import {
  AlesConnectionError,
  AlesHTTPError,
  AlesTimeoutError,
  AuthError,
  ConfigError,
  InvalidRequestError,
  RequestTooLargeError,
  ResponseError,
  ServerUnavailableError,
  SnapshotError,
  TenantMismatchError,
} from "./errors.js";
import { FailMode, parseFailMode } from "./failModes.js";
import { SessionTaint } from "./sessionTaint.js";
import {
  SnapshotKeys,
  snapshotDeadline,
  snapshotValidAt,
  verifySnapshot,
  type Snapshot,
  type SnapshotPublicKeySpec,
} from "./snapshot.js";

export const MAX_REQUEST_BYTES = 1_000_000;
export const DEFAULT_TIMEOUT_MS = 10_000;
export const RETRYABLE_STATUS: ReadonlySet<number> = new Set([429, 502, 503, 504]);
/** Min seconds between failed opportunistic snapshot fetches. */
export const SNAPSHOT_RETRY_INTERVAL = 1;

export type JsonObject = Record<string, unknown>;

export interface Principal {
  type?: string;
  id: string;
}

/** An object to authorize: a context id, `[contextId, version]`, or `{context_id, version?}`. */
export type ObjectRef = string | readonly [string, (string | null)?] | { context_id: string; version?: string | null };

export interface ParentRef {
  context_id: string;
  object_version: string;
}

/** Wire shape of a context envelope (spec/context_envelope.schema.json). */
export interface ContextEnvelope {
  context_id: string;
  tenant_id: string;
  object_id: string;
  object_version: string;
  content_digest: string;
  kind: "source" | "chunk" | "embedding" | "summary" | "memory" | "cache" | "artifact";
  source_system: string;
  source_acl_ref?: string | null;
  principal_scope?: string[];
  purpose_scope?: string[];
  classification: "public" | "internal" | "confidential" | "restricted";
  trust_state: "verified" | "untrusted" | "quarantined";
  parent_refs: ParentRef[];
  policy_version: string;
  valid_from: string;
  expires_at?: string | null;
  issuer_key_id?: string | null;
  signature?: string | null;
}

/** Wire shape of a revocation event (spec/revocation_event.schema.json). */
export interface RevocationEvent {
  event_id?: string;
  tenant_id?: string;
  source_id: string;
  source_version?: string | null;
  reason: "deleted" | "acl_changed" | "version_superseded" | "expired" | "compromised" | "poisoned";
  effective_at?: string;
  source_event_id?: string | null;
  actor?: string | null;
  affected_scope?: { principals?: string[]; purposes?: string[] } | null;
  issuer_key_id?: string | null;
  signature?: string | null;
}

export interface ObjectVerdict {
  contextId: string;
  decision: string;
  reason: string[];
  version: string | null;
  validUntil: string | null;
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== "string") throw new TypeError(field);
  return value;
}

function stringList(value: unknown, field: string): string[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) throw new TypeError(field);
  return value as string[];
}

function nullableString(value: unknown, field: string): string | null {
  return value === undefined || value === null ? null : requireString(value, field);
}

function parseObjectVerdict(value: unknown): ObjectVerdict {
  if (value === null || typeof value !== "object") throw new TypeError("objects[]");
  const fields = value as Record<string, unknown>;
  return {
    contextId: requireString(fields["context_id"], "context_id"),
    decision: requireString(fields["decision"], "decision"),
    reason: stringList(fields["reason"], "reason"),
    version: nullableString(fields["version"], "version"),
    validUntil: nullableString(fields["valid_until"], "valid_until"),
  };
}

export class AuthorizeResult {
  decision: string;
  reason: string[];
  revocationEpoch: number;
  policyVersion: string;
  traceId: string;
  objects: ObjectVerdict[];
  validUntil: string | null;
  fromCache: boolean;
  offline: boolean;
  /** null = server reachable; true/false = offline lease state. */
  leaseOk: boolean | null;

  constructor(init: {
    decision: string;
    reason: string[];
    revocationEpoch: number;
    policyVersion: string;
    traceId: string;
    objects?: ObjectVerdict[];
    validUntil?: string | null;
    fromCache?: boolean;
    offline?: boolean;
    leaseOk?: boolean | null;
  }) {
    this.decision = init.decision;
    this.reason = init.reason;
    this.revocationEpoch = init.revocationEpoch;
    this.policyVersion = init.policyVersion;
    this.traceId = init.traceId;
    this.objects = init.objects ?? [];
    this.validUntil = init.validUntil ?? null;
    this.fromCache = init.fromCache ?? false;
    this.offline = init.offline ?? false;
    this.leaseOk = init.leaseOk ?? null;
  }

  get allowed(): boolean {
    return this.decision === "ALLOW";
  }

  /**
   * The verdict for `contextId` at exactly `version`. With a version, only a verdict carrying that version
   * matches (an unversioned verdict matches only when nothing contradicts ours); a verdict for a different
   * version never answers for it. Without a version the server resolved "latest"; if several verdicts share
   * the id the most restrictive wins.
   */
  verdictFor(contextId: string, version?: string | null): ObjectVerdict | undefined {
    return matchVerdict(this.objects, contextId, version ?? null);
  }

  static fromResponse(data: unknown): AuthorizeResult {
    try {
      if (data === null || typeof data !== "object" || Array.isArray(data)) throw new TypeError("not an object");
      const fields = data as Record<string, unknown>;
      const epoch = fields["revocation_epoch"];
      if (typeof epoch !== "number" || !Number.isInteger(epoch)) throw new TypeError("revocation_epoch");
      const rawObjects = fields["objects"] ?? [];
      if (!Array.isArray(rawObjects)) throw new TypeError("objects");
      const objects = (rawObjects as unknown[]).map(parseObjectVerdict);
      return new AuthorizeResult({
        decision: requireString(fields["decision"], "decision"),
        reason: stringList(fields["reason"], "reason"),
        revocationEpoch: epoch,
        policyVersion: requireString(fields["policy_version"], "policy_version"),
        traceId: requireString(fields["trace_id"], "trace_id"),
        objects,
        validUntil: nullableString(fields["valid_until"], "valid_until"),
      });
    } catch (e) {
      throw new ResponseError(`malformed authorize response: ${e instanceof Error ? e.message : String(e)}`, {
        cause: e,
      });
    }
  }
}

function mostRestrictive(candidates: ObjectVerdict[]): ObjectVerdict | undefined {
  return candidates.find((verdict) => verdict.decision !== "ALLOW") ?? candidates[0];
}

/** Pick the verdict for exactly `(contextId, version)`; undefined if none answers for it. */
export function matchVerdict(
  objects: readonly ObjectVerdict[],
  contextId: string,
  version: string | null,
): ObjectVerdict | undefined {
  const candidates = objects.filter((verdict) => verdict.contextId === contextId);
  if (version === null) return mostRestrictive(candidates);
  const exact = candidates.filter((verdict) => verdict.version === version);
  if (exact.length > 0) return mostRestrictive(exact);
  const unversioned = candidates.filter((verdict) => verdict.version === null);
  if (unversioned.length === candidates.length) return mostRestrictive(unversioned);
  return undefined;
}

type RequestedObject = { context_id: string; version?: string };

/**
 * The requested object a verdict answers for, matched on (context_id, version). A versioned verdict matches
 * the request for exactly that version, or the sole request that omitted one (server resolved "latest"). An
 * unversioned verdict matches only when the id was requested once. Otherwise it is unattributable: not cached.
 */
function specForVerdict(objects: RequestedObject[], verdict: ObjectVerdict): RequestedObject | undefined {
  const matchingRequests = objects.filter((reference) => reference.context_id === verdict.contextId);
  if (verdict.version !== null) {
    const exact = matchingRequests.find((reference) => reference.version === verdict.version);
    if (exact !== undefined) return exact;
    return matchingRequests.length === 1 && matchingRequests[0]?.version === undefined ? matchingRequests[0] : undefined;
  }
  return matchingRequests.length === 1 ? matchingRequests[0] : undefined;
}

export interface InvariantClientOptions {
  baseUrl: string;
  tenantId: string;
  authToken?: string;
  failMode?: string;
  /** Cap on the offline lease, seconds. Default 60. */
  offlineLeaseSeconds?: number;
  /** Development only: permit construction without a bearer token. */
  allowAnonymous?: boolean;
  /** Base64 Ed25519 key (or `{key_id: key}`); required for BOUNDED_OFFLINE. */
  snapshotPublicKey?: SnapshotPublicKeySpec;
  timeoutMs?: number;
  maxRetries?: number;
  /** Base of the exponential backoff, seconds. Default 0.1. */
  retryBackoff?: number;
  cache?: DecisionCache;
  fetch?: typeof fetch;
  /** Monotonic seconds. */
  clock?: Clock;
  /** Wall-clock epoch seconds. */
  wallClock?: Clock;
  sleep?: (seconds: number) => Promise<void>;
  /** Returns [0,1); injectable for deterministic jitter. */
  random?: () => number;
}

export interface AuthorizeOptions {
  agentId?: string;
  sessionId?: string;
}

interface RequestOptions {
  retries?: number;
  json?: unknown;
  query?: Record<string, string>;
}

function parseRfc3339Seconds(value: string): number {
  if (!/^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/.test(value)) {
    throw new Error("valid_until is not an RFC 3339 timestamp with timezone");
  }
  const ms = Date.parse(value.replace(" ", "T"));
  if (Number.isNaN(ms)) throw new Error("valid_until is unparseable");
  return ms / 1000;
}

function normalizeObjects(objects: Iterable<ObjectRef>): { context_id: string; version?: string }[] {
  const out: { context_id: string; version?: string }[] = [];
  for (const o of objects) {
    let cid: string;
    let ver: string | null | undefined;
    if (typeof o === "string") {
      cid = o;
    } else if (Array.isArray(o)) {
      const t = o as readonly [string, (string | null)?];
      cid = t[0];
      ver = t[1];
    } else {
      const r = o as { context_id: string; version?: string | null };
      cid = r.context_id;
      ver = r.version;
    }
    if (typeof cid !== "string" || cid === "") throw new InvalidRequestError("object context_id must be a non-empty string");
    out.push(ver === undefined || ver === null ? { context_id: cid } : { context_id: cid, version: ver });
  }
  return out;
}

function validateToken(token: string): string {
  const t = token.trim();
  if (t === "") throw new ConfigError("authToken is empty");
  for (const ch of t) {
    const c = ch.charCodeAt(0);
    if (c < 33 || c === 127) throw new ConfigError("authToken contains whitespace or control characters");
  }
  return t;
}

const defaultSleep = (seconds: number): Promise<void> => new Promise((r) => setTimeout(r, seconds * 1000));

/**
 * Client for the decision API.
 *
 * `authToken` is mandatory (sent as `Authorization: Bearer`) unless `allowAnonymous: true`, which exists
 * only for local development against a server that does not enforce auth.
 *
 * `failMode: "BOUNDED_OFFLINE"` requires `snapshotPublicKey`: the client then fetches and verifies
 * `/v1/snapshot` and may serve cached ALLOWs without the server only while it holds a verified, unexpired
 * snapshot whose epoch equals the cached decision's epoch.
 */
export class InvariantClient {
  readonly baseUrl: string;
  readonly tenantId: string;
  readonly failMode: FailMode;
  readonly offlineLeaseSeconds: number;
  readonly maxRetries: number;
  readonly retryBackoff: number;
  readonly timeoutMs: number;
  readonly cache: DecisionCache;
  readonly sessionTaint = new SessionTaint();
  lastSnapshotError: SnapshotError | null = null;

  private readonly clock: Clock;
  private readonly wallClock: Clock;
  private readonly sleep: (seconds: number) => Promise<void>;
  private readonly random: () => number;
  private readonly fetchImpl: typeof fetch | undefined;
  private readonly snapshotKeys: SnapshotKeys | null;
  private readonly headers: Record<string, string>;
  private readonly hasToken: boolean;
  private lastSuccess: number | null = null;
  private policyVersion = "";
  private held: Snapshot | null = null;
  private nextSnapshotAttempt = 0;

  constructor(opts: InvariantClientOptions) {
    if (!opts.tenantId) throw new ConfigError("tenantId is required");
    if (!opts.baseUrl) throw new ConfigError("baseUrl is required");
    const maxRetries = opts.maxRetries ?? 2;
    if (!Number.isInteger(maxRetries) || maxRetries < 0) throw new ConfigError("maxRetries must be an integer >= 0");
    const fm = parseFailMode(opts.failMode ?? FailMode.ENFORCE);
    if (fm === null) throw new ConfigError(`unknown failMode ${JSON.stringify(opts.failMode)}`);
    this.failMode = fm;
    const token = opts.authToken !== undefined ? validateToken(opts.authToken) : null;
    if (token === null && opts.allowAnonymous !== true) {
      throw new ConfigError(
        "authToken is required (every API call is bearer-authenticated); " +
          "pass allowAnonymous: true only for local development",
      );
    }
    this.snapshotKeys = opts.snapshotPublicKey !== undefined ? new SnapshotKeys(opts.snapshotPublicKey) : null;
    if (this.failMode === FailMode.BOUNDED_OFFLINE && this.snapshotKeys === null) {
      throw new ConfigError(
        "failMode=BOUNDED_OFFLINE requires snapshotPublicKey: without a verifiable signed policy snapshot " +
          "the client cannot safely serve anything offline",
      );
    }
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.tenantId = opts.tenantId;
    this.offlineLeaseSeconds = opts.offlineLeaseSeconds ?? 60;
    this.maxRetries = maxRetries;
    this.retryBackoff = opts.retryBackoff ?? 0.1;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.clock = opts.clock ?? monotonicNow;
    this.wallClock = opts.wallClock ?? wallNow;
    this.sleep = opts.sleep ?? defaultSleep;
    this.random = opts.random ?? Math.random;
    this.fetchImpl = opts.fetch;
    this.cache = opts.cache ?? new DecisionCache({ clock: this.clock, wallClock: this.wallClock });
    this.hasToken = token !== null;
    this.headers = { "X-Tenant-Id": this.tenantId, Accept: "application/json" };
    if (token !== null) this.headers["Authorization"] = `Bearer ${token}`;
  }

  toString(): string {
    return (
      `InvariantClient(baseUrl=${JSON.stringify(this.baseUrl)}, tenantId=${JSON.stringify(this.tenantId)}, ` +
      `failMode=${this.failMode}, authenticated=${String(this.hasToken)})`
    );
  }

  // -- transport --------------------------------------------------------------------------------
  /** Exponential backoff with full jitter. */
  private async backoff(attempt: number): Promise<void> {
    const cap = this.retryBackoff * 2 ** attempt;
    await this.sleep(this.random() * cap);
  }

  private async sendOnce(
    method: string,
    path: string,
    url: string,
    body: Uint8Array<ArrayBuffer> | undefined,
  ): Promise<{ status: number; text: string; url: string }> {
    const ctrl = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      ctrl.abort();
    }, this.timeoutMs);
    try {
      const headers: Record<string, string> = { ...this.headers };
      if (body !== undefined) headers["Content-Type"] = "application/json";
      const init: RequestInit = { method, headers, redirect: "manual", signal: ctrl.signal };
      if (body !== undefined) init.body = body;
      const f = this.fetchImpl ?? globalThis.fetch;
      const resp = await f(url, init);
      const text = await resp.text();
      return { status: resp.status, text, url: resp.url || url };
    } catch (e) {
      if (timedOut) throw new AlesTimeoutError(`timeout calling ${path} after ${String(this.timeoutMs)}ms`, { cause: e });
      throw new AlesConnectionError(e instanceof Error ? `${e.message}` : String(e), { cause: e });
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Send a request. Only idempotent calls (GET, authorize) are retried: `retries` defaults to `maxRetries`
   * for GET and 0 otherwise; `authorize` passes it explicitly. Retries cover transport errors and
   * 429/502/503/504, with jittered exponential backoff.
   */
  private async request(method: string, path: string, opts: RequestOptions = {}): Promise<unknown> {
    let body: Uint8Array<ArrayBuffer> | undefined;
    if (opts.json !== undefined) {
      let text: string | undefined;
      try {
        text = JSON.stringify(opts.json, (_k, v: unknown) => {
          if (typeof v === "number" && !Number.isFinite(v)) throw new TypeError("non-finite number");
          if (typeof v === "bigint") throw new TypeError("BigInt is not JSON-serialisable");
          return v;
        });
      } catch (e) {
        throw new InvalidRequestError(`request body is not JSON-serialisable: ${e instanceof Error ? e.message : String(e)}`, {
          cause: e,
        });
      }
      if (typeof text !== "string") throw new InvalidRequestError("request body is not JSON-serialisable");
      body = new TextEncoder().encode(text);
      if (body.length > MAX_REQUEST_BYTES) throw new RequestTooLargeError(body.length, MAX_REQUEST_BYTES);
    }
    const retries = opts.retries ?? (method.toUpperCase() === "GET" ? this.maxRetries : 0);
    let url = this.baseUrl + path;
    if (opts.query !== undefined) url += "?" + new URLSearchParams(opts.query).toString();

    let attempt = 0;
    for (;;) {
      let err: Error | null = null;
      let res: { status: number; text: string; url: string } | null = null;
      try {
        res = await this.sendOnce(method, path, url, body);
        if (RETRYABLE_STATUS.has(res.status)) {
          err = new ServerUnavailableError(res.status, parseBody(res.text), res.url);
        }
      } catch (e) {
        if (e instanceof AlesConnectionError) err = e;
        else throw e;
      }
      if (err === null && res !== null) {
        return this.finish(res, path);
      }
      if (attempt >= retries) throw err ?? new AlesConnectionError("request failed");
      await this.backoff(attempt);
      attempt++;
    }
  }

  private finish(res: { status: number; text: string; url: string }, path: string): unknown {
    if (res.status < 200 || res.status >= 300) {
      const body = parseBody(res.text);
      if (res.status === 401 || res.status === 403) {
        if (res.status === 403 && new AlesHTTPError(403, body, res.url).detail.toLowerCase().includes("tenant")) {
          throw new TenantMismatchError(403, body, res.url, this.tenantId);
        }
        throw new AuthError(res.status, body, res.url);
      }
      throw new AlesHTTPError(res.status, body, res.url);
    }
    this.lastSuccess = this.clock();
    if (res.text === "") return {};
    try {
      return JSON.parse(res.text) as unknown;
    } catch (e) {
      throw new ResponseError(`non-JSON response from ${path}`, { cause: e });
    }
  }

  private async requestObject(method: string, path: string, opts: RequestOptions = {}): Promise<JsonObject> {
    const data = await this.request(method, path, opts);
    if (data === null || typeof data !== "object" || Array.isArray(data)) {
      throw new ResponseError(`expected a JSON object from ${path}`);
    }
    return data as JsonObject;
  }

  // -- offline lease / snapshot -----------------------------------------------------------------
  /** The currently held verified snapshot (may be expired; see {@link snapshotValid}). */
  get snapshot(): Snapshot | null {
    return this.held;
  }

  snapshotValid(): boolean {
    return this.held !== null && snapshotValidAt(this.held, this.clock(), this.offlineLeaseSeconds);
  }

  /**
   * Is the client currently entitled to serve decisions without the server?
   * BOUNDED_OFFLINE: a verified, unexpired snapshot is held. Other modes: last successful server contact is
   * younger than `offlineLeaseSeconds` (informational only).
   */
  leaseOk(): boolean {
    if (this.failMode === FailMode.BOUNDED_OFFLINE) return this.snapshotValid();
    return this.lastSuccess !== null && this.clock() - this.lastSuccess < this.offlineLeaseSeconds;
  }

  /**
   * Fetch `GET /v1/snapshot` and verify its Ed25519 signature. On any verification failure the previously
   * held snapshot is discarded (fail closed) and {@link SnapshotError} is thrown.
   */
  async refreshSnapshot(opts: { retries?: number } = {}): Promise<Snapshot> {
    if (this.snapshotKeys === null) throw new ConfigError("snapshotPublicKey is not configured");
    const ropts: RequestOptions = {};
    if (opts.retries !== undefined) ropts.retries = opts.retries;
    const data = await this.request("GET", "/v1/snapshot", ropts);
    const received = this.clock();
    let snap: Snapshot;
    try {
      snap = await verifySnapshot(data, {
        keys: this.snapshotKeys,
        tenantId: this.tenantId,
        receivedAt: received,
        wallNow: this.wallClock(),
      });
      const prev = this.held;
      if (prev !== null && snap.revocationEpoch < prev.revocationEpoch) {
        throw new SnapshotError(
          "epoch_regression",
          `epoch ${String(snap.revocationEpoch)} < previously accepted ${String(prev.revocationEpoch)}`,
        );
      }
    } catch (e) {
      if (e instanceof SnapshotError) {
        this.held = null;
        this.lastSnapshotError = e;
      }
      throw e;
    }
    this.held = snap;
    this.lastSnapshotError = null;
    this.cache.invalidateIfEpochAdvanced(snap.revocationEpoch);
    return snap;
  }

  /** Opportunistic refresh: no snapshot, older than half its lease, or epoch moved on. */
  private async maybeRefreshSnapshot(observedEpoch?: number): Promise<void> {
    if (this.failMode !== FailMode.BOUNDED_OFFLINE) return;
    const now = this.clock();
    const snap = this.held;
    if (now < this.nextSnapshotAttempt) return;
    const lease = snap === null ? this.offlineLeaseSeconds : Math.min(snap.effectiveLease, this.offlineLeaseSeconds);
    const need =
      snap === null ||
      now - snap.receivedAt >= lease / 2 ||
      (observedEpoch !== undefined && observedEpoch !== snap.revocationEpoch);
    if (!need) return;
    try {
      await this.refreshSnapshot({ retries: 0 });
    } catch (e) {
      if (e instanceof AuthError) throw e;
      if (e instanceof AlesConnectionError || e instanceof AlesHTTPError || e instanceof SnapshotError) {
        this.nextSnapshotAttempt = this.clock() + SNAPSHOT_RETRY_INTERVAL;
        return;
      }
      throw e;
    }
  }

  /** Absolute monotonic deadline of the held snapshot's lease, or null when none is held. */
  snapshotDeadline(): number | null {
    return this.held === null ? null : snapshotDeadline(this.held, this.offlineLeaseSeconds);
  }

  // -- registration -----------------------------------------------------------------------------
  async registerSource(envelope: ContextEnvelope): Promise<JsonObject> {
    const data = await this.requestObject("POST", "/v1/sources", { json: envelope });
    return Object.keys(data).length > 0 ? data : envelopeRef(envelope);
  }

  async registerDerivation(envelope: ContextEnvelope): Promise<JsonObject> {
    const data = await this.requestObject("POST", "/v1/derivations", { json: envelope });
    return Object.keys(data).length > 0 ? data : envelopeRef(envelope);
  }

  // -- revocation -------------------------------------------------------------------------------
  /** Submit a RevocationEvent. Missing event_id/tenant_id/effective_at are filled in. */
  async submitRevocation(event: RevocationEvent): Promise<JsonObject> {
    const ev: RevocationEvent = {
      event_id: crypto.randomUUID(),
      tenant_id: this.tenantId,
      effective_at: new Date().toISOString(),
      ...stripUndefined(event),
    };
    const data = await this.requestObject("POST", "/v1/revocations", { json: ev });
    const epoch = data["revocation_epoch"];
    if (typeof epoch === "number" && Number.isInteger(epoch)) this.cache.invalidateIfEpochAdvanced(epoch);
    return data;
  }

  // -- authorize --------------------------------------------------------------------------------
  async authorize(
    principal: Principal,
    purpose: string,
    objects: Iterable<ObjectRef>,
    opts: AuthorizeOptions = {},
  ): Promise<AuthorizeResult> {
    const objs = normalizeObjects(objects);
    if (objs.length === 0) throw new InvalidRequestError("authorize requires at least one object");
    const pid = (principal as Partial<Principal> | null | undefined)?.id;
    if (typeof pid !== "string" || pid === "") throw new InvalidRequestError("principal must be an object with an 'id'");
    const ptype = principal.type ?? "user";
    const bounded = this.failMode === FailMode.BOUNDED_OFFLINE;

    if (bounded) await this.maybeRefreshSnapshot();
    const policyVersion = this.policyVersion;
    const keys = objs.map((o) =>
      makeKey(this.tenantId, ptype, pid, purpose, o.context_id, o.version, policyVersion, opts.agentId),
    );
    if (policyVersion !== "" && (!bounded || this.snapshotValid())) {
      const epochs = keys.map((k) => this.cache.get(k));
      if (epochs.every((e) => e !== null) && (!bounded || this.epochsMatchSnapshot(epochs, policyVersion))) {
        return this.cachedResult(objs, epochs, policyVersion, false);
      }
    }

    const body: JsonObject = {
      tenant_id: this.tenantId,
      principal: { type: ptype, id: pid },
      purpose,
      objects: objs,
    };
    if (opts.agentId !== undefined) body["agent_id"] = opts.agentId;
    if (opts.sessionId !== undefined) body["session_id"] = opts.sessionId;

    let data: unknown;
    try {
      data = await this.request("POST", "/v1/authorize", { json: body, retries: this.maxRetries });
    } catch (e) {
      if (e instanceof AlesConnectionError || e instanceof ServerUnavailableError) {
        return this.offlineResult(objs, keys);
      }
      throw e;
    }

    const result = AuthorizeResult.fromResponse(data);
    if (this.policyVersion !== "" && this.policyVersion !== result.policyVersion) {
      this.cache.clear(); // policy changed: nothing decided under the old one may be reused
    }
    this.policyVersion = result.policyVersion;
    if (this.held !== null && this.held.policyVersion !== result.policyVersion) {
      // The held snapshot was signed under another policy: it can no longer vouch for anything decided
      // now. Drop it (fail closed); it is re-fetched below.
      this.held = null;
    }
    this.cache.invalidateIfEpochAdvanced(result.revocationEpoch);
    for (const o of result.objects) {
      if (o.decision !== "ALLOW") continue;
      const spec = specForVerdict(objs, o);
      if (spec === undefined) continue;
      const k = makeKey(this.tenantId, ptype, pid, purpose, o.contextId, spec.version, result.policyVersion, opts.agentId);
      // Per-object bound, else the response-level one. An unparseable bound is not cacheable: fail closed.
      const raw = o.validUntil ?? result.validUntil;
      let until: number | null = null;
      if (raw !== null) {
        try {
          until = parseRfc3339Seconds(raw);
        } catch {
          continue;
        }
      }
      this.cache.put(k, o.decision, result.revocationEpoch, { validUntil: until });
    }
    if (bounded) await this.maybeRefreshSnapshot(result.revocationEpoch);
    return result;
  }

  private epochsMatchSnapshot(epochs: (number | null)[], policyVersion: string): boolean {
    const snap = this.held;
    return snap !== null && snap.policyVersion === policyVersion && epochs.every((e) => e === snap.revocationEpoch);
  }

  private cachedResult(
    objs: { context_id: string; version?: string }[],
    epochs: number[],
    policyVersion: string,
    fromOffline: boolean,
  ): AuthorizeResult {
    return new AuthorizeResult({
      decision: "ALLOW",
      reason: ["OK"],
      revocationEpoch: epochs.length > 0 ? Math.max(...epochs) : 0,
      policyVersion,
      traceId: "cache-" + shortId(),
      objects: objs.map((o) => ({
        contextId: o.context_id,
        decision: "ALLOW",
        reason: ["OK"],
        version: o.version ?? null,
        validUntil: null,
      })),
      fromCache: true,
      offline: fromOffline,
      leaseOk: fromOffline ? this.leaseOk() : null,
    });
  }

  /**
   * Server unreachable. Fail closed unless BOUNDED_OFFLINE holds a valid snapshot AND the cached ALLOW was
   * issued at exactly the snapshot's epoch.
   */
  private offlineResult(objs: { context_id: string; version?: string }[], keys: CacheKey[]): AuthorizeResult {
    const lease = this.leaseOk();
    const snap = this.held;
    const usable =
      this.failMode === FailMode.BOUNDED_OFFLINE && lease && snap !== null && snap.policyVersion === this.policyVersion;
    const verdicts: ObjectVerdict[] = objs.map((o, i) => {
      const k = keys[i];
      const hit = usable && snap !== null && k !== undefined && this.cache.get(k) === snap.revocationEpoch;
      return {
        contextId: o.context_id,
        decision: hit ? "ALLOW" : "UNKNOWN",
        reason: [hit ? "OK" : "POLICY_SNAPSHOT_STALE"],
        version: o.version ?? null,
        validUntil: null,
      };
    });
    const allOk = verdicts.length > 0 && verdicts.every((v) => v.decision === "ALLOW");
    return new AuthorizeResult({
      decision: allOk ? "ALLOW" : "UNKNOWN",
      reason: [allOk ? "OK" : "POLICY_SNAPSHOT_STALE"],
      revocationEpoch: this.cache.latestEpoch,
      policyVersion: this.policyVersion,
      traceId: "offline-" + shortId(),
      objects: verdicts,
      fromCache: allOk,
      offline: true,
      leaseOk: lease,
    });
  }

  // -- queries ----------------------------------------------------------------------------------
  lineage(contextId: string): Promise<JsonObject> {
    return this.requestObject("GET", `/v1/lineage/${encodeURIComponent(contextId)}`, {
      query: { tenant_id: this.tenantId },
    });
  }

  verify(adapter: string, mode = "strict"): Promise<JsonObject> {
    return this.requestObject("POST", "/v1/verify", { json: { tenant_id: this.tenantId, adapter, mode } });
  }

  healthz(): Promise<JsonObject> {
    return this.requestObject("GET", "/v1/healthz");
  }
}

function parseBody(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

function envelopeRef(envelope: ContextEnvelope): JsonObject {
  return { context_id: envelope.context_id, object_version: envelope.object_version };
}

function shortId(): string {
  return crypto.randomUUID().replace(/-/g, "").slice(0, 12);
}

function stripUndefined<T extends object>(o: T): T {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as T;
}
