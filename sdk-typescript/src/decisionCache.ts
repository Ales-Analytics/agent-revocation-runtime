/** In-process ALLOW-only decision cache bound to the revocation epoch (port of ales_sdk.decision_cache). */

/** Seconds on a monotonic clock. */
export type Clock = () => number;

export const DEFAULT_MAX_CLOCK_SKEW = 30;
export const DEFAULT_MAX_TTL = 30;

export function monotonicNow(): number {
  return performance.now() / 1000;
}

export function wallNow(): number {
  return Date.now() / 1000;
}

/**
 * Opaque cache key built from the seven components
 * (tenant_id, principal_type, principal_id, purpose, context_id, object_version, policy_version).
 * Encoded as a JSON array so no component value can collide with a delimiter.
 */
export type CacheKey = string;

export function makeKey(
  tenantId: string,
  principalType: string,
  principalId: string,
  purpose: string,
  contextId: string,
  version: string | null | undefined,
  policyVersion: string,
): CacheKey {
  return JSON.stringify([tenantId, principalType, principalId, purpose, contextId, version ?? null, policyVersion]);
}

const CONTEXT_INDEX = 4;

interface Entry {
  revocationEpoch: number;
  expiresAt: number;
  /** Wall-clock epoch seconds; null = no pending revocation known. */
  validUntil: number | null;
}

export interface DecisionCacheOptions {
  maxTtl?: number;
  clock?: Clock;
  wallClock?: Clock;
  maxClockSkew?: number;
}

export class DecisionCache {
  readonly maxTtl: number;
  readonly maxClockSkew: number;
  private readonly clock: Clock;
  private readonly wallClock: Clock;
  private readonly entries = new Map<CacheKey, Entry>();
  private latest = 0;

  constructor(opts: DecisionCacheOptions = {}) {
    this.maxTtl = opts.maxTtl ?? DEFAULT_MAX_TTL;
    this.clock = opts.clock ?? monotonicNow;
    this.wallClock = opts.wallClock ?? wallNow;
    this.maxClockSkew = opts.maxClockSkew ?? DEFAULT_MAX_CLOCK_SKEW;
  }

  get size(): number {
    return this.entries.size;
  }

  get latestEpoch(): number {
    return this.latest;
  }

  /** An entry stops being served `maxClockSkew` seconds BEFORE validUntil (a slow client clock must not over-serve). */
  private pastValidUntil(validUntil: number | null): boolean {
    return validUntil !== null && this.wallClock() + this.maxClockSkew >= validUntil;
  }

  /**
   * Cache an ALLOW. Any other decision is refused (returns false); so are stale-epoch ALLOWs and ALLOWs
   * already within the skew allowance of their `validUntil`.
   */
  put(
    key: CacheKey,
    decision: string,
    revocationEpoch: number,
    opts: { ttl?: number; validUntil?: number | null } = {},
  ): boolean {
    const validUntil = opts.validUntil ?? null;
    if (decision !== "ALLOW" || this.pastValidUntil(validUntil)) return false;
    if (revocationEpoch < this.latest) return false;
    this.latest = Math.max(this.latest, revocationEpoch);
    const eff = opts.ttl === undefined ? this.maxTtl : Math.min(opts.ttl, this.maxTtl);
    this.entries.set(key, { revocationEpoch, expiresAt: this.clock() + eff, validUntil });
    return true;
  }

  /** The epoch the cached ALLOW was issued at, or null on miss/expiry. */
  get(key: CacheKey): number | null {
    const entry = this.entries.get(key);
    if (entry === undefined) return null;
    if (
      entry.expiresAt <= this.clock() ||
      entry.revocationEpoch < this.latest ||
      this.pastValidUntil(entry.validUntil)
    ) {
      this.entries.delete(key);
      return null;
    }
    return entry.revocationEpoch;
  }

  /** Wipe entries issued before `newEpoch`. Returns the number removed. */
  invalidateIfEpochAdvanced(newEpoch: number): number {
    this.latest = Math.max(this.latest, newEpoch);
    let removed = 0;
    for (const [k, e] of this.entries) {
      if (e.revocationEpoch < newEpoch) {
        this.entries.delete(k);
        removed++;
      }
    }
    return removed;
  }

  invalidateContext(contextId: string): number {
    let removed = 0;
    for (const k of [...this.entries.keys()]) {
      const parts = JSON.parse(k) as unknown[];
      if (parts[CONTEXT_INDEX] === contextId) {
        this.entries.delete(k);
        removed++;
      }
    }
    return removed;
  }

  clear(): void {
    this.entries.clear();
  }
}
