/** Track which context objects each session consumed, so revoked exposure can force a reset. */

import type { InvariantClient, ObjectRef, ObjectVerdict, Principal } from "./client.js";

export const ENFORCE_BATCH_SIZE = 1000;

/** One context object served to a session, with the authority it was served under. */
export interface Exposure {
  readonly contextId: string;
  readonly version: string | null;
  readonly principalType: string | null;
  readonly principalId: string | null;
  readonly purpose: string | null;
}

export interface TaintVerdict {
  sessionId: string;
  resetRequired: boolean;
  revoked: ObjectVerdict[];
  /** Context ids recorded without principal/purpose; they cannot be re-checked (fail closed: force a reset). */
  unverifiable: string[];
  checked: number;
}

export interface RecordOptions {
  versions?: Readonly<Record<string, string | null>>;
  principal?: Principal;
  purpose?: string;
}

function exposureKey(e: Exposure): string {
  return JSON.stringify([e.contextId, e.version, e.principalType, e.principalId, e.purpose]);
}

export class SessionTaint {
  private readonly sessions = new Map<string, Map<string, Exposure>>();

  /** Record that `contextIds` were served to the session. Each item is a context id or a
   * `[contextId, version]` pair; exposures are kept per exact (contextId, version). `opts.versions` supplies a
   * version for bare ids. Pass principal+purpose so `enforce` can re-authorize. */
  record(sessionId: string, contextIds: Iterable<string | readonly [string, string | null]>, opts: RecordOptions = {}): void {
    let ptype: string | null = null;
    let pid: string | null = null;
    if (opts.principal !== undefined) {
      pid = opts.principal.id;
      ptype = opts.principal.type ?? "user";
    }
    let bucket = this.sessions.get(sessionId);
    if (bucket === undefined) {
      bucket = new Map();
      this.sessions.set(sessionId, bucket);
    }
    for (const item of contextIds) {
      const [cid, ver] = typeof item === "string" ? [item, opts.versions?.[item] ?? null] : [item[0], item[1]];
      const e: Exposure = {
        contextId: cid,
        version: ver,
        principalType: ptype,
        principalId: pid,
        purpose: opts.purpose ?? null,
      };
      bucket.set(exposureKey(e), e);
    }
  }

  exposuresFor(sessionId: string): Exposure[] {
    return [...(this.sessions.get(sessionId)?.values() ?? [])];
  }

  contextsFor(sessionId: string): Set<string> {
    return new Set(this.exposuresFor(sessionId).map((e) => e.contextId));
  }

  /** True if the session consumed any revoked context (caller should reset the session). */
  isTainted(sessionId: string, revokedContextIds: Iterable<string>): boolean {
    const ctx = this.contextsFor(sessionId);
    for (const r of revokedContextIds) if (ctx.has(r)) return true;
    return false;
  }

  clear(sessionId: string): void {
    this.sessions.delete(sessionId);
  }
}

/**
 * Re-authorize everything the session has consumed and say whether it must be reset.
 *
 * Exposures sharing a (principal, purpose) are re-checked in batched `authorize` calls. Any object that is
 * not an explicit ALLOW now (DENY, UNKNOWN, offline/stale UNKNOWN, a missing verdict) sets `resetRequired`.
 * The check is independent of the fail mode: OBSERVE/WARN do not make a revoked exposure acceptable here.
 * `principal`/`purpose` override whatever was recorded; exposures recorded without them (and not overridden)
 * are reported as `unverifiable` and force a reset.
 */
export async function enforce(
  sessionId: string,
  client: InvariantClient,
  opts: { principal?: Principal; purpose?: string } = {},
): Promise<TaintVerdict> {
  const exposures = client.sessionTaint.exposuresFor(sessionId);
  const { principal, purpose } = opts;
  if ((principal === undefined) !== (purpose === undefined)) {
    throw new TypeError("pass both principal and purpose, or neither");
  }
  const groups = new Map<string, { ptype: string; pid: string; purpose: string; objs: Map<string, [string, string | null]> }>();
  const unverifiable: string[] = [];
  for (const e of exposures) {
    let ptype: string;
    let pid: string;
    let purp: string;
    if (principal !== undefined && purpose !== undefined) {
      ptype = principal.type ?? "user";
      pid = principal.id;
      purp = purpose;
    } else if (e.principalId !== null && e.purpose !== null) {
      ptype = e.principalType ?? "user";
      pid = e.principalId;
      purp = e.purpose;
    } else {
      if (!unverifiable.includes(e.contextId)) unverifiable.push(e.contextId);
      continue;
    }
    const gk = JSON.stringify([ptype, pid, purp]);
    let g = groups.get(gk);
    if (g === undefined) {
      g = { ptype, pid, purpose: purp, objs: new Map() };
      groups.set(gk, g);
    }
    g.objs.set(JSON.stringify([e.contextId, e.version]), [e.contextId, e.version]);
  }

  const revoked = new Map<string, ObjectVerdict>();
  let checked = 0;
  for (const g of groups.values()) {
    const items = [...g.objs.values()];
    for (let i = 0; i < items.length; i += ENFORCE_BATCH_SIZE) {
      const batch = items.slice(i, i + ENFORCE_BATCH_SIZE);
      const refs: ObjectRef[] = batch.map(([cid, ver]) => [cid, ver]);
      const result = await client.authorize({ type: g.ptype, id: g.pid }, g.purpose, refs, { sessionId });
      for (const [cid, ver] of batch) {
        checked++;
        const v = result.verdictFor(cid, ver) ?? {
          contextId: cid,
          decision: "UNKNOWN",
          reason: ["OBJECT_UNKNOWN"],
          version: ver,
          validUntil: null,
        };
        const rk = JSON.stringify([cid, ver]);
        if (v.decision !== "ALLOW" && !revoked.has(rk)) revoked.set(rk, v);
      }
    }
  }
  return {
    sessionId,
    resetRequired: revoked.size > 0 || unverifiable.length > 0,
    revoked: [...revoked.values()],
    unverifiable,
    checked,
  };
}
