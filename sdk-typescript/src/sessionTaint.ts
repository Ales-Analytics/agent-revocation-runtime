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

function exposureKey(exposure: Exposure): string {
  return JSON.stringify([exposure.contextId, exposure.version, exposure.principalType, exposure.principalId, exposure.purpose]);
}

export class SessionTaint {
  private readonly sessions = new Map<string, Map<string, Exposure>>();

  /** Record that `contextIds` were served to the session. Each item is a context id or a
   * `[contextId, version]` pair; exposures are kept per exact (contextId, version). `opts.versions` supplies a
   * version for bare ids. Pass principal+purpose so `enforce` can re-authorize. */
  record(sessionId: string, contextIds: Iterable<string | readonly [string, string | null]>, opts: RecordOptions = {}): void {
    let principalType: string | null = null;
    let principalId: string | null = null;
    if (opts.principal !== undefined) {
      principalId = opts.principal.id;
      principalType = opts.principal.type ?? "user";
    }
    let bucket = this.sessions.get(sessionId);
    if (bucket === undefined) {
      bucket = new Map();
      this.sessions.set(sessionId, bucket);
    }
    for (const item of contextIds) {
      const [contextId, version] = typeof item === "string" ? [item, opts.versions?.[item] ?? null] : [item[0], item[1]];
      const exposure: Exposure = {
        contextId: contextId,
        version: version,
        principalType: principalType,
        principalId: principalId,
        purpose: opts.purpose ?? null,
      };
      bucket.set(exposureKey(exposure), exposure);
    }
  }

  exposuresFor(sessionId: string): Exposure[] {
    return [...(this.sessions.get(sessionId)?.values() ?? [])];
  }

  contextsFor(sessionId: string): Set<string> {
    return new Set(this.exposuresFor(sessionId).map((exposure) => exposure.contextId));
  }

  /** True if the session consumed any revoked context (caller should reset the session). */
  isTainted(sessionId: string, revokedContextIds: Iterable<string>): boolean {
    const contextIds = this.contextsFor(sessionId);
    for (const revokedContextId of revokedContextIds) if (contextIds.has(revokedContextId)) return true;
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
  const groups = new Map<string, { principalType: string; principalId: string; purpose: string; objects: Map<string, [string, string | null]> }>();
  const unverifiable: string[] = [];
  for (const exposure of exposures) {
    let principalType: string;
    let principalId: string;
    let exposurePurpose: string;
    if (principal !== undefined && purpose !== undefined) {
      principalType = principal.type ?? "user";
      principalId = principal.id;
      exposurePurpose = purpose;
    } else if (exposure.principalId !== null && exposure.purpose !== null) {
      principalType = exposure.principalType ?? "user";
      principalId = exposure.principalId;
      exposurePurpose = exposure.purpose;
    } else {
      if (!unverifiable.includes(exposure.contextId)) unverifiable.push(exposure.contextId);
      continue;
    }
    const groupKey = JSON.stringify([principalType, principalId, exposurePurpose]);
    let group = groups.get(groupKey);
    if (group === undefined) {
      group = { principalType, principalId, purpose: exposurePurpose, objects: new Map() };
      groups.set(groupKey, group);
    }
    group.objects.set(JSON.stringify([exposure.contextId, exposure.version]), [exposure.contextId, exposure.version]);
  }

  const revoked = new Map<string, ObjectVerdict>();
  let checked = 0;
  for (const group of groups.values()) {
    const items = [...group.objects.values()];
    for (let i = 0; i < items.length; i += ENFORCE_BATCH_SIZE) {
      const batch = items.slice(i, i + ENFORCE_BATCH_SIZE);
      const refs: ObjectRef[] = batch.map(([contextId, version]) => [contextId, version]);
      const result = await client.authorize({ type: group.principalType, id: group.principalId }, group.purpose, refs, { sessionId });
      for (const [contextId, version] of batch) {
        checked++;
        const verdict = result.verdictFor(contextId, version) ?? {
          contextId: contextId,
          decision: "UNKNOWN",
          reason: ["OBJECT_UNKNOWN"],
          version: version,
          validUntil: null,
        };
        const referenceKey = JSON.stringify([contextId, version]);
        if (verdict.decision !== "ALLOW" && !revoked.has(referenceKey)) revoked.set(referenceKey, verdict);
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
