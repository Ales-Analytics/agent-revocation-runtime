/** Fail modes: how a decision is turned into an effective allow/block action (port of ales_sdk.fail_modes). */

export const FailMode = {
  OBSERVE: "OBSERVE",
  WARN: "WARN",
  ENFORCE: "ENFORCE",
  BOUNDED_OFFLINE: "BOUNDED_OFFLINE",
} as const;
export type FailMode = (typeof FailMode)[keyof typeof FailMode];

export function parseFailMode(value: string): FailMode | null {
  return (Object.values(FailMode) as string[]).includes(value) ? (value as FailMode) : null;
}

export interface EffectiveAction {
  allow: boolean;
  needsOverride: boolean;
  observedOnly: boolean;
}

/** Everything except an explicit `public` classification is protected (unknown => protected). */
export function isProtected(classification?: string | null): boolean {
  return (classification ?? "restricted") !== "public";
}

/**
 * Resolve a server/cached decision into an action.
 *
 * `leaseOk` only matters for BOUNDED_OFFLINE: `null`/`undefined` = server reachable (behaves like ENFORCE),
 * `true` = offline with a valid lease (decision comes from the cache, ALLOW only), `false` = offline with
 * an expired lease (protected reads are denied). Only an explicit ALLOW is ever allowed unconditionally;
 * REFRESH/REDACT/HUMAN_REVIEW are not raw-usable and therefore block under ENFORCE.
 */
export function resolve(
  decision: string,
  mode: FailMode,
  classification?: string | null,
  leaseOk?: boolean | null,
): EffectiveAction {
  const allowed = decision === "ALLOW";
  const prot = isProtected(classification);

  if (mode === FailMode.OBSERVE) return { allow: true, needsOverride: false, observedOnly: !allowed };
  if (mode === FailMode.WARN) {
    if (allowed) return { allow: true, needsOverride: false, observedOnly: false };
    if (prot) return { allow: false, needsOverride: true, observedOnly: false };
    return { allow: true, needsOverride: false, observedOnly: true };
  }
  if (mode === FailMode.BOUNDED_OFFLINE && leaseOk === false) {
    // Lease expired: no authority to serve anything protected, even a cached ALLOW.
    return {
      allow: !prot && decision !== "DENY" && decision !== "QUARANTINE",
      needsOverride: false,
      observedOnly: false,
    };
  }
  return { allow: allowed, needsOverride: false, observedOnly: false };
}
