import { describe, expect, it } from "vitest";
import { FailMode, isProtected, resolve, type EffectiveAction } from "../src/failModes.js";

type Row = [FailMode, string, string | null, boolean | null, Partial<EffectiveAction>];

const act = (allow: boolean, extra: Partial<EffectiveAction> = {}): EffectiveAction => ({
  allow,
  needsOverride: false,
  observedOnly: false,
  ...extra,
});

describe("fail-mode matrix (protected classification)", () => {
  const cases: Row[] = [
    // OBSERVE: log only; everything proceeds, non-ALLOW is labelled observed-only
    [FailMode.OBSERVE, "ALLOW", "restricted", null, act(true)],
    [FailMode.OBSERVE, "DENY", "restricted", null, act(true, { observedOnly: true })],
    [FailMode.OBSERVE, "UNKNOWN", "restricted", null, act(true, { observedOnly: true })],
    // WARN: protected non-ALLOW needs operator override
    [FailMode.WARN, "ALLOW", "restricted", null, act(true)],
    [FailMode.WARN, "DENY", "restricted", null, act(false, { needsOverride: true })],
    [FailMode.WARN, "UNKNOWN", "restricted", null, act(false, { needsOverride: true })],
    // ENFORCE: only ALLOW passes
    [FailMode.ENFORCE, "ALLOW", "restricted", null, act(true)],
    [FailMode.ENFORCE, "DENY", "restricted", null, act(false)],
    [FailMode.ENFORCE, "UNKNOWN", "restricted", null, act(false)],
    // BOUNDED_OFFLINE, server reachable: behaves like ENFORCE
    [FailMode.BOUNDED_OFFLINE, "ALLOW", "restricted", null, act(true)],
    [FailMode.BOUNDED_OFFLINE, "DENY", "restricted", null, act(false)],
    [FailMode.BOUNDED_OFFLINE, "UNKNOWN", "restricted", null, act(false)],
    // BOUNDED_OFFLINE, valid lease: cached ALLOW only
    [FailMode.BOUNDED_OFFLINE, "ALLOW", "restricted", true, act(true)],
    [FailMode.BOUNDED_OFFLINE, "DENY", "restricted", true, act(false)],
    [FailMode.BOUNDED_OFFLINE, "UNKNOWN", "restricted", true, act(false)],
    // BOUNDED_OFFLINE, expired lease: protected reads denied even for a cached ALLOW
    [FailMode.BOUNDED_OFFLINE, "ALLOW", "restricted", false, act(false)],
    [FailMode.BOUNDED_OFFLINE, "DENY", "restricted", false, act(false)],
    [FailMode.BOUNDED_OFFLINE, "UNKNOWN", "restricted", false, act(false)],
    // unknown classification is protected
    [FailMode.ENFORCE, "UNKNOWN", null, null, act(false)],
    [FailMode.BOUNDED_OFFLINE, "ALLOW", null, false, act(false)],
  ];
  it.each(cases)("%s / %s / classification=%s / leaseOk=%s", (mode, decision, cls, lease, expected) => {
    expect(resolve(decision, mode, cls, lease)).toEqual(expected);
  });
});

describe("fail-mode matrix (public classification)", () => {
  const cases: Row[] = [
    [FailMode.WARN, "UNKNOWN", "public", null, act(true, { observedOnly: true })],
    [FailMode.WARN, "DENY", "public", null, act(true, { observedOnly: true })],
    [FailMode.ENFORCE, "UNKNOWN", "public", null, act(false)],
    [FailMode.ENFORCE, "DENY", "public", null, act(false)],
    [FailMode.BOUNDED_OFFLINE, "ALLOW", "public", false, act(true)],
    [FailMode.BOUNDED_OFFLINE, "UNKNOWN", "public", false, act(true)],
    [FailMode.BOUNDED_OFFLINE, "DENY", "public", false, act(false)],
    [FailMode.BOUNDED_OFFLINE, "QUARANTINE", "public", false, act(false)],
  ];
  it.each(cases)("%s / %s / classification=%s / leaseOk=%s", (mode, decision, cls, lease, expected) => {
    expect(resolve(decision, mode, cls, lease)).toEqual(expected);
  });
});

describe("non-ALLOW, non-DENY decisions are never raw-usable under ENFORCE", () => {
  it.each(["REFRESH", "REDACT", "HUMAN_REVIEW", "QUARANTINE", "bogus"])("%s", (d) => {
    expect(resolve(d, FailMode.ENFORCE, "internal").allow).toBe(false);
  });
});

describe("isProtected", () => {
  it("treats everything except public as protected", () => {
    expect(isProtected("public")).toBe(false);
    for (const c of ["internal", "confidential", "restricted", null, undefined, ""]) {
      expect(isProtected(c)).toBe(true);
    }
  });
});
