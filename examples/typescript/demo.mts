import { InvariantClient, type ContextEnvelope } from "@ales-analytics/agent-revocation-runtime";

// The public development token is accepted only by the local example server or dev Compose stack.
const api = new InvariantClient({
  baseUrl: "http://127.0.0.1:8787", tenantId: "dev",
  authToken: "dev-only-INSECURE-token-do-not-use-in-production",
});
const bytes = new TextEncoder().encode("Returns within 30 days.");
const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
const source: ContextEnvelope = {
  context_id: crypto.randomUUID(), tenant_id: "dev", object_id: "handbook", object_version: "1",
  kind: "source", parent_refs: [], source_system: "examples", classification: "internal",
  trust_state: "verified", policy_version: "v1", valid_from: new Date().toISOString(),
  content_digest: "sha256:" + Array.from(hash, b => b.toString(16).padStart(2, "0")).join(""),
};
await api.registerSource(source);
const check = () => api.authorize({ type: "user", id: "support-reader" }, "support", [[source.context_id, "1"]]);
const before = await check();
if (!before.allowed) throw new Error(before.reason.join(", "));
console.log(before.decision);
await api.submitRevocation({ source_id: source.context_id, reason: "deleted" });
const after = await check();
if (after.decision !== "DENY" || !after.reason.includes("ANCESTOR_DELETED")) throw new Error("Expected deletion to block the read");
console.log(after.decision, "ANCESTOR_DELETED");
