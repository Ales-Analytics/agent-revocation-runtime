/**
 * End-to-end test against the real Python server. Skipped unless ALES_ITEST=1.
 *
 *   ALES_ITEST=1 npm test
 */
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { InvariantClient, type ContextEnvelope } from "../src/index.js";

const ENABLED = process.env["ALES_ITEST"] === "1";
const PORT = 8788;
const BASE = `http://127.0.0.1:${String(PORT)}`;
const TOKEN = "itest-token-0123456789";
const OTHER_TOKEN = "itest-other-token-9876543210";
const TENANT_ID = "itest-tenant";
const REPO_ROOT = resolve(import.meta.dirname, "..", "..");

async function sha256Digest(text: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return "sha256:" + [...d].map((b) => b.toString(16).padStart(2, "0")).join("");
}

describe.skipIf(!ENABLED)("integration: real Python server", () => {
  let proc: ChildProcess | undefined;
  let dir = "";
  let output = "";

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "ales-itest-"));
    const python = process.platform === "win32" ? join(REPO_ROOT, ".venv", "Scripts", "python.exe") : join(REPO_ROOT, ".venv", "bin", "python");
    const dbPath = join(dir, "itest.db").replace(/\\/g, "/");
    proc = spawn(python, ["-m", "uvicorn", "ales_server.main:app", "--port", String(PORT), "--host", "127.0.0.1"], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        ALES_TOKENS: JSON.stringify({
          [TOKEN]: { tenant_id: TENANT_ID, roles: ["ingest", "revoke", "read", "admin"], subject: "itest" },
          [OTHER_TOKEN]: { tenant_id: "someone-else", roles: ["read"], subject: "other" },
        }),
        DATABASE_URL: `sqlite:///${dbPath}`,
        ALES_REQUIRE_SIGNATURES: "0",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    proc.stdout?.on("data", (b: Buffer) => (output += b.toString()));
    proc.stderr?.on("data", (b: Buffer) => (output += b.toString()));
    let exited = false;
    proc.on("exit", () => (exited = true));

    const deadline = Date.now() + 45_000;
    for (;;) {
      if (exited) throw new Error("server exited early:\n" + output);
      try {
        const r = await fetch(`${BASE}/v1/healthz`);
        if (r.ok) break;
      } catch {
        /* not up yet */
      }
      if (Date.now() > deadline) throw new Error("server did not become healthy:\n" + output);
      await new Promise((r) => setTimeout(r, 250));
    }
  }, 60_000);

  afterAll(() => {
    if (proc !== undefined && proc.pid !== undefined) {
      if (process.platform === "win32") {
        spawn("taskkill", ["/pid", String(proc.pid), "/T", "/F"], { stdio: "ignore" });
      } else {
        proc.kill("SIGTERM");
      }
    }
    // give the process a moment to release the sqlite file; best effort cleanup
    setTimeout(() => {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        /* best effort */
      }
    }, 1000).unref();
  });

  it("register -> derive -> ALLOW -> revoke -> DENY -> verified snapshot", async () => {
    const client = new InvariantClient({ baseUrl: BASE, tenantId: TENANT_ID, authToken: TOKEN });
    const principal = { type: "user", id: "alice" };

    const sourceId = crypto.randomUUID();
    const chunkId = crypto.randomUUID();
    const source: ContextEnvelope = {
      context_id: sourceId,
      tenant_id: TENANT_ID,
      object_id: "doc-1",
      object_version: "1",
      content_digest: await sha256Digest("hello"),
      kind: "source",
      source_system: "itest",
      classification: "internal",
      trust_state: "verified",
      parent_refs: [],
      policy_version: "v1",
      valid_from: new Date(Date.now() - 60_000).toISOString(),
    };
    const reg = await client.registerSource(source);
    expect(reg["context_id"]).toBe(sourceId);

    const chunk: ContextEnvelope = {
      ...source,
      context_id: chunkId,
      object_id: "doc-1#chunk-0",
      content_digest: await sha256Digest("hel"),
      kind: "chunk",
      parent_refs: [{ context_id: sourceId, object_version: "1" }],
    };
    const dreg = await client.registerDerivation(chunk);
    expect(dreg["context_id"]).toBe(chunkId);

    const lineage = await client.lineage(chunkId);
    expect(JSON.stringify(lineage)).toContain(sourceId);

    const before = await client.authorize(principal, "rag", [chunkId]);
    expect(before.decision).toBe("ALLOW");
    expect(before.fromCache).toBe(false);
    expect((await client.authorize(principal, "rag", [chunkId])).fromCache).toBe(true);

    const rev = await client.submitRevocation({ source_id: sourceId, reason: "deleted" });
    expect(typeof rev["revocation_epoch"]).toBe("number");

    const after = await client.authorize(principal, "rag", [chunkId]);
    expect(after.decision).toBe("DENY");
    expect(after.reason).toContain("ANCESTOR_DELETED");
    expect(after.fromCache).toBe(false);

    // snapshot: fetch the server's key over the authenticated endpoint, then verify end to end
    const keyResp = await fetch(`${BASE}/v1/snapshot/public_key`, { headers: { Authorization: `Bearer ${TOKEN}` } });
    expect(keyResp.status).toBe(200);
    const keyInfo = (await keyResp.json()) as { key_id: string; public_key_b64: string };
    const verifier = new InvariantClient({
      baseUrl: BASE,
      tenantId: TENANT_ID,
      authToken: TOKEN,
      failMode: "BOUNDED_OFFLINE",
      snapshotPublicKey: { [keyInfo.key_id]: keyInfo.public_key_b64 },
    });
    const snap = await verifier.refreshSnapshot();
    expect(snap.tenantId).toBe(TENANT_ID);
    expect(snap.revocationEpoch).toBe(rev["revocation_epoch"]);
    expect(snap.keyId).toBe(keyInfo.key_id);
    expect(verifier.snapshotValid()).toBe(true);

    // a different key must not verify the server's snapshot
    const wrong = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const wrongRaw = new Uint8Array(await crypto.subtle.exportKey("raw", wrong.publicKey));
    const badClient = new InvariantClient({
      baseUrl: BASE,
      tenantId: TENANT_ID,
      authToken: TOKEN,
      failMode: "BOUNDED_OFFLINE",
      snapshotPublicKey: wrongRaw,
    });
    await expect(badClient.refreshSnapshot()).rejects.toMatchObject({ reason: "bad_signature" });
  });

  it("rejects bad credentials and cross-tenant use", async () => {
    const bad = new InvariantClient({ baseUrl: BASE, tenantId: TENANT_ID, authToken: "wrong-token" });
    await expect(bad.lineage("x")).rejects.toMatchObject({ name: "AuthError", statusCode: 401 });
    const cross = new InvariantClient({ baseUrl: BASE, tenantId: TENANT_ID, authToken: OTHER_TOKEN });
    await expect(cross.lineage("x")).rejects.toMatchObject({ name: "TenantMismatchError", statusCode: 403 });
  });
});
