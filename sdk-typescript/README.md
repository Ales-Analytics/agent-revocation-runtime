# Agent Revocation Runtime TypeScript SDK

Use this Node.js client to register AI context, authorize versioned objects before use, submit revocation events, and verify signed policy snapshots. The SDK calls a running Agent Revocation Runtime control plane. It is an ESM package for Node.js 20 or later.

## Install

The registry command below applies after the first npm release.

```bash
npm install @ales-analytics/agent-revocation-runtime
```

For a source build, run `npm ci`, `npm run build`, and `npm pack` from `sdk-typescript`, then install the resulting `.tgz` from your application.

## Check a registered object before use

```ts
import { InvariantClient } from "@ales-analytics/agent-revocation-runtime";

const client = new InvariantClient({ baseUrl, tenantId, authToken });
const principal = { type: "user", id: userId };
const result = await client.authorize(principal, "rag_answer", [[contextId, version]]);
if (!result.allowed) throw new Error(result.reason.join(", "));
```

Supply the control-plane URL, tenant and service credential from your server configuration. Use the end-user ID from the authenticated request and the context ID and version from ingestion. See the [complete runnable example](https://github.com/Ales-Analytics/agent-revocation-runtime/tree/main/examples/typescript).

Run the guard on the server at the point where your application would return the protected payload or supply it to a model. Keep the tenant's service token in server-side configuration. The authenticated host supplies the end-user identity and the exact registered object version. `authorize` returns decisions for the host to enforce, and a process-local cached `ALLOW` can remain valid within its configured bounds.

- [Project documentation](https://www.alesanalytics.com/agent-revocation-runtime)
- [Start the control plane and run the reproducible demo](https://github.com/Ales-Analytics/agent-revocation-runtime#quickstart)
- [Read the integration contract](https://github.com/Ales-Analytics/agent-revocation-runtime/blob/main/docs/integration-guide.md)
- [Review the wire specification](https://github.com/Ales-Analytics/agent-revocation-runtime/blob/main/spec/SPEC.md)
