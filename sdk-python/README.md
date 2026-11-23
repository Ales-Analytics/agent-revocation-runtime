# Agent Revocation Runtime

Agent Revocation Runtime is an open-source runtime for tracking source lineage and checking whether derived AI context may still be used. If a registered source is deleted, replaced, or restricted, a guarded retrieval, cache, or memory path can withhold its descendants. Your application keeps the payloads and applies the authorization verdict.

## Install and try the demo

Use Python 3.11 or newer in a virtual environment. In a checkout, run `python -m pip install .`. Once the first PyPI release is available, use:

```bash
python -m pip install agent-revocation-runtime
ales quickstart
```

The demo starts a control plane in-process on SQLite. It registers a synthetic HR policy and derives searchable chunks, a cached answer, and a memory entry. A source ACL change causes the registered reads to return `ANCESTOR_ACL_REVOKED`. A successful run ends with `ALL PASS: 12/12 checkpoints`, including verification of the audit chain. The run requires no Docker, model, API key, or separate server.

## Use it in an application

Start the FastAPI control plane, register sources and their exact derivative parents, and check authorization before releasing retrieved context. The Python package includes the `ales_sdk.InvariantClient`, the control plane, adapters, connectors, and database migrations. The TypeScript package is a separate HTTP client.

- [Run the demo from source](https://github.com/Ales-Analytics/agent-revocation-runtime#quickstart)
- [Read the architecture and wire contract](https://github.com/Ales-Analytics/agent-revocation-runtime/blob/main/spec/SPEC.md)
- [Integrate a guarded path](https://github.com/Ales-Analytics/agent-revocation-runtime/blob/main/docs/integration-guide.md)
- [Deploy the control plane](https://github.com/Ales-Analytics/agent-revocation-runtime/tree/main/deploy)
- [Review guarantees and their scope](https://github.com/Ales-Analytics/agent-revocation-runtime/blob/main/docs/guarantees.md)

Licensed under Apache-2.0.
