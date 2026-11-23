# Agent Revocation Runtime

**Context must never outlive its authority.**

Agent Revocation Runtime tracks the sources behind RAG chunks, cached answers and agent memory so an application can withhold them when a source is deleted or access changes.

<a id="run-the-demo"></a>

## Quickstart

```bash
git clone https://github.com/Ales-Analytics/agent-revocation-runtime.git
cd agent-revocation-runtime
python -m pip install .
ales quickstart
```

The demo runs locally without an API key, Docker or a model. It indexes a synthetic HR document, creates derived memory and cache entries, then narrows the source ACL. Retrieval, cache replay and memory reads return `ANCESTOR_ACL_REVOKED` before physical purge. A successful run prints `ALL PASS: 12/12 checkpoints` and exits with code 0.

Use Python 3.11 or newer in a virtual environment. `ales quickstart` runs the demo against an in-process control plane with in-memory SQLite. The existing `python examples/revoke-rag-source/demo.py` entry point runs the same demo. For the TypeScript client, see the [SDK guide](sdk-typescript/README.md).

For the full stack: `docker compose -f deploy/docker-compose.yml up -d` then `python examples/revoke-rag-source/demo.py --server http://localhost:8787`.

## Documentation

The website routes below are prepared for launch. While the site is being deployed, the checkout links provide the working guides.

| Guide | Website | In this repository |
|---|---|---|
| Quickstart | [Quickstart](https://www.alesanalytics.com/agent-revocation-runtime/quickstart) | [Read in the checkout](examples/revoke-rag-source/README.md) |
| Concepts | [Concepts](https://www.alesanalytics.com/agent-revocation-runtime/concepts) | [Read in the checkout](docs/product.md) |
| Architecture | [Architecture](https://www.alesanalytics.com/agent-revocation-runtime/architecture) | [Read in the checkout](PROJECT_ARCHITECTURE_GUIDE.md) |
| Guarantees | [Guarantees](https://www.alesanalytics.com/agent-revocation-runtime/guarantees) | [Read in the checkout](docs/guarantees.md) |
| Integrations | [Integrations](https://www.alesanalytics.com/agent-revocation-runtime/integrations) | [Read in the checkout](examples/README.md) |
| HTTP reference | [HTTP reference](https://www.alesanalytics.com/agent-revocation-runtime/http-reference) | [Read in the checkout](docs/api/index.html) |
| Deploy | [Deploy](https://www.alesanalytics.com/agent-revocation-runtime/deploy) | [Read in the checkout](deploy/README.md) |
| Evidence | [Evidence](https://www.alesanalytics.com/agent-revocation-runtime/evidence) | [Read in the checkout](docs/coverage-matrix.md) |

**Release status (23 November 2026).** Apache-2.0. Python 3.11+, distribution `agent-revocation-runtime` 0.3.0 with Python SDK 0.2.0. Node.js 20+, TypeScript SDK `@ales-analytics/agent-revocation-runtime` 0.2.0. Both registry listings are pending first publication. The server implements spec v0.4. The CLI is `ales`, Python imports retain their `ales_` names, and runtime settings retain the `ALES_` prefix.

See the [four captured HTTP exchanges](docs/api/examples.md), [standalone OpenAPI contract](docs/api/openapi.json), and [maintainer release instructions](docs/release.md).

## RevocationBench

`python -m revocationbench` measures stale-context escapes across 13 scenarios: ACL revocation, source deletion, version supersession, poisoned source, cache replay, agent handoff, multi-tenant collision, control-plane outage, delayed revocation, scoped revocation, signed ingress, a 100-deep lineage chain and a 200-child fan-out. Both execution profiles have checked-in reports:

- `inprocess`: FastAPI TestClient, in-memory SQLite ([benchmark/reports/latest.md](benchmark/reports/latest.md)).
- `postgres`: real `uvicorn` process, real Postgres 16 and Redis in Docker, SDK over loopback HTTP; `service_outage` and `delayed_revocation` still run in-process because they need a transport kill / clock shift ([benchmark/reports/latest-postgres.md](benchmark/reports/latest-postgres.md)).

Each report names its source revision, run time, scenario outcomes and latency distribution. Download the raw [in-process JSON](benchmark/reports/latest.json) or [Postgres JSON](benchmark/reports/latest-postgres.json) to reproduce a figure or cite a measurement.

Latencies were measured on one Windows machine and are relative, not absolute. What is **not** covered is listed in each report, in [docs/guarantees.md](docs/guarantees.md) and in [docs/residual-risks.md](docs/residual-risks.md): uninstrumented paths, multi-replica deployments behind a load balancer, network partitions, sustained load, a real vector store in the benchmark, and cross-replica SDK-cache propagation. Concurrency (revocation racing in-flight reads, multi-process, concurrent registration, adversarial tenants) is covered separately by the `stress/` suite, not by the benchmark. We publish exposure windows; we do not claim instantaneous revocation, recall of already-seen information, or compliance certification.

## How it works

- **Context envelope** (`spec/`): signed, versioned authority metadata for sources and derivatives, without their content.
- **Derivation graph** (`core/`): records parent-child dependencies. An output built from several sources records each source as a parent.
- **Authority propagation**: derivatives inherit the most restrictive classification, intersected scopes, earliest expiry and least trust.
- **Revocation engine**: records events, tombstones affected context, advances the epoch and queues asynchronous purge. Read-time enforcement precedes cleanup.
- **Use-time enforcement** (`sdk-python/`, `adapters/`): checks authorization before context enters a model, memory, cache or handoff. Fail modes are OBSERVE, WARN, ENFORCE and BOUNDED_OFFLINE. Adapters that cannot block are labelled OBSERVE_ONLY and excluded from coverage claims.

Integrations connect the runtime to existing frameworks, vector stores, caches and cloud services.

## Repository

| Dir | Contents |
|---|---|
| `spec/` | The public contract: JSON Schemas + SPEC.md (start here) |
| `core/` | Graph, deterministic resolver, revocation engine |
| `server/` | FastAPI control plane for sources, derivations, revocations, authorization, policy, workloads, approvals, OIDC and metrics |
| `sdk-python/` | Python client, decision cache, session taint, fail modes, handoff and model gateway, `ales` CLI |
| `sdk-typescript/` | TypeScript client, decision cache, signed snapshots and fail modes |
| `adapters/` | Filesystem sources, guarded vector stores and caches, purge handlers, LangGraph, LlamaIndex and ACS integrations |
| `connectors/` | Source integrations, including S3 and Azure Blob Storage |
| `benchmark/` | RevocationBench scenarios, runner, reports |
| `stress/` | Concurrency scenarios: revoke-vs-read races, in-flight bound, multi-process, outbox contention, adversarial tenants (single host, SQLite and Postgres) |
| `conformance/` | Adapter contract tests (ENFORCING / INGESTION_ONLY / NON_ENFORCING) |
| `docs/` | Product contract ([product.md](docs/product.md)), rollout path ([rollout.md](docs/rollout.md)), threat model, guarantees, operations, upgrades, compatibility and residual risks |
| `deploy/` | Docker Compose, Helm chart and Terraform modules for cloud deployments |

Dev: `pip install -e ".[dev]"` then `pytest -q`. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
