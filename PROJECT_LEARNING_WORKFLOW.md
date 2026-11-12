# ALES INVARIANT: project learning workflow

This guide is a route through the repository for learning the whole system, from its contract to its runtime behavior and operational limits. Read it in order the first time. Afterward, use the maps and checklists as a reference when changing or debugging a subsystem.

## What this project is

ALES INVARIANT is a Python context integrity and revocation runtime. It records a graph from source objects to derived context (chunks, embeddings, summaries, memories, cache entries and artifacts). At an instrumented read or handoff boundary, it decides whether the object and every recorded ancestor are still usable by a principal for a purpose at the current time.

Its central rule is: **context cannot outlive its authority**. Decisions are deterministic; an LLM is never the access authority. Revocation first makes recorded descendants unusable at authorization time, then leaves physical invalidation/purge to cleanup paths. Anything not registered or not read through an instrumented boundary is outside that guarantee.

## Repository map

| Area | Role | Begin with |
|---|---|---|
| `spec/` | Public contract, wire schemas, normative behavior | `spec/SPEC.md`, then the three `*.schema.json` files |
| `core/ales_core/` | Data models, database records, lineage graph, propagation, authorization, revocation, signing | `models.py`, `db.py`, `graph.py`, `propagation.py`, `resolver.py`, `revocation.py`, `signing.py` |
| `server/ales_server/` | FastAPI control plane and persistence lifecycle | `main.py`, `routes.py`, `telemetry.py` |
| `sdk-python/ales_sdk/` | Client, envelopes, local allow cache, fail modes, enforcement helpers, session tracking, CLI | `client.py`, `envelope.py`, `decision_cache.py`, `fail_modes.py`, `wrappers.py`, `session_taint.py`, `cli.py` |
| `adapters/ales_adapters/` | Filesystem source connector, guarded vector/cache access and LangGraph hook | `fs_source.py`, `pgvector_store.py`, `redis_cache.py`, `langgraph_middleware.py`, `coverage.py` |
| `examples/` | Small end-to-end story with no LLM dependency | `revoke-rag-source/README.md`, then `demo.py` |
| `conformance/` | Executable adapter enforcement/ingestion contracts and generated report | `ales_conformance/contract.py`, `subjects.py`, `suite.py`, `report.py`, `report.md` |
| `benchmark/` | Scenario harness, measured outcomes and caveats | `reports/latest.md`, then `revocationbench/scenarios.py`, `harness.py`, `runner.py`, `metrics.py` |
| `docs/` | Integration guidance, guarantees, threat model and coverage state | `guarantees.md`, `threat-model.md`, `integration-guide.md`, `coverage-matrix.md` |
| `deploy/` | Local container topology | `docker-compose.yml`, `Dockerfile` |
| Root | Packaging, contribution/security policies and project assessment | `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `ENGINEERING_ASSESSMENT.md`, `pyproject.toml` |

`invariant.db` is a checked-in SQLite file in this checkout. Treat it as repository data; do not assume it is a migration or the canonical source of schema. The schema is currently declared in `core/ales_core/db.py`.

## How to study each file

For each stage below, keep a short notebook with: (1) purpose, (2) inputs and outputs, (3) invariants, (4) callers/callees, (5) failure behavior, and (6) the test that demonstrates it. When reading a behavior, follow this path:

1. Find the contract or schema field that defines the behavior.
2. Find the implementation and write down the call chain.
3. Read the closest tests and note exactly what they prove.
4. Identify what the tests do not exercise, especially bypass paths and infrastructure behavior.
5. Explain the behavior back in your own words before moving on.

Do not learn the repository as a collection of files. Learn it as a set of state transitions: registration → derivation → authorization → revocation → later authorization → adapter action.

## Staged reading path

### Stage 0 — Establish the map and baseline (30–45 minutes)

Read `README.md` once, then `pyproject.toml` and `CONTRIBUTING.md`. Use the repository map above to list the packages, optional dependencies, entry points and test directories. Read the headings in `ENGINEERING_ASSESSMENT.md` to understand what the maintainers have already assessed; return to its details only when you reach the corresponding subsystem.

**Checkpoint:** You can explain the project in one paragraph, name its major packages, and distinguish the public contract (`spec/`) from an implementation choice (`core/`, `server/`, SDK or adapter).

### Stage 1 — Learn the contract before implementation (1–2 hours)

Read `spec/SPEC.md` top to bottom. Build a one-page glossary for:

- envelope, source, derivative, parent reference and lineage;
- classification, principal scope, purpose scope, expiry and trust state;
- `ALLOW`, `DENY`, `UNKNOWN`, `REFRESH`, `REDACT`, `QUARANTINE` and `HUMAN_REVIEW`;
- tombstone, revocation epoch, fail mode and exposure window.

Then inspect `context_envelope.schema.json`, `revocation_event.schema.json` and `decision_api.schema.json`. For each JSON shape, note required fields, optional fields, enums, and how it maps to the prose contract. Read `docs/guarantees.md` and `docs/threat-model.md` next. Mark each statement as a guarantee, an assumption, an explicit non-guarantee, or a threat/control/residual-risk pair.

**Checkpoint:** Without reading code, you can predict what should happen when (a) an ancestor ACL narrows, (b) a parent version is superseded, (c) a parent is poisoned, (d) lineage is missing, and (e) the control plane is unavailable.

### Stage 2 — Observe the complete behavior in the demo (45–90 minutes)

Read `examples/revoke-rag-source/README.md`, then follow `examples/revoke-rag-source/demo.py` from `main()` to `run_flow()`. Trace the sequence and write down every network/client call and every object kind created. Identify which pieces are deliberately stand-ins (hash embedding, truncation summary, in-process cache, test-client bridge) and what the example does not claim to prove.

If you want to execute the demo, follow its README prerequisites and commands. Compare each printed checkpoint with the code path that produces it. No model or API key is required. The example's test at `examples/tests/test_demo.py` checks the demo flow.

**Checkpoint:** Draw the concrete lineage: source → chunks → summary → cache and memory. Explain why a cached value may remain physically stored while reads are already denied.

### Stage 3 — Understand the core data and graph (1–2 hours)

Read in this order:

1. `core/ales_core/models.py` — enums and Pydantic contract objects.
2. `core/ales_core/db.py` — ORM tables, keys, tenant epoch and invalidation outbox.
3. `core/ales_core/exceptions.py` — domain failures and their semantics.
4. `core/ales_core/graph.py` — registration rules, deduplication and recursive ancestor/descendant traversal.
5. `core/tests/test_graph.py` — connect each graph invariant to a test.

Pay special attention to versioned node identity `(context_id, object_version)`, tenant scoping, missing parents, duplicate registrations, and the difference between a source and a derivative. Sketch the database tables and arrows between them.

**Checkpoint:** You can show where a source row and a derivation edge are written, and explain how an unknown parent is rejected instead of silently creating incomplete lineage.

### Stage 4 — Trace authority propagation and authorization (1–2 hours)

Read `propagation.py`, then its tests in `core/tests/test_propagation.py`. Work through a made-up multi-parent example by hand: intersect scopes; choose the most restrictive classification and trust state; choose the earliest expiry; reject a derivative that claims broader authority.

Then read `resolver.py` and `core/tests/test_resolver.py`. Trace one request from `authorize()` through version resolution, ancestor loading, incomplete-lineage handling, tombstone/expiry findings, effective authority, per-object verdict and aggregate decision. Note how reason codes and severity combine, including what happens for cross-tenant and unknown objects.

**Checkpoint:** Given a small graph and a principal/purpose/time, you can calculate the expected verdict and reasons without running the code.

### Stage 5 — Trace revocation as a state transition (45–90 minutes)

Read `core/ales_core/revocation.py`, then `core/tests/test_revocation.py`. Follow event idempotency, durable event recording, root-version selection, descendant traversal, tombstone writes, invalidation outbox rows and tenant epoch update. Compare this with the order specified in `spec/SPEC.md`: synchronous deny first; physical invalidation is asynchronous.

Then inspect `core/ales_core/signing.py` and relevant tests in `core/tests/test_resolver.py` or graph tests if applicable. Verify what is actually signed and verified. Compare implementation canonicalization with the spec's stated RFC 8785 JCS requirement; treat any difference as a compatibility/security question to investigate, not as a prose assumption.

**Checkpoint:** You can explain what commits atomically during revocation, what is deferred, why repeated event IDs are idempotent, and what a signature does and does not prove.

### Stage 6 — Learn the control plane and API lifecycle (1–2 hours)

Read `server/ales_server/main.py` first for engine/app/error setup. Then read `routes.py` endpoint by endpoint: health, source registration, derivation registration, revocation, authorization, lineage and verify. Follow each endpoint back into core, and read `server/tests/test_api.py` alongside it. Finish with `telemetry.py` to understand emitted spans and decision logs.

For every endpoint, record HTTP method/path, input model, tenant handling, core call, transaction/commit behavior, response and error mapping. Notice which routes are public functions and which work is handled in the core versus transport layer.

**Checkpoint:** You can trace a JSON request from HTTP validation through SQLAlchemy to the response, and identify where transactions commit or roll back.

### Stage 7 — Learn SDK behavior at enforcement time (1–2 hours)

Read the SDK in this order:

1. `envelope.py` — creation of source/derivative envelopes and digests.
2. `client.py` — HTTP transport, registration, revocation, authorization and outage path.
3. `decision_cache.py` — ALLOW-only caching, TTL and epoch invalidation.
4. `fail_modes.py` — how decisions become allow/block actions.
5. `wrappers.py` and `session_taint.py` — filtering before use and session bookkeeping.
6. `cli.py` — user-facing commands and their wiring.

Read `sdk-python/tests/` with the corresponding module. In particular, reason separately about server-reachable authorization, a same-process revocation advancing the epoch, a cached ALLOW, an offline bounded lease, and an expired lease. Follow a guarded retrieval through `_guard()` and `resolve()`; do not assume every decision except `ALLOW` has the same behavior in every fail mode.

**Checkpoint:** You can say exactly when the SDK can reuse an ALLOW, what invalidates it, and why an offline cache is not equivalent to a fresh server decision.

### Stage 8 — Learn adapters as enforcement boundaries (1–2 hours)

For each adapter, read implementation and tests as a pair:

- `fs_source.py` ↔ `adapters/tests/test_fs_source.py`: scan, sidecar ACLs, content changes/deletions, event emission and connector state.
- `pgvector_store.py` ↔ `test_pgvector_store.py`: backend abstraction, stored metadata, search and guarded result filtering.
- `redis_cache.py` ↔ `test_redis_cache.py`: cache wrapper, context dependencies and blocked-hit behavior.
- `langgraph_middleware.py` ↔ `test_langgraph_middleware.py`: guarded node input/output and lineage registration.
- `coverage.py`: adapter coverage metadata and how it is represented.

At every read path, ask the four questions from `docs/integration-guide.md`: where context enters, where derivatives form, where retrieval/handoff occurs, and where blocking is possible. Read `docs/coverage-matrix.md` after the implementations. It is the declared coverage inventory; a test passing does not cover direct access to an underlying store.

**Checkpoint:** For each adapter, list covered operations, bypass paths, whether it can block, and which conformance level/report it has. Separate tested adapter behavior from a system-wide coverage claim.

### Stage 9 — Understand evidence and its boundaries (1–2 hours)

Read `conformance/report.md`, then `conformance/ales_conformance/contract.py`, `subjects.py`, `suite.py` and `report.py`. Map each check to the enforcement contract or ingestion contract. Then read `benchmark/reports/latest.md` carefully before looking at benchmark code. Study `scenarios.py`, `harness.py`, `runner.py` and `metrics.py` to understand exactly how the reported values are produced.

For every metric, write down its denominator and environment. Explicitly note the report's exclusions: uninstrumented reads, physical purge timing, cross-process cache staleness, real network/Postgres effects, concurrency races and scale. Treat benchmark results as evidence for the scenarios and harness described, not as a universal production guarantee.

**Checkpoint:** You can distinguish a conformance check, a benchmark measurement, a normative guarantee and an untested assumption.

### Stage 10 — Deployment, security and contributor control (45–90 minutes)

Read `deploy/docker-compose.yml` and `deploy/Dockerfile`; identify the server, Postgres and Redis roles, ports, health checks, volumes and configuration. Read `SECURITY.md` for vulnerability reporting. Return to `CONTRIBUTING.md` for test/style commands, adapter rules, spec versioning/migration expectations and DCO. Review `pyproject.toml` again to connect packages, optional extras, scripts and test configuration.

**Checkpoint:** You can bring up or explain the local topology and know the repository's rules for changing the contract, adding an adapter, and reporting a vulnerability.

### Stage 11 — Capstone: explain the system end to end (1–2 hours)

Without referring to the README, explain this lifecycle on paper:

1. A connector discovers a source and creates an envelope.
2. The server validates and stores it.
3. An adapter creates a derivative with all parent references.
4. A client asks whether the derivative is usable for a principal and purpose.
5. The resolver walks lineage and returns a deterministic verdict.
6. The adapter allows or blocks before context is passed onward.
7. A source event is accepted; descendants are tombstoned, epoch advances and invalidation work is queued.
8. A subsequent read is denied even if a physical cache/vector entry remains.
9. A bounded-offline client behaves according to its lease and cached ALLOW state.

For each step name the file, main function/class and closest test. Then pick one failure (missing lineage, ACL narrowing, supersession, poisoned input, tenant mismatch or server outage) and trace it through all layers.

**Completion checkpoint:** You can explain capability, data flow, trust boundaries, persistence, failure modes, measured evidence and non-guarantees; navigate from an API behavior to its spec, implementation, test and operational caveat.

## Fast navigation index

Use these as entry points when a question comes up:

| Question | Start here | Follow through |
|---|---|---|
| What exactly is allowed? | `spec/SPEC.md` | `core/ales_core/resolver.py` → `sdk-python/ales_sdk/fail_modes.py` |
| How is lineage stored? | `core/ales_core/db.py` | `core/ales_core/graph.py` → graph tests |
| Why does a derivative inherit restrictions? | `core/ales_core/propagation.py` | propagation tests → spec authority table |
| What does revocation change? | `core/ales_core/revocation.py` | revocation tests → server route → client epoch cache |
| How is a source discovered? | `adapters/ales_adapters/fs_source.py` | connector tests → demo |
| Can retrieval/cache/memory be blocked? | `sdk-python/ales_sdk/wrappers.py` | adapter implementation/tests → conformance report |
| What can the runtime promise? | `docs/guarantees.md` | `docs/threat-model.md` → coverage matrix and benchmark caveats |
| How do I integrate another system? | `docs/integration-guide.md` | conformance contract → adapter example |
| How strong is current evidence? | `conformance/report.md`, `benchmark/reports/latest.md` | respective generators and scenario/tests |

## Keep a project-control notebook

Keep these living artifacts as you learn or maintain the project:

- **Component map:** packages, entry points, dependencies and owners/maintainers if known.
- **Data dictionary:** envelope fields, table fields, event fields, API request/response fields.
- **Call-chain index:** API route → core operation → SDK/adapter caller → tests.
- **Invariant ledger:** each invariant, where it is specified, enforced and tested, plus known gaps.
- **Threat and coverage ledger:** threat, control, instrumented path, bypasses, residual risk and evidence.
- **Change log:** any mismatch among spec, docs, implementation and generated reports; resolve contract questions before changing behavior.

## Repository caveats to check while learning

- The README describes the project as pre-release v0.1; treat it as active software whose guarantees depend on instrumentation and deployment configuration.
- `docs/coverage-matrix.md` currently says all adapter rows are pending and no adapter is claimed conformant, while `conformance/report.md` records passing local subjects for vector, cache, LangGraph and filesystem behavior. Understand the difference between passing a local suite and a declared coverage-matrix claim; confirm whether the matrix is intentionally stale before relying on it.
- The benchmark report is a generated, dated in-process result. Its caveats are part of the result and should be read alongside the headline metrics.
- `spec/SPEC.md` is explicitly normative. If code and spec disagree, document the mismatch and follow the project's spec-change process rather than silently treating implementation as the contract.
- Signing documentation states RFC 8785 JCS canonicalization. Check `core/ales_core/signing.py` against that requirement as a focused review question; its implementation should be verified against the stated canonicalization before depending on cross-language signature compatibility.

## Suggested pacing

For a deep first pass, plan on roughly 10–15 focused hours, split across several sessions. Do not try to memorize every line. Aim to own the key invariants and call paths, then use tests, schemas and the fast navigation index to re-enter details. After the capstone, repeat the same workflow for each proposed change: contract → implementation → tests → adapter coverage → operational caveats.
