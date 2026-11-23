# Agent Revocation Runtime: architecture and codebase guide

This guide describes the packages, data flow and trust boundaries. Use it alongside `spec/SPEC.md`, the test reports in `conformance/` and `benchmark/reports/`, and the operating guidance in `docs/`.

## 1. The project in one paragraph

Agent Revocation Runtime is a metadata control plane and SDK for tracking how AI context descends from source data. It stores versioned object envelopes and parent-to-child lineage, derives restrictive authority from ancestors, and makes an authorization decision when an instrumented application is about to use context. A revocation event creates authoritative tombstones and advances a tenant epoch in the database transaction; later authorization blocks matching descendants even while their bytes remain in vector stores, caches, or agent memory. An asynchronous outbox worker may then remove those bytes. The project does not host an LLM, vector search service, source-of-truth ACL engine, or agent orchestrator. Its guarantee is bounded to complete lineage registration and reads that pass through a guarded boundary.

## 2. Main components

The runtime has three main parts:

1. **A contract:** an envelope records identity, version, digest, classification, scopes, expiry, trust, and parent references. The JSON Schemas and spec/SPEC.md define the wire-level concepts.
2. **A graph and decision kernel:** SQL rows record objects and derivation edges. Pure deterministic logic combines authority and examines every ancestor and applicable tombstone.
3. **Enforcement hooks:** SDKs and adapters ask the control plane before consuming or handing off context; writes register derivation metadata.

The invariant is: ALLOW requires every recorded ancestor to remain valid for the authenticated tenant, principal, purpose, and current time. Incomplete lineage produces UNKNOWN; adapters treat unknown protected context as blocked. The LLM never decides access.

An envelope is metadata, not the document body. content_digest identifies the represented bytes; parent_refs express provenance. When a model output could have been influenced by several sources, the safe representation includes every candidate parent. This is conservative provenance, not token-level attribution.

## 3. Component and trust-boundary diagram

Source systems feed connectors. Connectors send source envelopes and revocation events to the FastAPI control plane. Application transforms send derivative envelopes with all parents. The API stores metadata in Postgres or SQLite. Python and TypeScript clients call authorize immediately before use; guarded adapters then allow or block access to vector stores, Redis, model prompts, memory, or handoffs. Revocation writes a tombstone, advances the epoch, and creates outbox work in the same transaction. A leased worker calls configured purge handlers afterward.

The API and database are the **control plane**. Your application, SDK, and adapters form the **data plane**. ALES stores lineage and policy metadata, not user document contents. Purge is cleanup: a purge outage delays physical removal but does not change the authorization result, because the resolver consults tombstones.

Trust boundaries to keep separate while reading:

- The API credential establishes the authenticated service subject, tenant, and route roles. A request tenant_id is checked against that identity; it does not establish identity itself.
- An envelope/event signature establishes that a registered active issuer key signed the metadata. It does not prove the metadata is true or that lineage is complete.
- A caller-provided principal describes whose access is being evaluated. It is not automatically the API caller's identity. Workload grants and policy rules can constrain it, but integrators must map end-user identity correctly.
- An adapter protects only reads made through that adapter. Direct access to its backing store is outside the guard.

## 4. Repository map: what each part owns

| Path | Responsibility | Good first files |
|---|---|---|
| spec/ | Normative envelope, revocation, decision schemas and protocol rules | SPEC.md, then the three JSON Schemas |
| core/ales_core/ | Domain models, persistence, graph, propagation, resolver, revocation, policy, identity registries, audit and outbox algorithms | models.py, db.py, graph.py, resolver.py, revocation.py |
| core/ales_core/alembic/ | Versioned database migrations | versions/0001_initial_schema.py through 0006_lifecycle.py |
| server/ales_server/ | HTTP API, authentication, configuration, signature ingress, transaction boundaries, worker lifecycle, metrics and operational checks | main.py, auth.py, routes.py, governance.py, worker.py |
| sdk-python/ales_sdk/ | Python HTTP client, signed snapshot verification, decision cache, fail modes, wrappers, model gateway, handoff/session taint, resilience and CLI | client.py, decision_cache.py, fail_modes.py, wrappers.py |
| sdk-typescript/src/ | TypeScript wire client, JCS-compatible signing/snapshot helpers, cache, fail modes and session taint | client.ts, jcs.ts, snapshot.ts |
| adapters/ales_adapters/ | Guarded vector/cache/framework/memory hooks, filesystem source connector and purge targets | pgvector_store.py, redis_cache.py, langgraph_middleware.py, llamaindex_adapter.py, acs_adapter.py |
| connectors/ales_connectors/ | Shared source connector SPI, diff/checkpoint logic, S3/Azure Blob/webhook integrations, connector health/freshness primitives | spi.py, provider connectors, registry.py |
| examples/revoke-rag-source/ | Small no-model end-to-end RAG-like revocation demo | README.md, demo.py |
| conformance/ | Executable adapter/source conformance scenarios and generated report | contract.py, subjects.py, suite.py, report.py |
| benchmark/ | RevocationBench scenarios, execution profiles, metrics and checked-in reports | reports/latest.md, scenarios.py, runner.py |
| stress/ | Race, multi-process, epoch, outbox contention and tenant adversarial tests | test_inflight_revocation.py, test_multiprocess.py, test_tenant_adversarial.py |
| docs/ | Product boundary, guarantees, threat model, integration, rollout, ops, upgrade, incident and residual-risk guidance | product.md, guarantees.md, threat-model.md, residual-risks.md |
| deploy/ | Compose, container image, Helm and provider-specific Terraform templates | README.md, docker-compose.yml, Dockerfile |
| scripts/ | Restore verification/export/reapplication helper | ales_restore_check.py |
| .github/workflows/ | CI, stress, TypeScript, deploy-template and supply-chain jobs | ci.yml, supply-chain.yml |

The root pyproject.toml is a single Python distribution mapping packages from these subdirectories. Some optional adapters need extras (demo, qdrant, pgvector, connectors, llamaindex); the TypeScript SDK has its own package configuration. The API package and Python SDK are not separate service processes by themselves; the Docker image packages the Python app.

## 5. Data model and persistence

The canonical object identity is (context_id, object_version). The database schema in core/ales_core/db.py separates graph facts from revocation state and operational work:

| Table / model | What it means | Why it matters |
|---|---|---|
| tenants | Tenant row and monotonically increasing revocation_epoch | Serializes mutation and invalidates stale client decisions |
| context_objects | One envelope's metadata per object version | Content digest and authority metadata; no document body |
| derivation_edges | Child-version → parent-version edges | Recursive lineage traversal in both directions |
| revocation_events | Accepted event record and resulting epoch | Event idempotency and incident history |
| tombstones | Authoritative root/version revocation with time and optional scope | Resolver input; context_objects.tombstoned is only denormalized information |
| invalidation_outbox | Store-kind purge task, lease, retry and dead-letter state | Durable asynchronous cleanup without coupling store I/O to authorization |
| issuer_keys | Tenant-scoped public Ed25519 keys and lifecycle | Verifies signed envelope/revocation ingress |
| audit_log | Per-tenant append-only hash chain | Tamper-evident event/decision/admin record sequence |
| policy_documents | Versioned tenant policy JSON; one active version by code invariant | Deterministic restrictions at authorize time (including tool selectors in authorize requests) |
| workloads, workload_grants | Registered agents/tools/connectors and principal-to-workload grants | Workload status/capability checks |
| delegations | Purpose-limited, expiring workload-to-workload delegation | Agent handoff gate |
| approvals | Pending/approved/denied decision fingerprint, TTL and requester fields | Human review scoped to an exact request; separation of duties |

GraphStore scopes lookup and traversal queries by tenant. The object primary key itself is (context_id, object_version), however, and the schema does not install PostgreSQL row-level security. Tenant isolation therefore depends on correct application predicates and tenant-bound credentials, not database RLS. The threat model recommends stronger storage separation when that boundary is not sufficient.

GraphStore.register_source() accepts only kind=source with no parents. register_derivation() requires a non-source kind and at least one parent; every parent must already exist in that tenant. It computes parent authority, rejects a child that claims wider authority, stores the child and inserts edges. Registration is idempotent only for an existing identity with the same digest; reusing the identity/version for different content is a conflict. Pending tombstones for a previously unknown source are materialized when a matching source is later registered.

GraphStore._walk() uses a recursive SQL CTE for transitive ancestors or descendants. Edges are version-specific. Revocation resolution can therefore trace the exact version that contributed to a derivative.

## 6. Authority propagation and authorization

### Authority inheritance

effective_authority() in core/ales_core/propagation.py folds all immediate parents:

- classification takes the most restrictive rank (public < internal < confidential < restricted);
- trust takes the least trusted rank (verified < untrusted < quarantined);
- principal and purpose scopes intersect; `None` means unrestricted, while an empty list or set grants access to nobody;
- expiry is the earliest non-null parent expiry.

check_not_wider() compares a proposed derivative against this computed result. It prevents accidental widening at registration. It does not independently prove that a source connector's original ACL or classification was truthful.

### Resolver algorithm

authorize_ex() in core/ales_core/resolver.py is deterministic database logic. Its order is important:

1. Validate the workload enforcement mode and normalize the supplied time to UTC.
2. Read the tenant epoch **before** walking lineage. An authorization racing a revocation is stamped with the old epoch if it read old graph state, which lets epoch-aware caches reject that ALLOW after observing the new epoch.
3. Resolve each requested context. An explicit version selects that version; an omitted version chooses the row with latest valid_from (version string breaks ties). Foreign-tenant IDs are returned on the wire as UNKNOWN/OBJECT_UNKNOWN, so the endpoint does not disclose their existence; the distinction is audit-only.
4. Load the requested node plus all ancestors. A missing graph node/edge yields UNKNOWN/LINEAGE_INCOMPLETE rather than assuming the context is safe.
5. Read tombstones for those IDs. A tombstone applies only at/after effective_at and only if its principal/purpose scope matches. Future matching tombstones contribute valid_until, the earliest cutover that can change the result without an epoch update.
6. Add findings for tombstone reason, object expiry, effective principal/purpose scope and quarantined trust. A superseded version is REFRESH only when that same object has a live sibling version; otherwise it is DENY.
7. Combine findings using DECISION_SEVERITY. The worst per-object decision becomes the request's overall decision; reasons are deduplicated. An empty findings list is ALLOW/OK.
8. Apply workload gates and the tenant's active deterministic policy as restrictions. An allow policy rule does not undo lineage denial. A human_review rule can create a pending approval.

The public authorize() function returns only the response. The server calls authorize_ex() to retain audit/approval metadata. This split keeps the core decision path read-only; the HTTP layer creates a pending approval and writes the decision ledger record in the same transaction before returning the result. If this audit/approval transaction fails, the server does not serve the decision.

The protocol defines REDACT, but the resolver does not implement content transformations. Framework hooks may remove denied records from a result list and call the action redact; that is adapter-side filtering, not a general redaction engine that reconstructs a partially safe document.

### Policy and human approval

core/ales_core/policy.py validates versioned policy documents. Rules are evaluated in document order, first match per (object, tool) pair, then aggregated worst-wins. Selectors are exact values or *; omitted means match-all. A policy can deny or request human review, and obligations can impose max_classification or require_fresh_lineage. Risk floors raise a caller-asserted risk tier; without a configured floor, the supplied risk remains advisory.

ApprovalStore fingerprints principal, purpose, exact resolved object/version set, tools, risk, and policy version. Therefore an approval is bound to a narrow request rather than a general identity. Pending records are created by the server; decisions have a TTL, are audited, and are subject to a requester/decider separation-of-duties check (migration 0003).

### Workloads and handoff

Workloads represent agents/tools/connectors. A workload can be suspended and can declare capabilities such as tool names. A grant says an authenticated principal may act as a workload. The decision resolver supports auto, strict, and off modes: auto activates a workload check after the tenant has registered workloads; strict checks any request naming an agent; off disables checks. Grant checks are similarly gated unless require_grants is set. Production configuration should use strict enforcement and explicit grants, rather than rely on auto mode.

Agent-to-agent transfer uses a separate handoff endpoint and authorize_handoff(): both workloads must be active and a live purpose-compatible delegation must exist. The Python SDK's handoff() invokes that endpoint when workload IDs are supplied, then copies local session exposure records into the receiving session. SessionTaint.enforce() can re-authorize all recorded exposures and require a session reset. These are integration primitives; the host must call them at the relevant lifecycle hooks.

## 7. Revocation: immediate decision state, deferred cleanup

RevocationEngine.accept() in core/ales_core/revocation.py is the central state transition. A tenant write lock serializes event acceptance. The transaction:

1. returns the original result if event_id was already accepted;
2. selects registered source versions, optionally narrowed by source_version;
3. creates authoritative root tombstones with reason, effective_at and normalized principal/purpose scope (an unknown source creates a pending tombstone);
4. for unscoped events, walks all descendants, updates informational tombstone flags, and creates outbox rows per affected object; scoped events avoid global purge because other principals may remain authorized;
5. increments the tenant epoch;
6. stores the accepted event and appends an audit-chain entry, then commits atomically.

The tombstone is stored at the root. Authorization discovers its effect on derivatives by walking parent edges, including descendants registered later. Delayed revocation is stored now but denies only once now >= effective_at; matching responses carry valid_until so caches can stop before that instant. Scoped events union by independent event match: scopes are not accidentally cross-multiplied between different tombstones.

After commit, the outbox dispatcher in core/ales_core/outbox.py leases due rows using conditional updates and lease tokens. It calls idempotent purge handlers outside the database transaction, then marks success, schedules exponential backoff, or dead-letters after six attempts. Expired leases can be reclaimed, and a stale worker cannot overwrite a newer lease owner. server/ales_server/worker.py runs this dispatcher in a background thread and exposes operator endpoints for stats, dead-letter inspection, requeue and one-shot dispatch.

The server only physically purges targets named in ALES_PURGE_TARGETS. With no target configured in development, the default handler is log-only: tombstones still block reads, but bytes remain in downstream stores. Production startup refuses unsafe purge configuration unless an explicit deny-only policy is chosen. Verify the actual worker.handlers status in /v1/outbox/stats.

## 8. Server, identity, signatures and audit

### Request path and endpoints

server/ales_server/main.py:create_app() builds the SQLAlchemy engine/session factory, loads settings and identity providers, validates production configuration, loads the snapshot signer, runs Alembic unless skipped, configures purge handlers/worker, installs middleware, and mounts routes.py plus governance.py.

The main router provides health/readiness (/v1/healthz, /v1/readyz); source and derivation registration, revocation acceptance, authorization, lineage inspection and an isolated self-check (/v1/sources, /v1/derivations, /v1/revocations, /v1/authorize, /v1/lineage, /v1/verify); signed policy snapshots and a public-key endpoint; issuer key registration/lifecycle; audit verification/head; and outbox operational endpoints.

governance.py provides policy install/activation, workload/grant/delegation CRUD, handoff authorization, approvals and metrics. Each route declares a role dependency. The authentication middleware validates static bearer tokens or configured OIDC JWTs, installs a server-owned identity on the request, and verifies tenant claims. Static token files and denylist files can hot-reload; OIDC may use static or remote JWKS with bounded caching. There is no general-purpose identity-provider management UI.

BodySizeLimitMiddleware enforces a configurable request body cap. Production startup checks in hardening.py refuse several unsafe settings (missing auth, unsigned ingress, ephemeral snapshot key, SQLite, non-strict workload gate, unsafe purge) unless explicit overrides are set. preflight.py is a separate operator diagnostic; in this checkout its --deep option performs a read round-trip to configured purge stores.

### Envelope/event signatures vs policy snapshots

Envelope/revocation signatures use Ed25519 and RFC 8785 canonical JSON in core/ales_core/signing.py. keys.py looks up the issuer key by ID, requires that key to belong to the object's tenant and be active, then verifies the signature. The route's _enforce_signature() makes this check conditional on ALES_REQUIRE_SIGNATURES; production configuration is intended to enable it. Key lifecycle is forward-only (active → retired → revoked). Revoking a key blocks new ingress signed by it; it does not retroactively revoke already registered objects.

Snapshots are a separate signature protocol. The intended payload is tenant, current epoch, active policy version, issue time and lease. Important current-code mismatch: routes.snapshot() passes the global resolver constant POLICY_VERSION (p0) rather than loading the tenant's active PolicyStore version. Python and TypeScript SDKs verify trusted public key material, reject tenant mismatch/epoch rollback, and calculate the lease from issued_at rather than restarting the entire clock at receipt. The signed snapshot does not contain the full policy; offline operation can only reuse prior cached ALLOW decisions whose epoch matches the snapshot.

### Audit chain

Every important decision and mutation can append a tenant-scoped hash-chained audit record (prev_hash, hash, actor, action, timestamp, identifiers/detail). /audit/verify recalculates the chain; /audit/head gives an operator a value to anchor outside the database. Optional append-only file export is best-effort and counts failures. The chain detects edits/reordering within the retained sequence, but deletion of the tail requires external anchoring to detect. Audit detail intentionally stores identifiers and decisions, not document content.

## 9. SDKs and enforcement adapters

### Python SDK

InvariantClient is the main client. It creates HTTP requests, parses results/errors, registers envelopes and submits events. Its thread-safe DecisionCache stores only ALLOW decisions and keys by tenant, principal type/id, purpose, object/version and policy version. Cache entries expire by TTL, observed epoch advancement, or valid_until with clock-skew margin. Tool/risk-scoped requests bypass the cache because those inputs are not in the cache key. Read the cache code carefully: the key also does not include agent_id, while workload/policy results can depend on it; that is a concrete correctness/security review question for the current checkout.

BOUNDED_OFFLINE requires trusted snapshot public keys. Online authorization can refresh a signed snapshot; if the service becomes unreachable, the SDK may reuse only a cached ALLOW at the same epoch while the snapshot lease remains valid. Otherwise it returns UNKNOWN. Fail modes map decisions to behavior: OBSERVE allows while recording the failure, WARN may require operator override for protected content, ENFORCE allows only explicit ALLOW, and expired BOUNDED_OFFLINE denies protected content.

wrappers.py contains common retrieval/memory/cache filtering. model_gateway.py wraps an OpenAI-compatible call: tracked prompt items are authorized, untracked items default to blocked unless exempt/explicitly allowed, and the response is registered as an artifact derivative of the context actually sent. session_taint.py remembers exposures and can re-authorize them. handoff.py enforces delegated transfer when workload IDs are supplied. resilience.py adds retry/circuit-breaker behavior; it does not make unknown authorization safe.

### TypeScript SDK

sdk-typescript/src/client.ts provides async HTTP operations, cache and signed-snapshot behavior. jcs.ts and snapshot.ts are central to cross-language canonicalization/signature compatibility. failModes.ts, decisionCache.ts and sessionTaint.ts provide corresponding local primitives. The package has client, cache, snapshot, fail-mode, JCS and integration tests; it is not a mirror of every Python helper (for example, the Python model gateway/adapters are separate).

### Adapter families

- **Vector stores:** GuardedVectorStore registers each chunk/embedding derivative and filters search hits before returning them. Backends include in-memory and Qdrant. The portable pgvector fallback stores JSON vectors and ranks in Python; PgVectorNativeBackend is the real PostgreSQL vector extension path. Direct backend/SQL access bypasses the guard.
- **Cache:** GuardedCache registers cached values as derivatives and stores a reverse index from context ID to key for purge. get() authorizes before returning and deletes blocked entries best-effort. It accepts a Redis-like client; the API process's REDIS_URL is not itself a shared authorization cache.
- **Framework/memory:** LangGraph decorators guard node input/output and register node outputs; LlamaIndex ingestion/retrieval hooks stamp context metadata and filter retrievals; ACS hook adapter maps knowledge, memory, tool and message hooks, filters blocked items, and checks session taint.
- **Filesystem source:** the source scanner registers files and emits delete, supersession and ACL-narrowing events. It is ingestion/event coverage; it is not a guarded file read.
- **Purge:** handler targets cover configured Redis, Qdrant and pgvector stores. They use object identity/version and verify absence after delete; handlers must remain idempotent.

Conformance success applies to the particular guarded subject and store/profile that was exercised. It does not cover unwrapped code paths in an application.

## 10. Source connectors and freshness

connectors/ales_connectors/spi.py is a shared abstraction for polling/event sources. TrackedConnector uses checkpoints to remember remote object identity, digest/version hint and normalized ACL. A common diff recognizes deletion, content supersession, and ACL narrowing; ACL widening does not revoke. A source listing failure is raised before diffing so an outage cannot be mistaken for mass deletion. FileCheckpoint persists connector state atomically; the default in-memory checkpoint is lost on process restart.

S3 and Azure Blob connectors adapt cloud listings/objects; WebhookConnector validates an authenticated/replay-protected event envelope. Connector health exposes last sync, lag, coverage and digest mode. ConnectorRegistry can run connectors and report stale/failed connectors; freshness_guard()/assert_fresh() are primitives. The server, SDK and adapters do not call them automatically. The integrator must schedule scans/reconciliation and block retrieval when connector freshness exceeds its chosen bound. Polling delay plus synchronization time is part of the revocation exposure window.

S3 digest mode deserves special attention: ETag-derived IDs are not always content hashes (especially encrypted or multipart objects). The connector can stream and hash object content, at extra read/egress cost. See R32 in docs/residual-risks.md before relying on auto for sensitive buckets.

## 11. Evidence, tests and how to interpret them

| Evidence | What it supports | What it does not prove |
|---|---|---|
| core/tests/ | Domain/model/graph/propagation/resolver/revocation/policy/audit behavior | Production identity, all database engines or every application path |
| server/tests/ | API validation, auth, route roles, startup hardening, signatures, snapshots, governance and operations | Real internet-facing/cloud deployment or independent security review |
| SDK/adapters/connectors tests | Each helper and adapter contract in the tested configuration | That a customer routes every read through those hooks |
| conformance/report.md | Named conformance subjects for the generated report | Universal adapter coverage; the checked-in report's rows and coverage matrix should be compared because the matrix includes live-store rows not present in the report table in this checkout |
| benchmark/reports/ | Sequential measured scenarios and named profiles/revision | Multi-replica, cross-region, sustained throughput, a real vector store for all paths, or outbox worker behavior unless explicitly included in that run |
| stress/ | Specific races, multi-process and adversarial tenant scenarios (SQLite; Postgres when configured) | Network partitions, broad load/scale SLOs or every production topology |
| .github/workflows/ | Intended CI checks for Python, stress, TypeScript, deploy templates and supply chain | That a workflow ran successfully in this local checkout; inspect GitHub run evidence separately |

The benchmark reports list the source revision in each report. Read the report header and its caveats before quoting a metric. Treat ENGINEERING_ASSESSMENT.md as a historical assessment dated 11 November 2026: it contains claims (for example, missing auth, migrations, outbox dispatch and snapshot verification) that do not describe the current code. Prefer current source and the updated docs/ pages where they disagree.

## 12. Important limits and review questions

1. **Instrumentation completeness:** an omitted source/parent edge or a direct store read bypasses ALES. No runtime mechanism in this repository detects every bypass.
2. **Disclosure is irreversible:** a revocation blocks later instrumented uses; it cannot retract content already sent to a person or model or erase model weights.
3. **Purge is configuration-dependent:** log-only cleanup leaves bytes in stores. A successful authorization denial is separate from physical erasure.
4. **Offline is bounded reuse, not offline policy evaluation:** the SDK reuses prior ALLOW decisions and requires a trusted, matching-epoch snapshot. Exposure includes the lease, acceptance delay and in-flight work.
5. **Cache variation:** decisions can depend on agent identity, tools, risk, policy, tenant, principal, purpose, object version and time. Verify each dimension is represented in the cache key or causes cache bypass. In the current Python client, agent_id warrants review because it can affect workload/policy checks but is absent from DecisionCache keys and from the cache-bypass predicate.
6. **Policy-version cache invalidation:** policy activation changes the resolver's policy_version but does not advance revocation_epoch. More directly, routes.snapshot() signs the global p0 constant instead of the tenant's active policy version. The Python and TypeScript clients include policy_version in cache keys, but offline cache reuse checks only snapshot epoch, not policy version. An old ALLOW may therefore outlive a stricter policy activation until cache/lease expiry. Treat policy cutover as a focused spec/code/test mismatch before relying on immediate enforcement.
7. **Application-layer tenancy:** role credentials bind tenant and route queries are tenant-scoped, but shared database schema/role has no RLS. A missing predicate in future code could cross the boundary.
8. **Connector timeliness:** source ACL changes are only noticed on the connector's next poll or event; registry health is not wired into authorization.
9. **Operations:** production behavior depends on persistent snapshot keys, active issuer keys, strong token handling, configured purge targets, worker monitoring, external audit anchoring, backups, restore checks and compatible migrations.
10. **Policy inputs:** caller-supplied risk is advisory without risk floors. Workload checks are auto by default in development; pin strict mode and grants when the workload boundary matters.
11. **Protocol modes:** decision enum values are broader than concrete transformations implemented in every adapter. Check how each adapter handles UNKNOWN, REFRESH, HUMAN_REVIEW and any REDACT path rather than assuming all modes return filtered content.

The current docs/residual-risks.md is the source of record for timed exposure windows and operator mitigations. The strongest accurate product statement is: ALES provides a deterministic, testable provenance-based authorization kernel and several guarded integrations, with guarantees bounded by supplied lineage, configured identity and purge controls, and actual use of instrumented paths.

## 13. A code-first learning route

The full staged workflow lives in PROJECT_LEARNING_WORKFLOW.md. A compact route through the runtime is:

1. **Contract:** README.md → spec/SPEC.md → JSON schemas → docs/product.md → docs/guarantees.md → docs/threat-model.md.
2. **One observed flow:** example README/demo → sdk-python/ales_sdk/envelope.py → server/ales_server/routes.py → core/ales_core/graph.py → core/ales_core/db.py.
3. **Decision:** models.py → propagation.py → resolver.py → policy.py / workloads.py / approvals.py → matching core tests.
4. **Revocation:** connector diff → routes.py ingress → revocation.py → tombstones.py → outbox.py → worker.py → purge target → next SDK read.
5. **Identity and integrity:** auth.py → oidc.py / denylist.py → keys.py / signing.py → snapshot.py → matching server and SDK tests.
6. **Enforcement edges:** Python client.py and wrappers.py → each adapter implementation/test → conformance contract and coverage matrix.
7. **Operations and evidence:** config.py / hardening.py / preflight.py → Alembic migrations → Docker/Helm/Terraform → operations/upgrades/incident docs → benchmark/stress reports.
8. **Language parity and ecosystem:** compare Python SDK with sdk-typescript/src/; then trace connector SPI to S3, Azure, webhook, and freshness registry.

At each point, record the contract, code entry point, state read/written, transaction boundary, test, bypass/failure behavior, and evidence limit. The capstone is to explain a source ACL revocation from connector observation through a post-revocation cache or vector read, naming every function, database fact, response reason, adapter action and operational caveat.
