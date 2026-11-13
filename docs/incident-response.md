# Incident response runbooks

Concrete steps for the incidents this runtime can actually help with. Endpoints and audit action names were checked against `server/ales_server/routes.py` and `core/ales_core/`. Where a step needs direct database access because no HTTP route exists, it says so. Read `docs/residual-risks.md` before any incident, since several steps are limited by known gaps.

Conventions:

- Admin calls need an `admin` token. Read calls need `read`. Revocations need `revoke` and, when `ALES_REQUIRE_SIGNATURES=1`, a revocation signed by an active key in the tenant's registry.
- The tenant is always the token's tenant. A `tenant_id` in a body or query that disagrees gets 403.
- Audit records are written for decisions (`decision.authorize`), revocations (`revocation.accept`), registrations (`source.register`, `derivation.register`), rejected ingress (`ingress.rejected`), and admin key actions (`admin.key.register`, `admin.key.set_status`, `admin.key.list`), plus `admin.audit.verify`.
- v0.3 governance adds `policy.install`, `policy.activate`, `workload.register`, `workload.status`, `workload.capabilities`, `workload.grant`, `workload.grant_revoke`, `delegation.create`, `delegation.revoke`, `handoff.authorize`, `approval.request` (actor = the caller whose authorize created it) and `approval.decide` (actor = the admin who decided). Use these to reconstruct approval and handoff history.
- **There is no HTTP endpoint that lists audit records.** Reading them needs direct access to the `audit_log` table (columns `seq, tenant_id, prev_hash, hash, at, actor, action, detail`). Plan read access to that table for responders before you need it.

## Runbook 1: Suspected leak of revoked context

Symptoms: content from a source that was revoked, deleted, superseded or quarantined appeared in a response, a model prompt, a cache or an agent memory after the revocation time.

1. **Pin down the source and time.** Record the `context_id`, the source's revocation event id and `effective_at`, and the time the content was served. Check whether the revocation was accepted before the read: `audit_log` `revocation.accept` with `at` before the read.
2. **Confirm lineage.** `GET /v1/lineage/{context_id}?tenant_id=<tenant>&version=<v>` (read). It returns `ancestors` and `descendants` with a time-correct `tombstoned` flag. Every affected descendant should show `tombstoned: true` after the revocation. A `false` on a descendant the revocation should have covered means the graph is missing an edge. Record which derivatives were served and their ids.
3. **Check what was decided.** In `audit_log`, select `decision.authorize` records for the principal and the time window. `detail` holds identifiers and verdicts, not content. An ALLOW after the revocation time on a descendant is a control failure. Record the `trace_id` values.
4. **Check the physical stores.** `GET /v1/outbox/stats` (read). Look at `dead` and at `worker.handlers`. If `worker.handlers` is `log_only`, **nothing was purged from any store**; the revoked content still sits in caches, indexes and memory. Purge manually from each store, and record the store and object ids. If `dead > 0`, the affected rows are dead-lettered and need direct recovery (`docs/operations.md` section 4).
5. **Sessions that consumed the content.** SDK `SessionTaint` (`sdk-python/ales_sdk/session_taint.py`) records which context objects each session consumed. `is_tainted(session_id, revoked_ids)` tells you whether a session must reset. Taint is held in process memory. It is lost on restart and is not shared between replicas. Sessions that ran in another process need to be identified from application logs or the `decision.authorize` trace ids. Reset tainted sessions with `clear(session_id)` and start them fresh. Use `transfer` only for handoffs you have verified.
6. **Contain.** If the leak is ongoing, quarantine the source (runbook 2, step 2) so that descendants return `QUARANTINE`. Do not rely on purge alone.
7. **Communicate.** The runtime cannot recall content a person or model has already seen (SPEC non-guarantee). Record exactly what was disclosed, to whom, and when. Do not describe the incident as "fully contained" unless steps 4 and 5 are complete.
8. **Afterwards.** Verify the audit chain (`GET /v1/audit/verify`, admin). Add a regression test for the path that served the content if it was an uninstrumented one.

## Runbook 2: Compromised connector

Symptoms: a connector registered envelopes with wrong ACLs, forged lineage or suppressed revocations, or its signing key is suspected leaked.

1. **Find its issuer key.** `GET /v1/admin/keys` (admin) lists keys for the tenant with `key_id` and `status`. The connector's envelopes carry `issuer_key_id`, recorded in `source.register` and `derivation.register` audit detail.
2. **Stop new trust from that connector.** `PATCH /v1/admin/keys/{key_id}` with body `{"status": "revoked"}` (admin). Registration checks in `_enforce_signature` then reject envelopes signed by that key with `key_not_active` (only when signatures are required). Audit: `admin.key.set_status`. Other tenants' keys are reported as 404.
3. **Quarantine what it already registered.** Submit revocation events for each affected source with `reason` set to `poisoned` or `compromised`. Both map to decision `QUARANTINE` with `ANCESTOR_QUARANTINED`, and propagate to descendants. Use `deleted` or `acl_changed` if content must be denied outright. Use `affected_scope` to narrow to principals or purposes if needed. The revocation must itself be signed by an active key (step 4 below), because `_enforce_signature` applies to revocations too.
   - Stop and check: the key from step 2 is revoked. Your revocation needs a **different, active** key in the tenant's registry. Register it first, if needed, with `POST /v1/admin/keys` (admin).
4. **Confirm.** Check `GET /v1/outbox/stats` and lineage for descendants (runbook 1, step 2). Check that `revocation.accept` records exist for each source.
5. **Rotate the connector's credentials.** Rotate its bearer token (runbook 3) and its cloud or source credentials, outside this runtime.
6. **Review the connector's history.** Query `audit_log` for `source.register`, `derivation.register` and `ingress.rejected` by that connector's token subject, back to the earliest suspected time. `ingress.rejected` records the reason, one of `missing_signature`, `unknown_key`, `key_not_active` (retired or revoked), `bad_signature`, or `cross_tenant_key` (the wire response collapses the last to `unknown_key`). Use these to scope which envelopes were refused.
7. **Known limit.** Revoking a key is an ingress control. This review did not find code that revokes objects already registered under the key (residual risk R14). Treat step 3 as the mechanism that actually denies existing objects.

## Runbook 3: Compromised service token

Symptoms: a bearer token is leaked, or its subject performed actions it should not have.

1. **Remove the token.** Delete the entry from `ALES_TOKENS` or `ALES_TOKENS_FILE` (or the Kubernetes/cloud secret that backs it). Issue a replacement token for the legitimate consumer.
2. **Restart every replica.** The token registry loads at process start (`auth.py`) and is not reloaded. A replica that was not restarted still accepts the old token. Confirm the old token returns 401 on every replica: call `/v1/outbox/stats` through each pod or endpoint.
   - **OIDC subjects.** If the consumer authenticates with a JWT through `ALES_OIDC_CONFIG`, removing a static token does nothing to it. The verifier has no revocation list, so the token stays valid until its `exp`. Stop issuance at the identity provider, record the token lifetime as the exposure window, and restart replicas if the static JWKS itself must change (`docs/operations.md` section 2b).
3. **Scope the damage by role.** The token's subject is recorded as `actor` in every audit record it caused.
   - `read`: review `decision.authorize` records for that actor. Check which principals and objects it queried.
   - `ingest`: review `source.register` and `derivation.register` for that actor. Check `issuer_key_id` and `signed` in `detail`. Unsigned registrations (`signed: false`) are only possible with signatures off.
   - `revoke`: review `revocation.accept` for that actor. Check for revocations it submitted that you did not expect (these are a denial-of-service risk). Recover by submitting corrective revocations only if the source is restored; the runtime does not provide an un-revoke.
   - `admin`: review `admin.key.*` and `admin.audit.verify` for that actor. Re-check the key registry (`GET /v1/admin/keys`) against your records.
4. **Check audit integrity.** `GET /v1/audit/verify` (admin, as a legitimate admin token). Its `first_bad_seq` should be null. A non-null value means the chain was altered; preserve the database and escalate. Anchor the current head (`ales_core.audit.head`) to external storage.
5. **Note the gap.** The runtime does not record the token used on each request, only the subject. If two tokens share a subject, you cannot tell them apart from the audit log. Give each token its own subject.

## Runbook 4: Control-plane outage

Symptoms: `/v1/authorize`, `/v1/revocations` or `/v1/snapshot` fail or time out; `/v1/readyz` returns 503.

1. **Check which part is down.** `/v1/readyz` returns `database: unavailable` or `migrations: behind`. A `behind` result after a deploy is a migration issue (`docs/upgrades.md`), not an outage of the database.
2. **Know what the data plane does, per fail mode.** The client's configured fail mode decides:
   - `ENFORCE` (production default per SPEC): a client that cannot reach the control plane cannot get a decision and must not serve protected context. This is the strongest mode; availability suffers.
   - `BOUNDED_OFFLINE`: the client may serve reads only while it holds a verified, unexpired signed snapshot whose `revocation_epoch` matches the decision's. Protected reads are denied after the lease expires. `ALES_SNAPSHOT_LEASE` defaults to 60 s on the server, and the SDK `offline_lease_seconds` defaults to 60 s.
   - `WARN` and `OBSERVE`: no protection. Reads continue and exposure is unbounded by the runtime (guarantees G4). Do not use these modes for protected data during an outage.
3. **Exposure window.** In `BOUNDED_OFFLINE`, the window for a revocation is the lease plus the time before the revocation was accepted. **A revocation can be accepted only when the control plane and its database are up.** If the outage prevents the revocation itself, exposure runs from the moment the control plane recovers and accepts it. Record the outage start, the revocation acceptance time and the lease in the incident record.
4. **Do not bypass.** Do not switch clients to `OBSERVE` or `WARN` to keep traffic moving. That turns a bounded window into an unbounded one.
5. **Recover.** Restore the database (see `docs/operations.md` section 8 for the restore hazard). Re-apply any revocations accepted after the restore point. Verify `/v1/readyz` returns 200, then `/v1/snapshot/public_key` shows `ephemeral: false`. Clients obtain new signed snapshots from `/v1/snapshot`; how often a given SDK refreshes is not verified here.
6. **Check dead letters and purge.** After recovery, `GET /v1/outbox/stats` (dead count and handler mode). Outage can strand pending purge rows. Confirm they drain.

## Contacts and evidence to keep

Record for every incident: the revocation event ids, the audit `seq` range checked, the outbox stats snapshot, the lineage output, the trace ids, and the exact times of revocation acceptance, first denial and last ALLOW. Keep copies outside the database. The database may be the thing under investigation.
