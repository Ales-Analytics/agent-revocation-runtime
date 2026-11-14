# Lifecycle value layer

Revocation answers "may this still be used?". The lifecycle layer answers the questions around it: *what will
this revocation touch*, *why was that request denied*, *how do I get fresh derivatives after a source changes*
and *which running sessions already saw it*. Everything here is read-mostly, tenant-scoped, audited where it
writes, and honest about what ALES cannot see. Schema: migration `0006`.

| Capability | Routes | Role |
|---|---|---|
| Impact preview | `GET /v1/impact/{context_id}?version=` | read |
| Decision explanation | `GET /v1/decisions/{trace_id}?format=json\|text` | read |
| Transformation registry | `POST /v1/transformations`, `GET /v1/transformations`, `POST /v1/derivations/{id}/{version}/transformation` | admin / read / ingest |
| Rebuilds | `POST /v1/rebuilds/{id}/{version}`, `GET /v1/rebuilds`, `POST /v1/rebuilds/run` | admin / read / admin |
| Durable sessions | `POST /v1/sessions/{id}/exposures`, `GET /v1/sessions/{id}`, `POST /v1/sessions/{id}/reset` | read |

Another tenant's object, trace, session or job is always a `404`, never a `403`, so none of these routes
confirms that something exists elsewhere.

## 1. Impact preview

`GET /v1/impact/{context_id}` (optionally `?version=`; default every version) shows what a revocation of that
object would touch, **before** you send it. It changes nothing except one `impact.preview` audit record.

```json
{
  "source":      {"context_id": "...", "versions": [{"object_version": "1", "kind": "source", "object_id": "...", "source_system": "...", "classification": "confidential"}]},
  "descendants": [{"context_id": "...", "object_version": "1", "kind": "chunk"}],
  "stores":      ["chunk", "source", "summary"],
  "exposed_sessions": {"status": "recorded", "count": 2, "ids": ["run-1", "run-7"], "truncated": false},
  "pending_cleanup":  {"count": 3, "by_state": {"pending": 3}, "by_store_kind": {"chunk": 1, "source": 1, "summary": 1}},
  "uninstrumented_note": "ALES knows only what was registered with it ...",
  "rebuildable": [{"context_id": "...", "object_version": "1", "transformation_id": "upper", "transformation_version": "1"}],
  "revocation_epoch": 4
}
```

* `stores` are the object kinds present in the lineage; they are the purge-routing keys, so they tell you which
  purge handlers a revocation will wake.
* `exposed_sessions.status` is `recorded` (matches found), `none` (the tenant reports sessions and none touched
  this lineage) or `unknown` (the tenant has never reported a session: ALES does **not** claim zero).
  Up to 100 ids are listed; `count` is exact.
* `pending_cleanup` counts outbox rows for the lineage that are not `done` (pending, leased or dead).
* `uninstrumented_note` is a fixed string. Copies of the content that ALES was never told about (stores without
  a purge handler, caches, prompts, transcripts, exports) are outside this report and outside any revocation.
* `rebuildable` lists descendants whose registered transformation exists in the registry (section 3).

## 2. Decision explanation

Every authorize and release decision is audited with its `trace_id` (`decision.authorize` /
`release.authorize`). `GET /v1/decisions/{trace_id}` finds that record **inside the caller's tenant ledger**
and combines it with the live lineage graph:

* `decision`, `reasons`, per-object verdicts: from the audit record (what was actually decided).
* `dependency_paths`: for each non-ALLOW object, source-to-leaf chains `[{context_id, object_version, kind}]`.
  When revocations explain the verdict, chains start at the revoked ancestor(s) that were in effect, and matched
  the request scope, at decision time (`causes` names each with its reason and event id). When none does (scope,
  policy, workload denials), chains start at the roots of the lineage. At most 10 chains per object.
* `authority`: the `revocation_epoch` and `policy_version` the decision observed, the entitlement revision when
  one was involved, plus `current_revocation_epoch` so a reader sees whether the world moved on.
* `cleanup`: outbox rows (store kind, state, attempts, last error) for every object on those paths.

`?format=text` (or the `explanation` field of the JSON) renders the same facts for people:

```
Decision: DENY  (trace 5c1e..., 2026-11-14T10:03:11.482113Z)

Object: 9a0f...@1 -> DENY
  Dependent source: 41d2...@1 (revoked: deleted at 2026-11-14T10:02:58.000000Z)
  Reason: ANCESTOR_DELETED
  Dependency path: 41d2...@1 (source) -> 77be...@1 (chunk) -> 9a0f...@1 (summary)

Authority observed: revocation epoch 1 (now 1), policy p0
Cleanup: 41d2...@1 source=pending; 77be...@1 chunk=pending; 9a0f...@1 summary=pending
```

Limits: the verdict is the recorded one, but paths, causes and cleanup are read from the graph *now*. A
tombstone accepted after the decision with an earlier `effective_at` can appear as a cause, and cleanup states
move. The audit lookup filters on `detail.trace_id` inside one tenant; on a very large ledger add an expression
index (`CREATE INDEX CONCURRENTLY ON audit_log ((detail->>'trace_id')) WHERE action IN
('decision.authorize','release.authorize')` on Postgres), which the migration deliberately does not do for you.

## 3. Transformations and rebuilds

When a source is superseded, its chunks, embeddings and summaries are stale: they resolve `REFRESH` (or `DENY`
if no live successor exists). ALES does not regenerate content. It records which **registered transformation**
produced each derivative, plans what must be recomputed from the new inputs, and runs integrator-supplied
handlers.

**The rule: a rebuild is always a new derivation.** A rebuilt derivative is registered as a new object with a
new derivation record over the *new* parents. Old bytes are never re-attached to new parents, the old
derivative is never edited or revalidated, and it keeps resolving `REFRESH`/`DENY` forever. There is no code
path that reconnects. Authority is recomputed from the new parents and passes the ordinary "no wider than the
parents" check, so a rebuild cannot launder authority either.

1. **Register** (admin): `POST /v1/transformations` with `transformation_id`, `version`, `input_kinds`,
   `output_kind`, `implementation_ref` (an opaque label; ALES never fetches or runs it) and `idempotent`.
   Immutable per `(id, version)`; an identical re-registration is a no-op, a different one is `409`.
2. **Tag**: name the transformation when registering a derivative (core API
   `GraphStore.register_derivation(env, transformation=(id, ver))`, no envelope change) or afterwards with
   `POST /v1/derivations/{id}/{version}/transformation` (ingest; set-once, audited).
3. **Plan/enqueue** (admin): after a version is superseded, `POST /v1/rebuilds/{context_id}/{version}` plans the
   direct derivatives that carry a registered transformation and have no successor yet. Each step records its
   *current inputs* (every parent replaced by its latest successor). Idempotent; a previously failed step is
   reset to pending, so fixing a handler and re-posting retries it. `planned: 0` means no successor exists yet or
   nothing carries a transformation.
4. **Run**: the server worker runs a rebuild pass each tick (or `POST /v1/rebuilds/run` for one tenant, now).
   Jobs use the outbox lease pattern (`pending -> leased -> done | failed`, crash-reclaimable).
5. **Cascade**: completing a job registers the new derivative with `successor_of` = the old one, then plans the
   old derivative's own derivatives against it, so a chunk -> summary chain rebuilds level by level.

ALES ships **no handlers**. Integrators pass `create_app(rebuild_handlers={"upper": fn})`, where
`fn(inputs: Sequence[RebuildInput]) -> RebuildOutput`. `RebuildInput` carries ids, kind and digest of each
current input (never content); the handler reads input bytes from, and writes output bytes to, its own store
and returns the `sha256:` digest. A job whose transformation has no handler ends `failed` with
`no rebuild handler registered for transformation '<id>'`. Handler errors retry (5 s, 30 s, 3 attempts) only
for transformations declared `idempotent`; a non-idempotent one fails at once and is never retried after a
crashed lease, because the side effect may have happened.

Rebuilt derivatives are server-originated and **unsigned**; they do not pass the signature ingress. With
`ALES_REQUIRE_SIGNATURES=1` that gate applies to what clients post, not to these (see R52).

## 4. Durable sessions

The SDK's `SessionTaint` forgets everything when the process restarts. The server keeps a bounded copy:

* **Report** (opt-in): `InvariantClient(..., durable_sessions=True)` reports every `record()` and every handoff
  receiver to `POST /v1/sessions/{id}/exposures` (principal, optional workload, `(context_id, version)` pairs;
  `version: null` means any version). Reporting is best-effort on the hot path: a failure stays pending and is
  retried, and the local record remains what `enforce()` uses. `SessionTaint.report(client, session_id)` is the
  explicit, raising form.
* **Flag**: when a revocation that is already in effect lands, the engine marks every session (current
  generation, unexpired) exposed to the source or any descendant `needs_reset=true` and appends a
  `session.flag` audit record. A scoped revocation flags only sessions that exposed the object to a listed
  principal id.
* **Read**: `GET /v1/sessions/{id}` returns `generation`, `needs_reset`, `flag_reason`, `exposure_count`,
  `expires_at`. The impact preview uses the same store.
* **Reset**: `POST /v1/sessions/{id}/reset` (audited `session.reset`) bumps `generation` and clears
  `needs_reset`. Exposures of older generations stop counting, so a reset session is not flagged again for
  objects it no longer holds.

**What reset means is host-defined.** ALES records the generation and the flag; it does not reset anything. A
LangGraph host might drop the thread, a chat product might start a new conversation, a memory layer might
truncate. Information already shown to a model or a person cannot be recalled by any of this: reset limits
*future* use, it does not undo *past* disclosure.

**Retention is bounded.** Every row expires `ALES_SESSION_RETENTION` after its last report (default `7d`; `s`,
`m`, `h`, `d` suffixes or bare seconds; anything over 366 days or invalid refuses to start). Lapsed rows no
longer count anywhere and the worker deletes them (sweep at most once a minute). A revocation after expiry
flags nothing for the forgotten session. Exposure reports are not audited per call (volume); flags and resets
are. A report accepts at most 1000 exposures.

## Operating notes

* The worker (`ALES_OUTBOX_INTERVAL > 0`) runs purge dispatch, the rebuild pass and the session sweep. With the
  worker off (or in-memory SQLite) call `POST /v1/rebuilds/run` and rely on lazy expiry for sessions.
* All lifecycle tables are tenant-partitioned and written under the same per-tenant lock as the audit ledger.
* New audit actions: `impact.preview`, `transformation.register`, `derivation.tag_transformation`,
  `rebuild.enqueue`, `rebuild.complete`, `rebuild.failed`, `session.flag`, `session.reset`.
