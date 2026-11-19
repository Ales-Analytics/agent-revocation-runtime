# Demo: revoke a RAG source

Revoking one document's access makes every derivative of that document unusable: its chunks, its summary, its memory entry and its cached answer. This happens at read time, through `authorize`, before any physical purge has run.

The demo runs in a few seconds. It needs no model, no API key and no network.

## The story

1. A restricted HR file, `hr-policy.txt`, is registered as a `source` envelope through `FilesystemSourceConnector.scan()`. Its `hr-policy.txt.acl.json` sidecar sets classification `restricted` and a principal scope of `user-42` and `recruiting-agent`.
2. The file is split on blank lines. Each paragraph is a `chunk` derivative of the source, indexed in a `GuardedVectorStore`. The embedding is a hash-based stand-in for a model.
3. An "agent" summarizes the chunks by truncation (no LLM). The summary is a `summary` derivative of the chunks. A `GuardedCache` holds the answer as a `cache` derivative of the summary. A `memory` derivative of the summary is registered for the employee-relations assistant.
4. Before any change, `user-42` reads all three: the search returns chunks, the cache returns the answer, and `authorize` on the memory returns `ALLOW`.
5. HR edits the sidecar to remove `user-42`. The connector's `watch_once()` sees a narrowed ACL and emits an `acl_changed` revocation. The server tombstones the source and every known descendant, and the tenant `revocation_epoch` increments.
6. The same three reads are denied with `ANCESTOR_ACL_REVOKED`. The cache entry still sits in the store until the blocked read deletes it. The memory's lineage shows the tombstoned source and its descendants.

The order matters. The deny comes from the lineage check at read time. The demo does not run a physical purge at all, and nothing in the read path depends on one.

## Run it

Prerequisites: Python 3.11 or newer, and the repository venv with the dev dependencies (`pip install -e ".[dev]"`).

From the repository root:

```bash
python examples/revoke-rag-source/demo.py
```

The default mode runs the control plane in-process on in-memory SQLite and talks to it through an httpx bridge to the FastAPI test client.

### Compose variant (live server)

```bash
# Start Postgres 16, Redis 7 and the control plane on port 8787
docker compose -f deploy/docker-compose.yml up -d --build

# Same flow, over HTTP
python examples/revoke-rag-source/demo.py --server http://localhost:8787

# Stop the stack (add -v to also remove the Postgres volume)
docker compose -f deploy/docker-compose.yml down
```

The demo itself only speaks HTTP to the server. Redis is not used by the demo: the cache is backed by an in-process dictionary that stands in for it.

### Tests

```bash
python -m pytest examples/tests -q
```

The test runs the same flow in-process and asserts that every checkpoint passes.

## What the output looks like

Each checkpoint prints one line, then a table, then a moral. The table below is from a real run; tenant IDs and context IDs vary between runs.

```
[1        ] register restricted source         PASS   1 registered, classification=restricted
[2        ] chunk and index derivatives        PASS   4 chunk derivatives
[3        ] summary, cache entry, memory       PASS   6 ancestors, source reachable=True
[4.search ] retrieval as user-42               PASS   4 served, 0 blocked, top='Parental leave: primary care'
[4.cache  ] cache read as user-42              PASS   value=hit, blocked=0
[4.memory ] memory authorize as user-42        PASS   ALLOW
[5        ] sidecar edit emits revocation      PASS   reasons=['acl_changed'], epoch=1
[6.search ] retrieval as user-42               PASS   0 served, 4 blocked, reasons=['ANCESTOR_ACL_REVOKED']
[6.cache  ] cache read as user-42              PASS   value=None, reasons=['ANCESTOR_ACL_REVOKED']
[6.memory ] memory authorize as user-42        PASS   DENY, reasons=['ANCESTOR_ACL_REVOKED']
  lineage of memory/employee-relations (tombstones):
    ancestor   chunk    ...      tombstoned=True
    ...
[6.lineage] source tombstoned in lineage       PASS   tombstoned=True

step       expected    got    result   (one row per checkpoint)
...

ALL PASS: 11/11 checkpoints
```

Exit codes:

- `0`: every checkpoint passed.
- `1`: at least one checkpoint failed. A failing row names what was expected and what was returned.
- `2`: server mode could not reach the control plane.

## What this demo does not show

- It does not recall anything a user already read before the revocation.
- It does not cover read paths that are not wrapped by `GuardedVectorStore`, `GuardedCache` or an explicit `authorize` call.
- It does not run the physical purge or dispatch the invalidation outbox.
- It does not test control-plane outages or fail modes.
