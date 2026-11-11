# Demo: revoke a RAG source

A ten-minute walkthrough. It shows that revoking one document's access stops every derivative of that document from being used, including cached and remembered copies, before any asynchronous purge has finished.

## The story

1. An HR policy document, `hr-policy-2026.pdf`, is indexed for a retrieval-augmented assistant. It is registered as a `source` envelope with classification `confidential` and a principal scope limited to HR.
2. The document is split into chunks. Each chunk is a `chunk` derivative whose `parent_refs` point at the source version.
3. An agent summarizes the chunks into a `summary` and writes a `memory` entry for the employee-relations assistant. Both record the chunks as parents.
4. The summary is placed in a Redis cache for fast answers. The cache entry is a `cache` derivative of the summary.
5. HR revokes access to the document. The revocation event is signed, durably recorded, and accepted. The graph marks every known descendant as unusable, and the tenant `revocation_epoch` increments.
6. The Redis purge and the vector index cleanup are queued as asynchronous invalidation events. In the demo, the purge is deliberately delayed so that the gap is visible.
7. A user asks a question that the cache, the memory and the retriever would previously have answered. Each instrumented read path calls authorize, and each returns `DENY` with reason `ANCESTOR_ACL_REVOKED`. The stale cache entry is not returned, even though it still physically exists.

The point is the order of events: the synchronous deny happens first, and the cleanup follows. Purge is not what protects the data.

## Prerequisites

- Docker with Compose v2.
- Python 3.11 or newer.
- A clone of this repository.

## Steps

From the repository root:

```bash
# 1. Start Postgres 16, Redis 7 and the control plane
docker compose -f deploy/docker-compose.yml up -d --build

# 2. Install the SDK and CLI from this checkout
pip install -e .

# 3. Create a local signing key and configuration (keys stay in a local key file for the demo only)
ales init --local

# 4. Run the scenario
ales demo --scenario revoke-rag-source
```

Expected run time is about ten minutes, most of which is the image build on the first run.

To stop the stack afterwards:

```bash
docker compose -f deploy/docker-compose.yml down
```

Add `-v` to remove the Postgres volume as well.

## What PASS looks like

The scenario prints one line per step and ends with a summary. The exact formatting may change between releases, but the structure is:

```
[1] register source    hr-policy-2026.pdf v1          OK
[2] derive chunks      <n> chunks                     OK
[3] derive summary     summary-hr-benefits            OK
[4] derive memory      memory/employee-relations      OK
[5] cache entry        cache:benefits-faq             OK
[6] revoke source      hr-policy-2026.pdf ACL         ACCEPTED  epoch=<k>
[7] purge              redis:cache:benefits-faq       PENDING   (async, delayed for demo)
[8] authorize chunk    chunk/…                        DENY      ANCESTOR_ACL_REVOKED
[8] authorize summary  summary-hr-benefits            DENY      ANCESTOR_ACL_REVOKED
[8] authorize memory   memory/employee-relations     DENY      ANCESTOR_ACL_REVOKED
[8] authorize cache    cache:benefits-faq             DENY      ANCESTOR_ACL_REVOKED

PASS  revoke-rag-source
  descendants checked: <n>
  served after revocation: 0
  denied with ANCESTOR_ACL_REVOKED: <n>
  physical purge completed after deny: yes
```

The check that matters is `served after revocation: 0`. If that number is not zero, the scenario prints `FAIL` and exits non-zero.

Notes on reading the output:

- Step 7 shows purge as `PENDING` on purpose. The deny in step 8 does not depend on it.
- This is the shape of the output, not a captured transcript. Angle-bracket fields are filled in by the actual run, and the exact wording may change between releases.
- `FAIL` at any step means an instrumented path returned content after the revocation was accepted. That is a bug to report, not an expected outcome.

## What this demo does not show

- It does not recall anything a user already read before step 6.
- It does not cover any read path that the demo does not call through authorize. The demo's paths are the ones instrumented in `examples/`, not the whole system.
- It does not test a control-plane outage. For fail-mode behaviour, see `docs/guarantees.md`.
