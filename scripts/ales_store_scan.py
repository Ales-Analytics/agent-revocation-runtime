"""Operator store scan: find ALES-managed Redis entries that need purge reconciliation.

Scans a Redis prefix for ``__ales_idx__<context_id>`` reverse-index keys AND for data records
(``{"value", "context_id", "version"}``) written by ``GuardedCache``, collects the context ids and posts them
to ``POST /v1/outbox/reconcile``. A data key whose reverse index is missing (crash between the two writes)
is exactly the case purge cannot find on its own; its context_id still comes from the data record.

Usage:
    python scripts/ales_store_scan.py --redis redis://localhost:6379/0 --prefix ales: \
        --server http://localhost:8787 --token $ALES_ADMIN_TOKEN [--store-kind cache]

Exit code 0 = clean, 2 = tombstoned or untracked entries found. Read-only against Redis. Never prints values.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from collections.abc import Iterable

IDX = "__ales_idx__"


def collect_ids(redis_client, prefix: str) -> tuple[set[str], list[str]]:
    """Return (context_ids, data_keys_without_index) for entries under ``prefix``."""
    ids: set[str] = set()
    data_ids: dict[str, str] = {}
    indexed: set[str] = set()
    for raw in redis_client.scan_iter(match=prefix + "*", count=500):
        key = raw.decode() if isinstance(raw, bytes) else raw
        if key.startswith(prefix + IDX):
            context_id = key[len(prefix + IDX) :]
            ids.add(context_id)
            indexed.add(context_id)
            continue
        val = redis_client.get(key)
        if val is None:
            continue
        try:
            record = json.loads(val)
            context_id = record["context_id"]
        except (ValueError, KeyError, TypeError):
            continue
        if isinstance(context_id, str):
            ids.add(context_id)
            data_ids[context_id] = key
    return ids, sorted(k for c, k in data_ids.items() if c not in indexed)


def reconcile(server: str, token: str, store_kind: str, ids: Iterable[str]) -> dict:
    request = urllib.request.Request(
        server.rstrip("/") + "/v1/outbox/reconcile",
        data=json.dumps({"store_kind": store_kind, "known_ids": sorted(ids)}).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--redis", required=True)
    ap.add_argument("--prefix", default="")
    ap.add_argument("--server", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--store-kind", default="cache")
    a = ap.parse_args(argv)
    import redis

    client = redis.Redis.from_url(a.redis)
    ids, orphans = collect_ids(client, a.prefix)
    result = reconcile(a.server, a.token, a.store_kind, ids)
    print(
        json.dumps(
            {
                "scanned": result["scanned"],
                "tombstoned": result["tombstoned"],
                "untracked": result["untracked"],
                "data_keys_missing_index": orphans,
            },
            indent=2,
        )
    )
    return 2 if (result["tombstoned"] or result["untracked"]) else 0


if __name__ == "__main__":
    sys.exit(main())
