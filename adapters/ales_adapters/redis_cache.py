"""Guarded cache over any redis-like object (``get``/``set``/``delete``).

Entries are registered as ``cache``-kind derivatives of the envelopes the value was built from and
stored as JSON ``{value, context_id, version}``. ``get`` authorizes the entry before returning it; a
blocked entry yields ``(None, blocked)`` and is deleted best-effort so stale data does not linger.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterable, Mapping
from typing import Any

from ales_sdk.client import InvariantClient
from ales_sdk.envelope import new_derivative
from ales_sdk.wrappers import Blocked, guard_cache_get


class DictRedis:
    """Minimal in-process stand-in for a redis client."""

    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self.data.get(key)

    def set(self, key: str, value: str, *args: Any, **kw: Any) -> bool:
        self.data[key] = value
        return True

    def delete(self, *keys: str) -> int:
        return sum(1 for k in keys if self.data.pop(k, None) is not None)


class GuardedCache:
    def __init__(
        self,
        client: InvariantClient,
        principal: Mapping[str, str],
        purpose: str,
        redis_like: Any,
        prefix: str = "",
    ) -> None:
        self.client = client
        self.principal = principal
        self.purpose = purpose
        self.redis = redis_like
        self.prefix = prefix

    def put(self, key: str, value: Any, parent_envelopes: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
        payload = json.dumps(value, sort_keys=True)
        env = new_derivative(
            "cache",
            parent_envelopes,
            self.client.tenant_id,
            f"cache:{key}",
            payload,
            source_system="redis-cache",
        )
        self.client.register_derivation(env)
        record = {"value": value, "context_id": env["context_id"], "version": env["object_version"]}
        self.redis.set(self.prefix + key, json.dumps(record))
        return env

    def get(self, key: str, *, session_id: str | None = None) -> tuple[Any | None, list[Blocked]]:
        """Return ``(value, [])`` on an authorized hit, ``(None, [])`` on a miss, ``(None, blocked)`` if denied."""
        raw = self.redis.get(self.prefix + key)
        if raw is None:
            return None, []
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        record = json.loads(raw)
        value, blocked = guard_cache_get(
            self.client,
            self.principal,
            self.purpose,
            record,
            [record["context_id"]],
            version_getter=lambda _c: record.get("version"),
            session_id=session_id,
        )
        if value is None:
            with contextlib.suppress(Exception):  # best-effort cleanup must never mask the block
                self.redis.delete(self.prefix + key)
            return None, blocked
        return record["value"], []
