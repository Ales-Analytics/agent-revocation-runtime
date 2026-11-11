from ales_adapters.redis_cache import DictRedis, GuardedCache
from conftest import PRINCIPAL


def test_put_get_then_revoke_returns_none_and_deletes(client, src, server):
    r = DictRedis()
    cache = GuardedCache(client, PRINCIPAL, "support", r, prefix="ales:")
    env = cache.put("q1", {"answer": 42}, [src])
    assert env["kind"] == "cache" and env["parent_refs"][0]["context_id"] == src["context_id"]
    assert env["context_id"] in server.envelopes
    assert "ales:q1" in r.data

    assert cache.get("q1") == ({"answer": 42}, [])

    client.submit_revocation({"source_id": src["context_id"], "reason": "acl_changed"})
    value, blocked = cache.get("q1")
    assert value is None
    assert blocked and blocked[0].decision == "DENY" and "ANCESTOR_ACL_REVOKED" in blocked[0].reasons
    assert "ales:q1" not in r.data
    assert cache.get("q1") == (None, [])  # now a plain miss


def test_delete_failure_is_swallowed(client, src):
    class Broken(DictRedis):
        def delete(self, *keys):
            raise RuntimeError("redis down")

    cache = GuardedCache(client, PRINCIPAL, "support", Broken())
    cache.put("k", "v", [src])
    client.submit_revocation({"source_id": src["context_id"], "reason": "deleted"})
    value, blocked = cache.get("k")
    assert value is None and blocked


def test_bytes_values_supported(client, src):
    r = DictRedis()
    cache = GuardedCache(client, PRINCIPAL, "support", r)
    cache.put("k", [1, 2], [src])
    r.data["k"] = r.data["k"].encode()
    assert cache.get("k")[0] == [1, 2]
