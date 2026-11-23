"""Check a cached answer after deleting its source."""

from ales_adapters.redis_cache import DictRedis, GuardedCache

from examples.local import PURPOSE, READER, client, register_handbook


def main() -> None:
    with client() as api:
        handbook = register_handbook(api)
        cache = GuardedCache(api, READER, PURPOSE, DictRedis())
        cache.put("returns", "30 days", [handbook])
        before, blocked = cache.get("returns")
        assert before == "30 days" and not blocked
        print(f"Cached answer: {before}")

        api.submit_revocation({"source_id": handbook["context_id"], "reason": "deleted"})
        after, blocked = cache.get("returns")
        assert after is None and "ANCESTOR_DELETED" in blocked[0].reasons
        print("Cached answer withheld: ANCESTOR_DELETED")


if __name__ == "__main__":
    main()
