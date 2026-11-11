"""The eight RevocationBench scenario families.

Each scenario builds its own isolated control plane, performs legitimate control reads, revokes, then
attempts reads that must fail. An *escape* is a read that returned usable content for an object whose
ancestor was revoked (or that belongs to another tenant).
"""

from __future__ import annotations

from collections.abc import Callable

from ales_adapters.redis_cache import DictRedis, GuardedCache
from ales_sdk import AlesHTTPError, DecisionCache, FailMode

from .harness import RAG, BenchEnv, FakeClock, ScenarioResult

U42 = {"type": "user", "id": "user-42"}
U7 = {"type": "user", "id": "user-7"}
AGENT_A = {"type": "agent", "id": "agent-a"}
AGENT_B = {"type": "agent", "id": "agent-b"}


def _label(env_obj: dict) -> str:
    return env_obj["kind"]


# --------------------------------------------------------------------------------------------
def acl_revocation() -> ScenarioResult:
    with BenchEnv() as env:
        a = env.build_lineage("alpha", principal_scope=["user-42"])
        b = env.build_lineage("beta", principal_scope=["user-7"])

        for o in a.everything:
            env.read_legit(o["context_id"], U42)
        for o in b.everything:
            env.read_legit(o["context_id"], U7)
        out = env.read(a.chunk["context_id"], U7)  # unauthorized principal, not a revocation matter
        env.check(
            "user-7 cannot read user-42's chunk pre-revocation",
            not out.allowed and "PRINCIPAL_NOT_IN_SCOPE" in out.reasons,
        )

        env.revoke(a.source, "acl_changed")

        for o in a.everything:
            out = env.read_revoked(o["context_id"], U42)
            env.check(
                f"user-42 denied on {_label(o)}",
                not out.allowed and "ANCESTOR_ACL_REVOKED" in out.reasons,
                f"{out.decision} {out.reasons}",
            )
        for o in b.everything:  # control: unrelated lineage untouched
            env.read_legit(o["context_id"], U7)
        return env.finish("acl_revocation", revoked_objects=len(a.everything))


def source_deletion() -> ScenarioResult:
    with BenchEnv() as env:
        a = env.build_lineage("doomed")
        ctrl = env.build_lineage("survivor")
        for o in a.everything:
            env.read_legit(o["context_id"], U42)

        env.revoke(a.source, "deleted")

        lin = env.client.lineage(a.source["context_id"])
        env.check(
            "all descendants tombstoned in graph",
            len(lin["descendants"]) == len(a.descendants)
            and all(d["tombstoned"] for d in lin["descendants"]),
            f"{[d['tombstoned'] for d in lin['descendants']]}",
        )
        for o in a.everything:
            out = env.read_revoked(o["context_id"], U42)
            env.check(
                f"denied on {_label(o)}",
                not out.allowed and "ANCESTOR_DELETED" in out.reasons,
                f"{out.decision} {out.reasons}",
            )
        for o in ctrl.everything:
            env.read_legit(o["context_id"], U42)
        return env.finish("source_deletion", tombstoned=len(lin["descendants"]))


def version_supersession() -> ScenarioResult:
    with BenchEnv() as env:
        v1 = env.build_lineage("policy")
        for o in v1.everything:
            env.read_legit(o["context_id"], U42)

        # New version of the same source (same context_id, version "2", new content).
        v2 = env.source(
            "policy",
            object_id=v1.source["object_id"],
            object_version="2",
            context_id=v1.source["context_id"],
            content="policy: revised body",
        )
        env.revoke(v1.source, "version_superseded", version="1")

        decisions = {}
        for o in v1.descendants:
            out = env.read_revoked(o["context_id"], U42)
            decisions[_label(o)] = out.decision
            env.check(
                f"old {_label(o)} DENY or REFRESH",
                out.decision in ("DENY", "REFRESH") and "ANCESTOR_SUPERSEDED" in out.reasons,
                f"{out.decision} {out.reasons}",
            )
        old_src = env.read_revoked(v1.source["context_id"], U42, version="1")
        env.check("old source version not usable", old_src.decision in ("DENY", "REFRESH"), old_src.decision)

        # Reprocess from v2: the new derivatives must authorize ALLOW.
        env.read_legit(v2["context_id"], U42)
        chunk2 = env.derive("chunk", [v2], "policy/chunk-v2")
        summ2 = env.derive("summary", [chunk2], "policy/summary-v2")
        for o in (chunk2, summ2):
            out = env.read_legit(o["context_id"], U42)
            env.check(f"reprocessed {_label(o)} ALLOW", out.allowed, out.decision)
        return env.finish("version_supersession", old_decisions=decisions)


def poisoned_source() -> ScenarioResult:
    with BenchEnv() as env:
        a = env.build_lineage("poisoned")
        ctrl = env.build_lineage("clean")
        for o in a.everything:
            env.read_legit(o["context_id"], U42)

        env.revoke(a.source, "poisoned")

        for o in a.everything:
            out = env.read_revoked(o["context_id"], U42)
            env.check(
                f"{_label(o)} is QUARANTINE (not ALLOW)",
                out.decision == "QUARANTINE" and "ANCESTOR_QUARANTINED" in out.reasons,
                f"{out.decision} {out.reasons}",
            )
        for o in ctrl.everything:
            env.read_legit(o["context_id"], U42)
        return env.finish("poisoned_source")


class _StickyRedis(DictRedis):
    """A redis whose purge never lands: the entry stays physically present after the block."""

    def delete(self, *keys: str) -> int:
        return 0


def cache_replay() -> ScenarioResult:
    with BenchEnv() as env:
        src = env.source("cached-doc")
        other = env.source("other-doc")
        redis = _StickyRedis()
        cache = GuardedCache(env.client, U42, RAG, redis, prefix="rb:")
        cache.put("q-revoked", {"answer": "revoked-secret"}, [src])
        cache.put("q-ok", {"answer": "fine"}, [other])

        for key, expect in (("q-revoked", {"answer": "revoked-secret"}), ("q-ok", {"answer": "fine"})):
            value, _ = cache.get(key)
            env.record_legit(value is not None)
            env.check(f"pre-revocation get({key}) served", value == expect)

        env.revoke(src, "acl_changed")

        env.check("entry still physically present before replay", "rb:q-revoked" in redis.data)
        for i in range(5):  # replay: repeated gets must never resurrect the value
            value, blocked = cache.get("q-revoked")
            env.record_revoked(value is not None)
            env.check(f"replay {i + 1} returns None", value is None)
            if i == 0:
                env.check(
                    "first replay carries ANCESTOR_ACL_REVOKED",
                    bool(blocked) and "ANCESTOR_ACL_REVOKED" in blocked[0].reasons,
                    str([b.reasons for b in blocked]),
                )
            env.check(f"replay {i + 1} reports blocked", bool(blocked))
        physically_held = "rb:q-revoked" in redis.data
        env.check("block did not depend on physical purge", physically_held)

        value, _ = cache.get("q-ok")
        env.record_legit(value is not None)
        env.check("unrelated cache entry unaffected", value == {"answer": "fine"})
        return env.finish("cache_replay", physically_present_after_block=physically_held)


def agent_handoff() -> ScenarioResult:
    with BenchEnv() as env:
        src = env.source("handoff-src")
        summary = env.derive("summary", [src], "agent-a/summary")
        handoff = env.derive("artifact", [summary], "handoff:agent-a->agent-b")
        b_memory = env.derive("memory", [handoff], "agent-b/memory")
        ctrl_src = env.source("handoff-ctrl")
        ctrl_summary = env.derive("summary", [ctrl_src], "agent-a/ctrl-summary")
        ctrl_handoff = env.derive("artifact", [ctrl_summary], "handoff-ctrl")

        chain = [summary, handoff, b_memory]
        for p in (AGENT_A, AGENT_B):
            for o in chain + [ctrl_handoff]:
                env.read_legit(o["context_id"], p, agent_id=p["id"])

        env.revoke(src, "deleted")

        for p in (AGENT_A, AGENT_B):
            for o in chain:
                out = env.read_revoked(o["context_id"], p, agent_id=p["id"])
                env.check(
                    f"{p['id']} denied on {_label(o)}",
                    not out.allowed and "ANCESTOR_DELETED" in out.reasons,
                    f"{out.decision} {out.reasons}",
                )
        for p in (AGENT_A, AGENT_B):
            env.read_legit(ctrl_handoff["context_id"], p, agent_id=p["id"])
        return env.finish("agent_handoff", hops=3)


def multi_tenant_collision() -> ScenarioResult:
    with BenchEnv(tenant="tenant-a") as env:
        ca = env.client
        cb = env.client_for("tenant-b")
        shared = "shared/handbook.md"
        la = env.build_lineage("handbook", client=ca, object_id=shared)
        lb = env.build_lineage("handbook", client=cb, object_id=shared)  # same object_id string AND bytes
        env.check(
            "same object_id in both tenants", la.source["object_id"] == lb.source["object_id"] == shared
        )
        env.check("distinct context_ids", la.source["context_id"] != lb.source["context_id"])

        # A tenant cannot claim another tenant's context_id.
        hijack = dict(lb.source, context_id=la.source["context_id"])
        try:
            cb.register_source(hijack)
            env.check("context_id collision rejected", False, "registered")
        except AlesHTTPError as e:
            env.check("context_id collision rejected", e.status_code == 409, str(e.status_code))

        for o in la.everything:
            env.read_legit(o["context_id"], U42, client=ca)
        for o in lb.everything:
            env.read_legit(o["context_id"], U42, client=cb)

        # Cross-tenant revocation attempt: tenant-b names tenant-a's source; must not touch tenant-a.
        env.revoke(la.source, "deleted", client=cb, track_latency=False)
        for o in la.everything:
            env.read_legit(o["context_id"], U42, client=ca)

        env.revoke(la.source, "acl_changed", client=ca)

        for o in la.everything:
            out = env.read_revoked(o["context_id"], U42, client=ca)
            env.check(
                f"tenant-a denied on {_label(o)}",
                not out.allowed and "ANCESTOR_ACL_REVOKED" in out.reasons,
                f"{out.decision} {out.reasons}",
            )
        for o in lb.everything:
            out = env.read_legit(o["context_id"], U42, client=cb)
            env.check(f"tenant-b still ALLOW on {_label(o)}", out.allowed, out.decision)

        allowed_reasons = {"TENANT_MISMATCH", "OBJECT_UNKNOWN"}
        for o in la.descendants:  # tenant-b principal probing tenant-a ids
            out = env.read_revoked(o["context_id"], U42, client=cb)
            env.check(
                f"cross-tenant (b->a) {_label(o)} denied",
                not out.allowed and bool(set(out.reasons) & allowed_reasons),
                f"{out.decision} {out.reasons}",
            )
        for o in lb.descendants:  # and the reverse
            out = env.read_revoked(o["context_id"], U42, client=ca)
            env.check(
                f"cross-tenant (a->b) {_label(o)} denied",
                not out.allowed and bool(set(out.reasons) & allowed_reasons),
                f"{out.decision} {out.reasons}",
            )
        return env.finish("multi_tenant_collision", shared_object_id=shared)


def service_outage() -> ScenarioResult:
    clock = FakeClock()
    lease = 60.0
    with BenchEnv(tenant="outage") as env:
        admin = env.client  # control-plane writer; its link never goes down
        reader = env.client_for(
            "outage",
            name="reader",
            fail_mode=FailMode.BOUNDED_OFFLINE,
            offline_lease_seconds=lease,
            cache=DecisionCache(max_ttl=300.0, clock=clock),
            clock=clock,
        )
        target = env.build_lineage("outage", client=admin)
        ctrl = env.build_lineage("outage-ctrl", client=admin)
        link = env.transports["reader"]

        # t=0: online; the reader populates its decision cache for chunk and summary only.
        for o in (target.chunk, target.summary):
            env.read_legit(o["context_id"], U42, client=reader)

        # Control plane becomes unreachable for the reader.
        link.available = False
        clock.advance(10)
        out = env.read_legit(target.chunk["context_id"], U42, client=reader)
        last = env.authorize_log[-1]
        env.check(
            "within lease: cached ALLOW served",
            out.allowed and last.from_cache,
            f"{out.decision} cache={last.from_cache}",
        )
        out = env.read(target.memory["context_id"], U42, client=reader)  # never seen before the outage
        env.check(
            "within lease: uncached object fails closed",
            not out.allowed and "POLICY_SNAPSHOT_STALE" in out.reasons,
            f"{out.decision} {out.reasons}",
        )

        # Revocation happens while the reader is partitioned: it cannot know until the lease ends.
        env.revoke(target.source, "deleted", client=admin, track_latency=False)
        clock.advance(10)
        out = env.read(target.chunk["context_id"], U42, client=reader)
        exposure = out.allowed
        env.bounded_exposure += 1 if exposure else 0
        env.check(
            "within lease: revocation not yet visible (documented bounded window)",
            exposure,
            "served from cache inside the published lease",
        )

        # Lease expires: protected reads must be denied even though the cache still holds ALLOW.
        clock.advance(lease)
        for o in (target.chunk, target.summary):
            out = env.read_revoked(o["context_id"], U42, client=reader)
            env.check(
                f"after lease: {_label(o)} denied (fail closed)",
                not out.allowed and out.decision == "UNKNOWN",
                f"{out.decision} {out.reasons}",
            )

        # Link restored: the revocation is now visible and denies for the right reason.
        link.available = True
        out = env.read_revoked(target.chunk["context_id"], U42, client=reader)
        env.check(
            "after recovery: revocation enforced",
            not out.allowed and "ANCESTOR_DELETED" in out.reasons,
            f"{out.decision} {out.reasons}",
        )
        out = env.read_legit(ctrl.chunk["context_id"], U42, client=reader)
        env.check("after recovery: unrelated object allowed", out.allowed, out.decision)
        return env.finish(
            "service_outage",
            lease_seconds=lease,
            bounded_exposure_served=exposure,
            simulated_exposure_window_seconds=20.0,
            note="exposure counted separately from escapes: it is the published BOUNDED_OFFLINE window",
        )


SCENARIOS: dict[str, Callable[[], ScenarioResult]] = {
    "acl_revocation": acl_revocation,
    "source_deletion": source_deletion,
    "version_supersession": version_supersession,
    "poisoned_source": poisoned_source,
    "cache_replay": cache_replay,
    "agent_handoff": agent_handoff,
    "multi_tenant_collision": multi_tenant_collision,
    "service_outage": service_outage,
}
