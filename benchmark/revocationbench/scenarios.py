"""The eleven RevocationBench scenario families.

Each scenario builds its own isolated control plane, performs legitimate control reads, revokes, then
attempts reads that must fail. An *escape* is a read that returned usable content for an object whose
ancestor was revoked (or that belongs to another tenant).
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from ales_adapters.redis_cache import GuardedCache
from ales_core import outbox_stats
from ales_sdk import AlesHTTPError, DecisionCache, FailMode, new_source
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .harness import RAG, BenchEnv, FakeClock, ScenarioResult, ServerClock
from .metrics import percentile

U42 = {"type": "user", "id": "user-42"}
U7 = {"type": "user", "id": "user-7"}
AGENT_A = {"type": "agent", "id": "agent-a"}
AGENT_B = {"type": "agent", "id": "agent-b"}


def _label(env_obj: dict) -> str:
    return env_obj["kind"]


def acl_revocation() -> ScenarioResult:
    with BenchEnv() as env:
        a = env.build_lineage("alpha", principal_scope=["user-42"])
        b = env.build_lineage("beta", principal_scope=["user-7"])

        for o in a.everything:
            env.read_legit(o["context_id"], U42)
        for o in b.everything:
            env.read_legit(o["context_id"], U7)
        result = env.read(a.chunk["context_id"], U7)  # unauthorized principal, not a revocation matter
        env.check(
            "user-7 cannot read user-42's chunk pre-revocation",
            not result.allowed and "PRINCIPAL_NOT_IN_SCOPE" in result.reasons,
        )

        plant = env.enable_purge()
        for lin in (a, b):
            for o in lin.descendants:
                plant.place(o)

        env.revoke(a.source, "acl_changed")
        env.purge_now(a.descendants, controls=b.descendants)

        for o in a.everything:
            result = env.read_revoked(o["context_id"], U42)
            env.check(
                f"user-42 denied on {_label(o)}",
                not result.allowed and "ANCESTOR_ACL_REVOKED" in result.reasons,
                f"{result.decision} {result.reasons}",
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

        plant = env.enable_purge()
        for lin0 in (a, ctrl):
            for o in lin0.descendants:
                plant.place(o)

        env.revoke(a.source, "deleted")
        env.purge_now(a.descendants, controls=ctrl.descendants)

        lin = env.client.lineage(a.source["context_id"])
        env.check(
            "all descendants tombstoned in graph",
            len(lin["descendants"]) == len(a.descendants)
            and all(d["tombstoned"] for d in lin["descendants"]),
            f"{[d['tombstoned'] for d in lin['descendants']]}",
        )
        for o in a.everything:
            result = env.read_revoked(o["context_id"], U42)
            env.check(
                f"denied on {_label(o)}",
                not result.allowed and "ANCESTOR_DELETED" in result.reasons,
                f"{result.decision} {result.reasons}",
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
            result = env.read_revoked(o["context_id"], U42)
            decisions[_label(o)] = result.decision
            env.check(
                f"old {_label(o)} DENY or REFRESH",
                result.decision in ("DENY", "REFRESH") and "ANCESTOR_SUPERSEDED" in result.reasons,
                f"{result.decision} {result.reasons}",
            )
        old_src = env.read_revoked(v1.source["context_id"], U42, version="1")
        env.check("old source version not usable", old_src.decision in ("DENY", "REFRESH"), old_src.decision)

        # Reprocess from v2: the new derivatives must authorize ALLOW.
        env.read_legit(v2["context_id"], U42)
        chunk2 = env.derive("chunk", [v2], "policy/chunk-v2")
        summ2 = env.derive("summary", [chunk2], "policy/summary-v2")
        for o in (chunk2, summ2):
            result = env.read_legit(o["context_id"], U42)
            env.check(f"reprocessed {_label(o)} ALLOW", result.allowed, result.decision)
        return env.finish("version_supersession", old_decisions=decisions)


def poisoned_source() -> ScenarioResult:
    with BenchEnv() as env:
        a = env.build_lineage("poisoned")
        ctrl = env.build_lineage("clean")
        for o in a.everything:
            env.read_legit(o["context_id"], U42)

        env.revoke(a.source, "poisoned")

        for o in a.everything:
            result = env.read_revoked(o["context_id"], U42)
            env.check(
                f"{_label(o)} is QUARANTINE (not ALLOW)",
                result.decision == "QUARANTINE" and "ANCESTOR_QUARANTINED" in result.reasons,
                f"{result.decision} {result.reasons}",
            )
        for o in ctrl.everything:
            env.read_legit(o["context_id"], U42)
        return env.finish("poisoned_source")


def cache_replay() -> ScenarioResult:
    with BenchEnv() as env:
        src = env.source("cached-doc")
        other = env.source("other-doc")
        redis = env.make_redis(sticky=True)  # real Redis in the postgres profile, a dict stand-in in-process
        pfx = f"rb:{uuid.uuid4().hex[:8]}:"
        cache = GuardedCache(env.client, U42, RAG, redis, prefix=pfx)
        cache.put("q-revoked", {"answer": "revoked-secret"}, [src])
        cache.put("q-ok", {"answer": "fine"}, [other])

        for key, expect in (("q-revoked", {"answer": "revoked-secret"}), ("q-ok", {"answer": "fine"})):
            value, _ = cache.get(key)
            env.record_legit(value is not None)
            env.check(f"pre-revocation get({key}) served", value == expect)

        env.revoke(src, "acl_changed")

        env.check("entry still physically present before replay", redis.has(pfx + "q-revoked"))
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
        physically_held = redis.has(pfx + "q-revoked")
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
                result = env.read_revoked(o["context_id"], p, agent_id=p["id"])
                env.check(
                    f"{p['id']} denied on {_label(o)}",
                    not result.allowed and "ANCESTOR_DELETED" in result.reasons,
                    f"{result.decision} {result.reasons}",
                )
        for p in (AGENT_A, AGENT_B):
            env.read_legit(ctrl_handoff["context_id"], p, agent_id=p["id"])
        return env.finish("agent_handoff", hops=3)


def multi_tenant_collision() -> ScenarioResult:
    with BenchEnv(tenant="tenant-a", extra_tenants=["tenant-b"]) as env:
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
            env.check("context_id collision rejected", e.status_code in (403, 409), str(e.status_code))

        # Tenant binding: a tenant-b token naming tenant-a in the body is a 403, on every write/read path.
        spoof = env.raw("POST", "/v1/sources", tenant="tenant-b", json=dict(la.source))
        env.check("tenant-b token cannot register into tenant-a (403)", spoof.status_code == 403, spoof.text)
        spoof = env.raw(
            "POST",
            "/v1/revocations",
            tenant="tenant-b",
            json={"tenant_id": "tenant-a", "source_id": la.source["context_id"], "reason": "deleted"},
        )
        env.check("tenant-b token cannot revoke in tenant-a (403)", spoof.status_code == 403, spoof.text)
        spoof = env.raw(
            "POST",
            "/v1/authorize",
            tenant="tenant-b",
            json={
                "tenant_id": "tenant-a",
                "principal": U42,
                "purpose": RAG,
                "objects": [{"context_id": la.chunk["context_id"]}],
            },
        )
        env.check("tenant-b token cannot authorize in tenant-a (403)", spoof.status_code == 403, spoof.text)

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
            result = env.read_revoked(o["context_id"], U42, client=ca)
            env.check(
                f"tenant-a denied on {_label(o)}",
                not result.allowed and "ANCESTOR_ACL_REVOKED" in result.reasons,
                f"{result.decision} {result.reasons}",
            )
        for o in lb.everything:
            result = env.read_legit(o["context_id"], U42, client=cb)
            env.check(f"tenant-b still ALLOW on {_label(o)}", result.allowed, result.decision)

        allowed_reasons = {"TENANT_MISMATCH", "OBJECT_UNKNOWN"}
        for o in la.descendants:  # tenant-b principal probing tenant-a ids
            result = env.read_revoked(o["context_id"], U42, client=cb)
            env.check(
                f"cross-tenant (b->a) {_label(o)} denied",
                not result.allowed and bool(set(result.reasons) & allowed_reasons),
                f"{result.decision} {result.reasons}",
            )
        for o in lb.descendants:  # and the reverse
            result = env.read_revoked(o["context_id"], U42, client=ca)
            env.check(
                f"cross-tenant (a->b) {_label(o)} denied",
                not result.allowed and bool(set(result.reasons) & allowed_reasons),
                f"{result.decision} {result.reasons}",
            )
        return env.finish("multi_tenant_collision", shared_object_id=shared)


def service_outage() -> ScenarioResult:
    clock = FakeClock()
    lease = 60.0
    # Real signed snapshot protocol: the server signs with a fixed Ed25519 key and the reader verifies
    # it with the matching public key (the harness hands that key to every client it builds).
    with BenchEnv(tenant="outage", snapshot_key=Ed25519PrivateKey.generate()) as env:
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
        result = env.read_legit(target.chunk["context_id"], U42, client=reader)
        last = env.authorize_log[-1]
        env.check(
            "within lease: cached ALLOW served",
            result.allowed and last.from_cache,
            f"{result.decision} cache={last.from_cache}",
        )
        result = env.read(target.memory["context_id"], U42, client=reader)  # never seen before the outage
        env.check(
            "within lease: uncached object fails closed",
            not result.allowed and "POLICY_SNAPSHOT_STALE" in result.reasons,
            f"{result.decision} {result.reasons}",
        )

        # Revocation happens while the reader is partitioned: it cannot know until the lease ends.
        env.revoke(target.source, "deleted", client=admin, track_latency=False)
        clock.advance(10)
        result = env.read(target.chunk["context_id"], U42, client=reader)
        exposure = result.allowed
        env.bounded_exposure += 1 if exposure else 0
        env.check(
            "within lease: revocation not yet visible (documented bounded window)",
            exposure,
            "served from cache inside the published lease",
        )

        # Lease expires: protected reads must be denied even though the cache still holds ALLOW.
        clock.advance(lease)
        for o in (target.chunk, target.summary):
            result = env.read_revoked(o["context_id"], U42, client=reader)
            env.check(
                f"after lease: {_label(o)} denied (fail closed)",
                not result.allowed and result.decision == "UNKNOWN",
                f"{result.decision} {result.reasons}",
            )

        # Link restored: the revocation is now visible and denies for the right reason.
        link.available = True
        result = env.read_revoked(target.chunk["context_id"], U42, client=reader)
        env.check(
            "after recovery: revocation enforced",
            not result.allowed and "ANCESTOR_DELETED" in result.reasons,
            f"{result.decision} {result.reasons}",
        )
        result = env.read_legit(ctrl.chunk["context_id"], U42, client=reader)
        env.check("after recovery: unrelated object allowed", result.allowed, result.decision)
        return env.finish(
            "service_outage",
            lease_seconds=lease,
            bounded_exposure_served=exposure,
            simulated_exposure_window_seconds=20.0,
            note="exposure counted separately from escapes: it is the published BOUNDED_OFFLINE window",
        )


def delayed_revocation() -> ScenarioResult:
    """A revocation with a future ``effective_at`` is accepted now but only denies once it is effective."""
    clock = (
        FakeClock()
    )  # reader's monotonic clock: deliberately NEVER advanced, so the 30 s TTL cannot expire
    with ServerClock() as sclock, BenchEnv(tenant="delayed") as env:
        # The reader caches ALLOWs but the server stamps each one with ``valid_until`` (the pending
        # effective_at). Only the shared wall clock moves, so a denial after effective_at can come from
        # nothing but the cache's valid_until bound (not TTL expiry and not an epoch change).
        def wall() -> float:
            return time.time() + sclock.offset

        reader = env.client_for(
            "delayed",
            name="reader",
            cache=DecisionCache(max_ttl=30.0, clock=clock, wall_clock=wall),
            clock=clock,
            wall_clock=wall,
        )

        def advance(seconds: float) -> None:
            sclock.advance(seconds)

        a = env.build_lineage("scheduled")
        ctrl = env.build_lineage("unscheduled")
        # (No reader priming before the revocation: a cached ALLOW from before the event is accepted carries no
        # valid_until, and that cross-client staleness is the separate multi-process gap listed in the report.)
        delay = 3600.0
        accepted = env.revoke(
            a.source,
            "deleted",
            effective_at=datetime.now(UTC) + timedelta(seconds=delay),
            track_latency=False,
        )
        env.check("future-dated event accepted", "revocation_epoch" in accepted, str(accepted))

        # Before effectiveness the data is still entitled: these are legitimate reads, not escapes.
        cache_hits_before = 0
        for o in a.everything:
            result = env.read_legit(o["context_id"], U42, client=reader)
            env.check(
                f"before effective_at: {_label(o)} still ALLOW",
                result.allowed,
                f"{result.decision} {result.reasons}",
            )
        for o in a.everything:  # second pass: served from the decision cache (valid_until in the future)
            result = env.read_legit(o["context_id"], U42, client=reader)
            cache_hits_before += int(env.authorize_log[-1].from_cache)
            env.check(
                f"before effective_at: {_label(o)} cached ALLOW",
                result.allowed,
                f"{result.decision} {result.reasons}",
            )
        advance(delay / 2)
        result = env.read_legit(a.chunk["context_id"], U42, client=reader)
        cache_hits_before += int(env.authorize_log[-1].from_cache)
        env.check("halfway to effective_at: still ALLOW", result.allowed, result.decision)

        # Simulated time passes effective_at: every descendant (and the source) must deny.
        advance(delay / 2 + 1)
        for o in a.everything:
            result = env.read_revoked(o["context_id"], U42, client=reader)
            env.check(
                f"after effective_at: {_label(o)} denied",
                not result.allowed and "ANCESTOR_DELETED" in result.reasons,
                f"{result.decision} {result.reasons}",
            )
        lin = env.client.lineage(a.source["context_id"])
        env.check(
            "descendants tombstoned once effective",
            all(d["tombstoned"] for d in lin["descendants"]),
            f"{[d['tombstoned'] for d in lin['descendants']]}",
        )
        for o in ctrl.everything:
            env.read_legit(o["context_id"], U42, client=reader)
        env.check(
            "reader cache hits before effective_at were served from the decision cache",
            cache_hits_before > 0,
            str(cache_hits_before),
        )
        return env.finish(
            "delayed_revocation",
            delay_seconds=delay,
            reader_cache_ttl_seconds=30.0,
            note=(
                "reads before effective_at are legitimate (not escapes); escapes are counted only after it. "
                "The reader's monotonic clock is frozen, so cutover is enforced by valid_until, not TTL"
            ),
        )


def scoped_revocation() -> ScenarioResult:
    """``affected_scope`` revokes for named principals only; a later unscoped event revokes for everyone."""
    scope = {"principals": ["user-42"]}
    with BenchEnv(tenant="scoped") as env:
        a = env.build_lineage("shared-doc")
        ctrl = env.build_lineage("untouched")
        for o in a.everything:
            env.read_legit(o["context_id"], U42)
            env.read_legit(o["context_id"], U7)

        env.revoke(a.source, "acl_changed", affected_scope=scope)

        for o in a.everything:
            result = env.read_revoked(o["context_id"], U42)
            env.check(
                f"user-42 denied on {_label(o)}",
                not result.allowed and "ANCESTOR_ACL_REVOKED" in result.reasons,
                f"{result.decision} {result.reasons}",
            )
        for o in a.everything:  # out of scope: still entitled, so these are legit reads, never escapes
            result = env.read_legit(o["context_id"], U7)
            env.check(
                f"user-7 still ALLOW on {_label(o)}", result.allowed, f"{result.decision} {result.reasons}"
            )

        env.revoke(a.source, "acl_changed")  # unscoped follow-up: everyone
        for p in (U42, U7):
            for o in a.everything:
                result = env.read_revoked(o["context_id"], p)
                env.check(
                    f"{p['id']} denied on {_label(o)} after unscoped event",
                    not result.allowed and "ANCESTOR_ACL_REVOKED" in result.reasons,
                    f"{result.decision} {result.reasons}",
                )
        for o in ctrl.everything:
            env.read_legit(o["context_id"], U42)
            env.read_legit(o["context_id"], U7)
        return env.finish("scoped_revocation", scoped_principals=scope["principals"])


def signed_ingress() -> ScenarioResult:
    """A require_signatures server accepts only issuer-signed envelopes/events and enforces them end to end."""
    key = Ed25519PrivateKey.generate()
    with BenchEnv(tenant="signed", require_signatures=True) as env:

        def rejected(label: str, fn: Callable[[], object]) -> None:
            try:
                fn()
                env.check(label, False, "accepted")
            except AlesHTTPError as e:
                env.check(label, e.status_code in (401, 403, 422), str(e.status_code))

        # Before any issuer key exists, and with no signature at all: nothing may register.
        unsigned = new_source(
            "signed", "kb/unsigned.md", "unsigned body", "bench-kb", classification="confidential"
        )
        rejected("unsigned source rejected", lambda: env.client.register_source(unsigned))
        result = env.read_revoked(unsigned["context_id"], U42)
        env.check(
            "rejected source is not readable", not result.allowed, f"{result.decision} {result.reasons}"
        )

        env.enable_signing(key)
        tampered = env.sign_envelope(
            new_source("signed", "kb/tampered.md", "original", "bench-kb", classification="confidential")
        )
        tampered["object_id"] = "kb/tampered-after-signing.md"
        rejected("tampered signed source rejected", lambda: env.client.register_source(tampered))

        a = env.build_lineage("signed-doc")
        ctrl = env.build_lineage("signed-ctrl")
        for o in a.everything:
            env.read_legit(o["context_id"], U42)

        # An unsigned revocation must not be honoured, and must not disturb anything.
        rejected(
            "unsigned revocation rejected",
            lambda: env.client.submit_revocation(
                {"source_id": a.source["context_id"], "reason": "deleted", "actor": "attacker"}
            ),
        )
        for o in a.everything:
            result = env.read_legit(o["context_id"], U42)
            env.check(f"after rejected event: {_label(o)} still ALLOW", result.allowed, result.decision)

        env.revoke(a.source, "deleted")  # signed by the registered issuer key
        for o in a.everything:
            result = env.read_revoked(o["context_id"], U42)
            env.check(
                f"signed revocation: {_label(o)} denied",
                not result.allowed and "ANCESTOR_DELETED" in result.reasons,
                f"{result.decision} {result.reasons}",
            )
        for o in ctrl.everything:
            env.read_legit(o["context_id"], U42)
        return env.finish("signed_ingress", issuer_key_id=env.signing[1] if env.signing else None)


def deep_lineage() -> ScenarioResult:
    """A chain of 100 derivations; revoking the root must deny every link. Records authorize latency at depth."""
    depth = 100
    with BenchEnv(tenant="deep") as env:
        env.lineage_audit_every = 10  # each lineage call is O(depth); audit a spread sample, not all 101
        chain = [env.source("deep-root")]
        for i in range(1, depth + 1):
            chain.append(env.derive("chunk" if i % 2 else "summary", [chain[-1]], f"deep/{i}"))
        env.check("chain built", len(chain) == depth + 1, str(len(chain)))
        ctrl = env.build_lineage("deep-ctrl")

        mark = len(env.authorize_log)
        for o in chain:  # first read of each object is a server round trip (nothing cached yet)
            env.read_legit(o["context_id"], U42)
        pre = [a.ms for a in env.authorize_log[mark:] if not a.from_cache]
        deepest = [a.ms for a in env.authorize_log[mark:][-10:]]

        t0 = time.perf_counter()
        lin = env.client.lineage(chain[-1]["context_id"])
        lineage_leaf_ms = (time.perf_counter() - t0) * 1000
        env.check(
            "leaf lineage reports the full ancestor chain",
            len(lin["ancestors"]) == depth,
            f"{len(lin['ancestors'])} ancestors",
        )

        env.revoke(chain[0], "deleted")
        mark = len(env.authorize_log)
        for o in chain:
            result = env.read_revoked(o["context_id"], U42)
            env.check(
                f"depth {chain.index(o)} denied",
                not result.allowed and "ANCESTOR_DELETED" in result.reasons,
                f"{result.decision} {result.reasons}",
            )
        post = [a.ms for a in env.authorize_log[mark:] if not a.from_cache]
        leaf_ms = env.authorize_log[-1].ms
        for o in ctrl.everything:
            env.read_legit(o["context_id"], U42)
        return env.finish(
            "deep_lineage",
            depth=depth,
            lineage_call_leaf_ms=round(lineage_leaf_ms, 3),
            lineage_audit="every 10th derivative plus the leaf",
            authorize_p95_ms_pre_revocation_all_depths=round(percentile(pre, 95) or 0, 3),
            authorize_p95_ms_pre_revocation_deepest10=round(percentile(deepest, 95) or 0, 3),
            authorize_p95_ms_post_revocation_all_depths=round(percentile(post, 95) or 0, 3),
            authorize_ms_post_revocation_leaf=round(leaf_ms, 3),
            note="every authorize here is an uncached server round trip (distinct objects, epoch just changed)",
        )


def wide_fanout() -> ScenarioResult:
    """One source with 200 children; a single revocation must deny all of them."""
    width = 200
    with BenchEnv(tenant="wide") as env:
        env.lineage_audit_every = 10  # audit a spread sample of the 200 children, not every one
        src = env.source("wide-root")
        kids = [env.derive("chunk", [src], f"wide/{i}") for i in range(width)]
        ctrl = env.build_lineage("wide-ctrl")
        for o in [src, *kids[::10]]:  # sample of pre-revocation reads; all 200 are checked after
            env.read_legit(o["context_id"], U42)

        plant = env.enable_purge()
        for o in kids:
            plant.place(o)
        for o in ctrl.descendants:
            plant.place(o)

        env.revoke(src, "deleted")
        accept_ms = env.revocation_ms[-1]
        result = env.read_revoked(src["context_id"], U42)  # first denied read after acceptance
        first_denied = env.revoke_to_deny_ms[-1] if env.revoke_to_deny_ms else None
        env.check(
            "source denied",
            not result.allowed and "ANCESTOR_DELETED" in result.reasons,
            f"{result.decision} {result.reasons}",
        )
        with plant.session_factory() as sess:
            enqueued = sum(n for st in outbox_stats(sess)["by_store_kind"].values() for n in st.values())
        env.check("one purge row per child enqueued by the revocation", enqueued >= width, f"{enqueued}")
        purge_ms = env.purge_now(kids, controls=ctrl.descendants)
        for i, o in enumerate(kids):
            result = env.read_revoked(o["context_id"], U42)
            env.check(
                f"child {i} denied",
                not result.allowed and "ANCESTOR_DELETED" in result.reasons,
                f"{result.decision} {result.reasons}",
            )
        for o in ctrl.everything:
            env.read_legit(o["context_id"], U42)
        return env.finish(
            "wide_fanout",
            width=width,
            revocation_accept_ms=round(accept_ms, 3),
            outbox_rows_enqueued_by_accept=enqueued,
            first_deny_latency_ms=None if first_denied is None else round(first_denied, 3),
            purge_completion_ms=round(purge_ms, 3),
            note="purge enqueue happens inside the revocation transaction, so its time is part of revocation_accept_ms",
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
    "delayed_revocation": delayed_revocation,
    "scoped_revocation": scoped_revocation,
    "signed_ingress": signed_ingress,
    "deep_lineage": deep_lineage,
    "wide_fanout": wide_fanout,
}

# Scenarios that need an in-process trick and therefore always run on the in-process profile:
# service_outage kills the SDK transport; delayed_revocation shifts the server's wall clock.
INPROCESS_ONLY = frozenset({"service_outage", "delayed_revocation"})
