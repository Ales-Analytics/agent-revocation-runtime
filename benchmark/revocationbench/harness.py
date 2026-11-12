"""BenchEnv: an in-process control plane plus bridged SDK clients, with timing and escape accounting.

Every scenario gets a fresh ``create_app("sqlite://")`` (in-memory SQLite) and one or more
``InvariantClient`` instances whose HTTP transport is bridged into a FastAPI ``TestClient``.
All client calls that matter are wrapped so timing is captured no matter who makes them (the harness
or an adapter): ``authorize`` (decision overhead), ``submit_revocation`` (acceptance latency) and
the register calls (so lineage completeness can be audited from what was actually registered).

Definitions used by the metrics:

* **post-revocation read attempt**: a read of an object whose ancestor was revoked (or that belongs to
  another tenant). Recorded through ``read_revoked`` / ``record_revoked``.
* **escape**: such a read that returned usable content.
* **legitimate read**: a read by an authorized principal of an object whose lineage is intact.
  If it is denied it is a **false block**.
"""

from __future__ import annotations

import base64
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Self

import httpx
from ales_core import ContextEnvelope, RevocationEvent, sign_model
from ales_sdk import InvariantClient, new_derivative, new_source
from ales_sdk.wrappers import guard_retrieval
from ales_server import create_app
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from . import _paths  # noqa: F401

BASE_URL = "http://testserver"
RAG = "rag"


ALL_ROLES = ["ingest", "revoke", "read", "admin"]


def bench_token(tenant: str) -> str:
    """Deterministic per-tenant bearer token for the in-process benchmark control plane (not a secret)."""
    return f"bench-token-{tenant}"


def pub_b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


class ServerClock:
    """Shifts the server's wall clock (``ales_server.routes.datetime``) so delayed revocations can be driven.

    The control plane stamps decisions with ``datetime.now(UTC)``; while this context manager is active
    that reading is advanced by ``offset`` seconds, without sleeping.
    """

    def __init__(self) -> None:
        self.offset = 0.0
        self._saved: Any = None

    def advance(self, seconds: float) -> None:
        self.offset += seconds

    def __enter__(self) -> Self:
        from ales_server import routes

        clock = self

        class _Shifted(datetime):
            @classmethod
            def now(cls, tz: Any = None) -> Any:  # type: ignore[override]
                return datetime.now(tz) + timedelta(seconds=clock.offset)

        self._saved = routes.datetime
        routes.datetime = _Shifted  # type: ignore[attr-defined]
        return self

    def __exit__(self, *exc: object) -> None:
        from ales_server import routes

        routes.datetime = self._saved  # type: ignore[attr-defined]


class FakeClock:
    """Controllable monotonic clock for lease / TTL simulation."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class BridgeTransport(httpx.BaseTransport):
    """Sync httpx transport routing SDK requests into a FastAPI TestClient; can simulate an outage."""

    def __init__(self, tc: TestClient) -> None:
        self.tc = tc
        self.available = True

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if not self.available:
            raise httpx.ConnectError("simulated outage: control plane unreachable", request=request)
        headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")}
        resp = self.tc.request(request.method, str(request.url), content=request.content, headers=headers)
        out_headers = [
            (k, v)
            for k, v in resp.headers.items()
            if k.lower() not in ("content-encoding", "transfer-encoding", "content-length")
        ]
        return httpx.Response(resp.status_code, headers=out_headers, content=resp.content, request=request)


@dataclass
class AuthorizeTiming:
    ms: float
    from_cache: bool
    offline: bool
    decision: str


@dataclass
class ReadOutcome:
    context_id: str
    allowed: bool
    decision: str
    reasons: list[str]
    content: str | None


@dataclass
class Lineage:
    """source -> chunk -> embedding, chunk -> summary -> memory, summary -> cache."""

    source: dict[str, Any]
    chunk: dict[str, Any]
    embedding: dict[str, Any]
    summary: dict[str, Any]
    memory: dict[str, Any]
    cache: dict[str, Any]

    @property
    def descendants(self) -> list[dict[str, Any]]:
        return [self.chunk, self.embedding, self.summary, self.memory, self.cache]

    @property
    def everything(self) -> list[dict[str, Any]]:
        return [self.source, *self.descendants]


@dataclass
class ScenarioResult:
    name: str
    passed: bool
    escapes: int
    details: dict[str, Any] = field(default_factory=dict)
    timings: dict[str, list[float]] = field(default_factory=dict)
    attempted: int = 0  # post-revocation read attempts
    legit_reads: int = 0
    false_blocks: int = 0
    bounded_exposure_reads: int = 0  # served within a published exposure window (see service_outage)
    derivatives: int = 0
    derivatives_complete: int = 0


class BenchEnv:
    def __init__(
        self,
        tenant: str = "bench",
        *,
        extra_tenants: Sequence[str] = (),
        require_signatures: bool = False,
        snapshot_key: Ed25519PrivateKey | None = None,
    ) -> None:
        self.tenant = tenant
        self.tokens = {
            bench_token(t): {"tenant_id": t, "roles": list(ALL_ROLES), "subject": f"bench-{t}"}
            for t in (tenant, *extra_tenants)
        }
        # A fixed snapshot key lets BOUNDED_OFFLINE clients verify the real signed policy snapshot.
        self.snapshot_key = snapshot_key
        self.app = create_app(
            "sqlite://",
            tokens=self.tokens,
            require_signatures=require_signatures,
            snapshot_private_key=snapshot_key,
            outbox_interval=0,
        )
        self._tc = TestClient(self.app)
        self._tc.__enter__()
        self.signing: tuple[Ed25519PrivateKey, str] | None = None
        self.clients: dict[str, InvariantClient] = {}
        self._probes: dict[str, InvariantClient] = {}
        self.transports: dict[str, BridgeTransport] = {}
        self.authorize_log: list[AuthorizeTiming] = []
        self.revocation_ms: list[float] = []
        self.revoke_to_deny_ms: list[float] = []
        self.envelopes: dict[tuple[str, str], dict[str, Any]] = {}
        self.content: dict[str, str] = {}
        self.attempted = 0
        self.escapes = 0
        self.legit = 0
        self.false_blocks = 0
        self.bounded_exposure = 0
        self.checks: list[dict[str, Any]] = []
        self.details: dict[str, Any] = {}
        self._accepted_at: float | None = None
        self.client = self.client_for(tenant)

    # -- lifecycle ---------------------------------------------------------------------------
    def close(self) -> None:
        for c in [*self.clients.values(), *self._probes.values()]:
            c.close()
        self._tc.__exit__(None, None, None)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- clients -----------------------------------------------------------------------------
    def _new_client(self, tenant: str, **kw: Any) -> tuple[InvariantClient, BridgeTransport]:
        transport = BridgeTransport(self._tc)
        kw.setdefault("auth_token", bench_token(tenant))
        if self.snapshot_key is not None:
            kw.setdefault("snapshot_public_key", pub_b64(self.snapshot_key))
        return InvariantClient(BASE_URL, tenant, transport=transport, **kw), transport

    def raw(self, method: str, path: str, tenant: str | None = None, **kw: Any) -> httpx.Response:
        """A direct HTTP call with the tenant's token (to assert status codes the SDK would wrap)."""
        headers = {"Authorization": f"Bearer {bench_token(tenant or self.tenant)}"}
        return self._tc.request(method, path, headers=headers, **kw)

    # -- issuer signing (require_signatures servers) -------------------------------------------
    def enable_signing(self, key: Ed25519PrivateKey, key_id: str = "bench-issuer") -> None:
        """Register ``key`` as an active issuer key for the home tenant; sign everything from now on."""
        r = self.raw("POST", "/v1/admin/keys", json={"key_id": key_id, "public_key_b64": pub_b64(key)})
        if r.status_code != 201:
            raise RuntimeError(f"issuer key registration failed: {r.status_code} {r.text}")
        self.signing = (key, key_id)

    def sign_envelope(self, env: dict[str, Any]) -> dict[str, Any]:
        if self.signing is None:
            return env
        key, kid = self.signing
        return sign_model(ContextEnvelope.model_validate(env), key, kid).model_dump(mode="json")

    def sign_event(self, event: dict[str, Any]) -> dict[str, Any]:
        if self.signing is None:
            return event
        key, kid = self.signing
        return sign_model(RevocationEvent.model_validate(event), key, kid).model_dump(mode="json")

    def client_for(self, tenant: str, name: str | None = None, **kw: Any) -> InvariantClient:
        """A timed client bound to ``tenant``. ``name`` (default: tenant) keys it for later lookup."""
        name = name or tenant
        c, transport = self._new_client(tenant, **kw)
        self._instrument(c)
        self.clients[name] = c
        self.transports[name] = transport
        return c

    def _probe(self, tenant: str) -> InvariantClient:
        if tenant not in self._probes:
            self._probes[tenant] = self._new_client(tenant)[0]
        return self._probes[tenant]

    def _instrument(self, c: InvariantClient) -> None:
        orig_auth, orig_rev = c.authorize, c.submit_revocation
        orig_src, orig_der = c.register_source, c.register_derivation

        def authorize(*a: Any, **kw: Any):
            t0 = time.perf_counter()
            r = orig_auth(*a, **kw)
            t1 = time.perf_counter()
            self.authorize_log.append(AuthorizeTiming((t1 - t0) * 1000, r.from_cache, r.offline, r.decision))
            if self._accepted_at is not None and r.decision != "ALLOW":
                self.revoke_to_deny_ms.append((t1 - self._accepted_at) * 1000)
                self._accepted_at = None  # only the first denied read after a revocation counts
            return r

        def submit_revocation(event: Any):
            t0 = time.perf_counter()
            out = orig_rev(event)
            t1 = time.perf_counter()
            self.revocation_ms.append((t1 - t0) * 1000)
            self._accepted_at = t1
            return out

        def register_source(env: Any):
            out = orig_src(env)
            self.envelopes[(env["context_id"], env["object_version"])] = dict(env)
            return out

        def register_derivation(env: Any):
            out = orig_der(env)
            self.envelopes[(env["context_id"], env["object_version"])] = dict(env)
            return out

        c.authorize = authorize  # type: ignore[method-assign]
        c.submit_revocation = submit_revocation  # type: ignore[method-assign]
        c.register_source = register_source  # type: ignore[method-assign]
        c.register_derivation = register_derivation  # type: ignore[method-assign]

    # -- building lineage --------------------------------------------------------------------
    def source(
        self,
        name: str,
        *,
        client: InvariantClient | None = None,
        object_id: str | None = None,
        principal_scope: list[str] | None = None,
        classification: str = "confidential",
        object_version: str = "1",
        context_id: str | None = None,
        content: str | None = None,
    ) -> dict[str, Any]:
        c = client or self.client
        text = content if content is not None else f"{name}: confidential source body"
        env = new_source(
            c.tenant_id,
            object_id or f"kb/{name}.md",
            text,
            "bench-kb",
            object_version=object_version,
            classification=classification,
            principal_scope=principal_scope,
            context_id=context_id,
        )
        env = self.sign_envelope(env)
        c.register_source(env)
        self.content[env["context_id"]] = text
        return env

    def derive(
        self,
        kind: str,
        parents: list[dict[str, Any]],
        name: str,
        *,
        client: InvariantClient | None = None,
        object_id: str | None = None,
    ) -> dict[str, Any]:
        c = client or self.client
        text = f"{name}: {kind} content"
        env = new_derivative(
            kind, parents, c.tenant_id, object_id or f"{kind}:{name}", text, source_system="bench"
        )
        env = self.sign_envelope(env)
        c.register_derivation(env)
        self.content[env["context_id"]] = text
        return env

    def build_lineage(
        self,
        name: str,
        *,
        client: InvariantClient | None = None,
        object_id: str | None = None,
        principal_scope: list[str] | None = None,
    ) -> Lineage:
        src = self.source(name, client=client, object_id=object_id, principal_scope=principal_scope)
        chunk = self.derive("chunk", [src], f"{name}/chunk", client=client)
        emb = self.derive("embedding", [chunk], f"{name}/embedding", client=client)
        summ = self.derive("summary", [chunk], f"{name}/summary", client=client)
        mem = self.derive("memory", [summ], f"{name}/memory", client=client)
        cache = self.derive("cache", [summ], f"{name}/cache", client=client)
        return Lineage(src, chunk, emb, summ, mem, cache)

    # -- revocation --------------------------------------------------------------------------
    def revoke(
        self,
        source: dict[str, Any],
        reason: str,
        *,
        version: str | None = None,
        client: InvariantClient | None = None,
        track_latency: bool = True,
        effective_at: datetime | None = None,
        affected_scope: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        c = client or self.client
        event: dict[str, Any] = {
            "source_id": source["context_id"],
            "reason": reason,
            "actor": "revocationbench",
        }
        if version is not None:
            event["source_version"] = version
        if affected_scope is not None:
            event["affected_scope"] = affected_scope
        if effective_at is not None:
            event["effective_at"] = effective_at.isoformat()
        if self.signing is not None:  # signatures cover every field, so nothing may be server-defaulted
            event.setdefault("event_id", str(uuid.uuid4()))
            event.setdefault("tenant_id", c.tenant_id)
            event.setdefault("effective_at", datetime.now(UTC).isoformat())
            event = self.sign_event(event)
        out = c.submit_revocation(event)
        if not track_latency:
            self._accepted_at = None
        return out

    # -- reads -------------------------------------------------------------------------------
    def read(
        self,
        context_id: str,
        principal: dict[str, str],
        *,
        client: InvariantClient | None = None,
        purpose: str = RAG,
        version: str | None = None,
        agent_id: str | None = None,
    ) -> ReadOutcome:
        """Authorize through the production guard path; content is returned only if allowed."""
        c = client or self.client
        allowed, blocked = guard_retrieval(
            c,
            principal,
            purpose,
            [context_id],
            lambda x: x,
            version_getter=lambda _x: version,
            agent_id=agent_id,
        )
        if allowed:
            return ReadOutcome(context_id, True, "ALLOW", ["OK"], self.content.get(context_id, "<content>"))
        b = blocked[0]
        return ReadOutcome(context_id, False, b.decision, list(b.reasons), None)

    def read_revoked(self, context_id: str, principal: dict[str, str], **kw: Any) -> ReadOutcome:
        """A read that MUST be denied (revoked ancestor / foreign tenant). Counts attempt and escape."""
        out = self.read(context_id, principal, **kw)
        self.record_revoked(out.content is not None)
        return out

    def read_legit(self, context_id: str, principal: dict[str, str], **kw: Any) -> ReadOutcome:
        """A read an authorized principal is entitled to. Counts legit read and false block."""
        out = self.read(context_id, principal, **kw)
        self.record_legit(out.content is not None)
        return out

    def record_revoked(self, returned_content: bool) -> None:
        self.attempted += 1
        if returned_content:
            self.escapes += 1

    def record_legit(self, returned_content: bool) -> None:
        self.legit += 1
        if not returned_content:
            self.false_blocks += 1

    # -- checks ------------------------------------------------------------------------------
    def check(self, label: str, ok: bool, detail: str = "") -> bool:
        self.checks.append({"check": label, "passed": bool(ok), "detail": detail})
        return bool(ok)

    # -- lineage audit -----------------------------------------------------------------------
    def lineage_stats(self) -> tuple[int, int]:
        """(derivatives whose server-side ancestors cover every registered parent chain, total)."""
        complete = total = 0
        for env in list(self.envelopes.values()):
            if env["kind"] == "source":
                continue
            total += 1
            expected: set[tuple[str, str]] = set()
            stack = [(p["context_id"], p["object_version"]) for p in env["parent_refs"]]
            while stack:
                k = stack.pop()
                if k in expected:
                    continue
                expected.add(k)
                pe = self.envelopes.get(k)
                if pe:
                    stack += [(p["context_id"], p["object_version"]) for p in pe["parent_refs"]]
            try:
                lin = self._probe(env["tenant_id"]).lineage(env["context_id"])
                actual = {(a["context_id"], a["object_version"]) for a in lin["ancestors"]}
            except Exception:  # noqa: BLE001 - an unreachable lineage is an incomplete lineage
                actual = set()
            if env["parent_refs"] and expected <= actual:
                complete += 1
        return complete, total

    # -- result ------------------------------------------------------------------------------
    def timings(self) -> dict[str, list[float]]:
        return {
            "authorize_ms": [a.ms for a in self.authorize_log],
            "authorize_server_ms": [a.ms for a in self.authorize_log if not a.from_cache and not a.offline],
            "revocation_ms": list(self.revocation_ms),
            "revocation_to_deny_ms": list(self.revoke_to_deny_ms),
        }

    def finish(self, name: str, **details: Any) -> ScenarioResult:
        complete, total = self.lineage_stats()
        self.check("lineage complete for every derivative", complete == total, f"{complete}/{total}")
        failed = [c["check"] for c in self.checks if not c["passed"]]
        passed = not failed and self.escapes == 0 and self.false_blocks == 0 and self.attempted > 0
        return ScenarioResult(
            name=name,
            passed=passed,
            escapes=self.escapes,
            details={**self.details, **details, "checks": list(self.checks), "failed_checks": failed},
            timings=self.timings(),
            attempted=self.attempted,
            legit_reads=self.legit,
            false_blocks=self.false_blocks,
            bounded_exposure_reads=self.bounded_exposure,
            derivatives=total,
            derivatives_complete=complete,
        )
