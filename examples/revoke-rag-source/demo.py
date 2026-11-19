"""Revoke a RAG source: every derivative becomes unusable before any physical purge.

Default mode (no arguments) runs fully in-process: the FastAPI control plane on in-memory SQLite,
reached through a sync httpx bridge to the FastAPI TestClient. No model, no API key, no network.

    python examples/revoke-rag-source/demo.py                  # local, in-process
    python examples/revoke-rag-source/demo.py --server URL     # live control plane (e.g. docker compose)
    python examples/revoke-rag-source/demo.py --server URL --token TOKEN --tenant TENANT

The control plane requires a bearer token on every call. In-process mode mints a throwaway DEMO token
for a throwaway tenant. Server mode defaults to the docker-compose dev token (tenant "dev"); that
token is publicly known and must never be used outside a local dev stack.

Exit code is 0 only if every checkpoint passes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
for _p in (ROOT / "core", ROOT / "sdk-python", ROOT / "server", ROOT / "adapters"):
    sys.path.insert(0, str(_p))

import httpx
from ales_adapters import (
    DictRedis,
    FilesystemSourceConnector,
    GuardedCache,
    GuardedVectorStore,
    InMemoryVectorBackend,
)
from ales_sdk import InvariantClient
from ales_sdk.envelope import new_derivative

PRINCIPAL = {"type": "user", "id": "user-42"}
PURPOSE = "rag"
POLICY_NAME = "hr-policy.txt"
POLICY_TEXT = (
    "Employee benefits policy. Restricted to HR and recruiting.\n\n"
    "Health insurance: medical, dental and vision cover starts on day one.\n\n"
    "Parental leave: primary caregivers receive sixteen weeks of paid leave.\n\n"
    "Remote work: staff may work remotely up to three days per week with manager approval.\n"
)
QUERY = "parental leave paid weeks"
ACL_WITH_USER = {"classification": "restricted", "principal_scope": ["user-42", "recruiting-agent"]}
ACL_WITHOUT_USER = {"classification": "restricted", "principal_scope": ["recruiting-agent"]}
EMBED_DIM = 64
# DEMO ONLY: a throwaway token for the in-process control plane; it exists only for this process.
DEMO_TOKEN = "demo-only-in-process-token-not-a-secret"
# The docker-compose dev stack's token (deploy/dev-tokens.json). Publicly known; never use in production.
DEV_COMPOSE_TOKEN = "dev-only-INSECURE-token-do-not-use-in-production"
DEV_COMPOSE_TENANT = "dev"
MORAL = "The source lost authority; every derivative became unusable — before any physical purge."


@dataclass
class Check:
    label: str
    title: str
    expected: str
    got: str
    ok: bool


def embed(text: str) -> list[float]:
    """Deterministic bag-of-words hash embedding. Stands in for a real model."""
    vec = [0.0] * EMBED_DIM
    for tok in re.findall(r"[a-z0-9]+", text.lower()):
        vec[int(hashlib.sha256(tok.encode()).hexdigest(), 16) % EMBED_DIM] += 1.0
    return vec


def run_flow(
    client: InvariantClient,
    workdir: Path,
    out: Callable[..., Any] = print,
    audit_verify: Callable[[], dict[str, Any]] | None = None,
) -> list[Check]:
    """The scenario. Works against any InvariantClient (in-process bridge or live HTTP).

    ``audit_verify`` fetches ``GET /v1/audit/verify`` (an admin call the SDK does not wrap); the final
    checkpoint asserts the tenant's audit hash chain is intact after everything above.
    """
    checks: list[Check] = []

    def record(label: str, title: str, expected: str, got: str, ok: bool) -> None:
        c = Check(label, title, expected, got, bool(ok))
        checks.append(c)
        out(f"[{label:<9}] {title:<34} {'PASS' if c.ok else 'FAIL'}   {got}")

    try:
        # 1. A restricted source file with an ACL sidecar; the connector registers it.
        root = workdir / "hr-docs"
        root.mkdir()
        (root / POLICY_NAME).write_text(POLICY_TEXT, encoding="utf-8")
        sidecar = root / (POLICY_NAME + ".acl.json")
        sidecar.write_text(json.dumps(ACL_WITH_USER), encoding="utf-8")
        connector = FilesystemSourceConnector(
            client, root, client.tenant_id, checkpoint_path=workdir / "connector-checkpoint.json"
        )
        envs = connector.scan()
        src = next((e for e in envs if e["object_id"] == POLICY_NAME), None)
        src_ok = (
            src is not None
            and src["classification"] == "restricted"
            and set(src.get("principal_scope") or []) == {"user-42", "recruiting-agent"}
        )
        record(
            "1",
            "register restricted source",
            "1 source, restricted, scope user-42",
            f"{len(envs)} registered, classification={src and src['classification']}",
            src_ok,
        )

        # 2. Naive paragraph chunking; each chunk is a derivative of the source.
        store = GuardedVectorStore(client, PRINCIPAL, PURPOSE, InMemoryVectorBackend())
        chunk_texts = [p.strip() for p in POLICY_TEXT.split("\n\n") if p.strip()]
        chunk_envs = [store.add_derived([src], text, embed(text)) for text in chunk_texts]
        record(
            "2",
            "chunk and index derivatives",
            f"{len(chunk_texts)} chunk derivatives",
            f"{len(chunk_envs)} chunk derivatives",
            len(chunk_envs) == len(chunk_texts) and all(c["kind"] == "chunk" for c in chunk_envs),
        )

        # 3. The agent "summarizes" by truncation (no LLM); summary, cached answer and memory
        #    are all registered as derivatives of the chunks.
        summary_text = " ".join(chunk_texts)[:120].rstrip() + "..."
        summ_env = new_derivative(
            "summary",
            chunk_envs,
            client.tenant_id,
            "summary:hr-benefits",
            summary_text,
            source_system="demo-agent",
        )
        client.register_derivation(summ_env)
        cache = GuardedCache(client, PRINCIPAL, PURPOSE, DictRedis(), prefix="demo:")
        cache.put("hr-benefits-faq", {"answer": summary_text}, [summ_env])
        mem_env = new_derivative(
            "memory",
            [summ_env],
            client.tenant_id,
            "memory:employee-relations",
            "employee-relations note: " + summary_text,
            source_system="demo-agent",
        )
        client.register_derivation(mem_env)
        lin3 = client.lineage(mem_env["context_id"])
        reaches_source = any(a["context_id"] == src["context_id"] for a in lin3["ancestors"])
        record(
            "3",
            "summary, cache entry, memory",
            "memory lineage reaches the source",
            f"{len(lin3['ancestors'])} ancestors, source reachable={reaches_source}",
            reaches_source,
        )

        # 4. Before revocation, the same three reads as user-42 are allowed.
        hits, blocked = store.search(embed(QUERY), k=len(chunk_texts))
        top = hits[0].payload["text"] if hits else ""
        record(
            "4.search",
            "retrieval as user-42",
            "ALLOW: top chunk served",
            f"{len(hits)} served, {len(blocked)} blocked, top='{top[:28]}'",
            bool(hits) and not blocked and "Parental" in top,
        )
        value, blocked = cache.get("hr-benefits-faq")
        record(
            "4.cache",
            "cache read as user-42",
            "ALLOW: cached answer returned",
            f"value={'hit' if value is not None else 'None'}, blocked={len(blocked)}",
            value is not None and not blocked,
        )
        result = client.authorize(PRINCIPAL, PURPOSE, [mem_env["context_id"]])
        record(
            "4.memory", "memory authorize as user-42", "ALLOW", result.decision, result.decision == "ALLOW"
        )

        # 5. HR narrows the sidecar ACL to remove user-42. The connector emits acl_changed.
        sidecar.write_text(json.dumps(ACL_WITHOUT_USER), encoding="utf-8")
        events = connector.watch_once()
        revs = [e for e in events if e["reason"] == "acl_changed"]
        record(
            "5",
            "sidecar edit emits revocation",
            "acl_changed revocation accepted",
            f"reasons={[e['reason'] for e in events]}, epoch={revs[0]['revocation_epoch'] if revs else None}",
            bool(revs) and revs[0]["revocation_epoch"] is not None,
        )

        # 6. The same three reads are now denied, although the cache entry still exists in redis.
        hits, blocked = store.search(embed(QUERY), k=len(chunk_texts))
        reasons = {r for b in blocked for r in b.reasons}
        record(
            "6.search",
            "retrieval as user-42",
            "0 served, ANCESTOR_ACL_REVOKED",
            f"{len(hits)} served, {len(blocked)} blocked, reasons={sorted(reasons)}",
            not hits and len(blocked) == len(chunk_texts) and "ANCESTOR_ACL_REVOKED" in reasons,
        )
        value, blocked = cache.get("hr-benefits-faq")
        cache_reasons = blocked[0].reasons if blocked else []
        record(
            "6.cache",
            "cache read as user-42",
            "None, blocked ANCESTOR_ACL_REVOKED",
            f"value={'hit' if value is not None else 'None'}, reasons={cache_reasons}",
            value is None and "ANCESTOR_ACL_REVOKED" in cache_reasons,
        )
        result = client.authorize(PRINCIPAL, PURPOSE, [mem_env["context_id"]])
        record(
            "6.memory",
            "memory authorize as user-42",
            "DENY, ANCESTOR_ACL_REVOKED",
            f"{result.decision}, reasons={result.reason}",
            result.decision == "DENY" and "ANCESTOR_ACL_REVOKED" in result.reason,
        )

        lin = client.lineage(mem_env["context_id"])
        out("  lineage of memory/employee-relations (tombstones):")
        for label, nodes in (("ancestor", lin["ancestors"]), ("descendant", lin["descendants"])):
            for n in nodes:
                out(
                    f"    {label:<10} {n['kind']:<8} {n['context_id'][:8]} v{n['object_version']} "
                    f"tombstoned={n['tombstoned']}"
                )
        old_source_tombstoned = any(a["kind"] == "source" and a["tombstoned"] for a in lin["ancestors"])
        record(
            "6.lineage",
            "source tombstoned in lineage",
            "old source tombstoned=True",
            f"tombstoned={old_source_tombstoned}",
            old_source_tombstoned,
        )

        # 12. Every registration, revocation and decision above was written to the tamper-evident audit
        #     chain; verifying it end to end proves none of it was altered or dropped.
        if audit_verify is None:
            record("12", "audit chain verifies", "ok=true", "no audit verifier supplied", False)
        else:
            rep_ = audit_verify()
            record(
                "12",
                "audit chain verifies",
                "ok=true, records checked > 0",
                f"ok={rep_.get('ok')}, records={rep_.get('records_checked')}, first_bad={rep_.get('first_bad_seq')}",
                rep_.get("ok") is True and (rep_.get("records_checked") or 0) > 0,
            )
    except Exception as exc:  # noqa: BLE001 - an unexpected error is a FAIL checkpoint, not a crash
        record("error", "unexpected exception", "no exception", f"{type(exc).__name__}: {exc}", False)
    return checks


def render_table(checks: list[Check], out: Callable[..., Any] = print) -> None:
    rows = [(c.label, c.expected, c.got, "PASS" if c.ok else "FAIL") for c in checks]
    headers = ("step", "expected", "got", "result")
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    out(fmt.format(*headers))
    out(fmt.format(*("-" * w for w in widths)))
    for r in rows:
        out(fmt.format(*r))


def all_passed(checks: list[Check]) -> bool:
    return bool(checks) and all(c.ok for c in checks)


class _TestClientTransport(httpx.BaseTransport):
    """Sync httpx transport that routes SDK requests into the FastAPI TestClient (as in server/tests)."""

    def __init__(self, tc: Any) -> None:
        self.tc = tc

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")}
        response = self.tc.request(request.method, str(request.url), content=request.content, headers=headers)
        out_headers = [
            (k, v)
            for k, v in response.headers.items()
            if k.lower() not in ("content-encoding", "transfer-encoding", "content-length")
        ]
        return httpx.Response(
            response.status_code, headers=out_headers, content=response.content, request=request
        )


def new_tenant() -> str:
    return f"demo-{uuid.uuid4().hex[:8]}"


def run_local(tenant: str | None = None, out: Callable[..., Any] = print) -> list[Check]:
    """Default mode: in-process control plane on in-memory SQLite."""
    # Set before importing ales_server: its module-level app is built from DATABASE_URL on import.
    os.environ["DATABASE_URL"] = "sqlite://"
    from ales_server import create_app
    from fastapi.testclient import TestClient

    tenant = tenant or new_tenant()
    tokens = {
        DEMO_TOKEN: {"tenant_id": tenant, "roles": ["ingest", "revoke", "read", "admin"], "subject": "demo"}
    }
    with (
        tempfile.TemporaryDirectory(prefix="ales-revoke-demo-") as tmp,
        TestClient(create_app("sqlite://", tokens=tokens, outbox_interval=0)) as tc,
        InvariantClient(
            "http://testserver", tenant, auth_token=DEMO_TOKEN, transport=_TestClientTransport(tc)
        ) as client,
    ):

        def audit_verify() -> dict[str, Any]:
            r = tc.get("/v1/audit/verify", headers={"Authorization": f"Bearer {DEMO_TOKEN}"})
            r.raise_for_status()
            return r.json()

        return run_flow(client, Path(tmp), out=out, audit_verify=audit_verify)


def run_remote(
    url: str,
    tenant: str | None = None,
    out: Callable[..., Any] = print,
    token: str = DEV_COMPOSE_TOKEN,
) -> list[Check]:
    """Server mode: the same flow against a live control plane (the token's tenant must match ``tenant``)."""
    tenant = tenant or DEV_COMPOSE_TENANT
    with (
        tempfile.TemporaryDirectory(prefix="ales-revoke-demo-") as tmp,
        InvariantClient(url, tenant, auth_token=token) as client,
        httpx.Client(
            base_url=url.rstrip("/"), headers={"Authorization": f"Bearer {token}"}, timeout=30
        ) as http,
    ):
        client.healthz()

        def audit_verify() -> dict[str, Any]:
            r = http.get("/v1/audit/verify")
            r.raise_for_status()
            return r.json()

        return run_flow(client, Path(tmp), out=out, audit_verify=audit_verify)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Revoke a RAG source and watch its derivatives go dark.")
    parser.add_argument(
        "--server", metavar="URL", help="run against a live control plane, e.g. http://localhost:8787"
    )
    parser.add_argument(
        "--token",
        default=DEV_COMPOSE_TOKEN,
        help="bearer token for --server (default: the docker-compose dev token; INSECURE, local dev only)",
    )
    parser.add_argument(
        "--tenant",
        default=DEV_COMPOSE_TENANT,
        help="tenant the token is bound to, for --server (default: dev)",
    )
    args = parser.parse_args(argv)

    print("ALES INVARIANT demo: revoke-rag-source")
    print(f"mode: {'server ' + args.server if args.server else 'local (in-process)'}")
    print()
    if args.server:
        try:
            checks = run_remote(args.server, tenant=args.tenant, token=args.token)
        except Exception as exc:  # noqa: BLE001 - any failure to reach the server is reported, not raised
            print(f"cannot reach control plane at {args.server}: {exc}")
            return 2
    else:
        checks = run_local()

    print()
    render_table(checks)
    print()
    passed = sum(c.ok for c in checks)
    print(f"{'ALL PASS' if all_passed(checks) else 'FAIL'}: {passed}/{len(checks)} checkpoints")
    print(MORAL)
    return 0 if all_passed(checks) else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
