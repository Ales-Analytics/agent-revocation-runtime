"""``ales`` command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, TextIO

import httpx

from .client import AlesError, InvariantClient
from .envelope import new_derivative, new_source

DEFAULT_BASE_URL = "http://localhost:8787"
CONFIG_FILE = "ales.toml"
DEMO_PRINCIPAL = {"type": "user", "id": "demo-user"}
DEMO_PURPOSE = "rag_answer"


def _load_config(path: str = CONFIG_FILE) -> dict[str, str]:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        import tomllib

        return dict(tomllib.loads(p.read_text(encoding="utf-8")))
    except (OSError, ValueError, ImportError):
        return {}


def _make_client(**kw: Any) -> InvariantClient:
    cfg = _load_config()
    base = os.environ.get("ALES_BASE_URL") or cfg.get("base_url") or DEFAULT_BASE_URL
    tenant = os.environ.get("ALES_TENANT_ID") or cfg.get("tenant_id") or "demo-tenant"
    token = os.environ.get("ALES_AUTH_TOKEN") or cfg.get("auth_token") or None
    # No token configured: allow anonymous so the CLI can talk to a local dev server; a server that
    # enforces auth rejects the call with a typed AuthError.
    return InvariantClient(base, tenant, auth_token=token, allow_anonymous=token is None, **kw)


def run_revoke_rag_source(client: InvariantClient, out: TextIO = sys.stdout) -> bool:
    """source -> chunk+summary+memory -> authorize(ALLOW) -> revoke -> authorize(DENY). Returns pass."""
    t = client.tenant_id
    src = new_source(t, "kb/handbook.md", "Confidential handbook text", "demo-kb", classification="confidential")
    client.register_source(src)
    derivs = [
        new_derivative("chunk", [src], t, "kb/handbook.md#chunk-0", "chunk text"),
    ]
    derivs.append(new_derivative("summary", [derivs[0]], t, "kb/handbook.md#summary", "summary text"))
    derivs.append(new_derivative("memory", [derivs[1]], t, "mem/handbook", "memory text"))
    for d in derivs:
        client.register_derivation(d)
    ids = [d["context_id"] for d in derivs]

    rows: list[tuple[str, str, str]] = []

    before = client.authorize(DEMO_PRINCIPAL, DEMO_PURPOSE, ids)
    rows.append(("authorize before revocation", "ALLOW", before.decision))

    client.submit_revocation({"source_id": src["context_id"], "reason": "deleted", "actor": "ales-demo"})
    after = client.authorize(DEMO_PRINCIPAL, DEMO_PURPOSE, ids)
    rows.append(("authorize after revocation", "DENY", after.decision))
    for d, kind in zip(derivs, ("chunk", "summary", "memory"), strict=True):
        v = after.verdict_for(d["context_id"])
        rows.append((f"  {kind} denied", "DENY", v.decision if v else "MISSING"))

    ok = True
    print(f"{'STEP':<34}{'EXPECTED':<10}{'ACTUAL':<10}RESULT", file=out)
    for step, exp, act in rows:
        passed = exp == act
        ok &= passed
        print(f"{step:<34}{exp:<10}{act:<10}{'PASS' if passed else 'FAIL'}", file=out)
    print("OVERALL: " + ("PASS" if ok else "FAIL"), file=out)
    return ok


def cmd_init(args: argparse.Namespace) -> int:
    p = Path(CONFIG_FILE)
    if p.exists() and not args.force:
        print(f"{CONFIG_FILE} already exists (use --force to overwrite)")
        return 1
    p.write_text(
        f'base_url = "{DEFAULT_BASE_URL}"\ntenant_id = "demo-tenant"\nfail_mode = "ENFORCE"\n', encoding="utf-8"
    )
    print(f"wrote {CONFIG_FILE}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    print(f"scenario {args.scenario}: register source -> chunk+summary+memory -> authorize (ALLOW)")
    print("  -> submit revocation -> authorize again (DENY) -> PASS/FAIL table")
    env_url = os.environ.get("ALES_BASE_URL")
    if not env_url:
        print("ALES_BASE_URL not set; server not assumed. See examples/ for a runnable walkthrough.")
        return 0
    with _make_client() as client:
        try:
            client.healthz()
        except (AlesError, httpx.HTTPError):
            print(f"server at {env_url} unreachable; see examples/ for a runnable walkthrough.")
            return 0
        try:
            return 0 if run_revoke_rag_source(client) else 1
        except AlesError as e:
            print(f"demo failed: {e}")
            return 1


def cmd_verify(args: argparse.Namespace) -> int:
    with _make_client() as client:
        try:
            res = client.verify(args.adapter, args.mode)
        except AlesError as e:
            print(f"verify failed: {e}")
            return 2
    print(json.dumps(res, indent=2))
    status = str(res.get("status", res.get("result", ""))).lower()
    return 1 if res.get("passed") is False or status in ("fail", "failed") else 0


def cmd_status(_: argparse.Namespace) -> int:
    with _make_client() as client:
        try:
            res = client.healthz()
        except AlesError as e:
            print(f"unreachable: {e}")
            return 1
    print(f"{client.base_url}: ok {json.dumps(res)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="ales", description="ALES INVARIANT SDK CLI")
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init", help="write ales.toml")
    p.add_argument("--local", action="store_true")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)
    p = sub.add_parser("demo", help="run a demo scenario")
    p.add_argument("--scenario", default="revoke-rag-source", choices=["revoke-rag-source"])
    p.set_defaults(func=cmd_demo)
    p = sub.add_parser("verify", help="verify an adapter via /v1/verify")
    p.add_argument("--adapter", required=True)
    p.add_argument("--mode", default="strict")
    p.set_defaults(func=cmd_verify)
    p = sub.add_parser("status", help="check server health")
    p.set_defaults(func=cmd_status)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
