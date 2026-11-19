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
    configuration = _load_config()
    base = os.environ.get("ALES_BASE_URL") or configuration.get("base_url") or DEFAULT_BASE_URL
    tenant = os.environ.get("ALES_TENANT_ID") or configuration.get("tenant_id") or "demo-tenant"
    token = os.environ.get("ALES_AUTH_TOKEN") or configuration.get("auth_token") or None
    # No token configured: allow anonymous so the CLI can talk to a local dev server; a server that
    # enforces auth rejects the call with a typed AuthError.
    return InvariantClient(base, tenant, auth_token=token, allow_anonymous=token is None, **kw)


def run_revoke_rag_source(client: InvariantClient, out: TextIO = sys.stdout) -> bool:
    """source -> chunk+summary+memory -> authorize(ALLOW) -> revoke -> authorize(DENY). Returns pass."""
    t = client.tenant_id
    src = new_source(
        t, "kb/handbook.md", "Confidential handbook text", "demo-kb", classification="confidential"
    )
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
        f'base_url = "{DEFAULT_BASE_URL}"\ntenant_id = "demo-tenant"\nfail_mode = "ENFORCE"\n',
        encoding="utf-8",
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
            result = client.verify(args.adapter, args.mode)
        except AlesError as e:
            print(f"verify failed: {e}")
            return 2
    print(json.dumps(result, indent=2))
    status = str(result.get("status", result.get("result", ""))).lower()
    return 1 if result.get("passed") is False or status in ("fail", "failed") else 0


def cmd_status(_: argparse.Namespace) -> int:
    with _make_client() as client:
        try:
            result = client.healthz()
        except AlesError as e:
            print(f"unreachable: {e}")
            return 1
    print(f"{client.base_url}: ok {json.dumps(result)}")
    return 0


PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
_REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_manifests() -> list[dict[str, Any]] | None:
    """Capability manifests as dicts, or ``None`` when ``ales_adapters`` is not installed (imported lazily)."""
    try:
        from ales_adapters.coverage import manifest_report
    except ImportError:
        if not (_REPO_ROOT / "adapters" / "ales_adapters").is_dir():
            return None
        for d in ("adapters", "connectors"):
            p = str(_REPO_ROOT / d)
            if p not in sys.path:
                sys.path.append(p)
        try:
            from ales_adapters.coverage import manifest_report
        except ImportError:
            return None
    return [m.to_dict() for m in manifest_report()]


def _render_checks(title: str, checks: list[tuple[str, str, str]]) -> str:
    width = max((len(n) for _, n, _ in checks), default=4)
    lines = [title, ""] + [f"  {st:<4}  {n:<{width}}  {d}" for st, n, d in checks]
    c = {s: sum(1 for st, _, _ in checks if st == s) for s in (PASS, WARN, FAIL)}
    lines += ["", f"  {c[PASS]} pass, {c[WARN]} warn, {c[FAIL]} fail -> {'FAIL' if c[FAIL] else 'OK'}"]
    return "\n".join(lines)


def _installed_version(pkg: str) -> str | None:
    from importlib import metadata

    try:
        return metadata.version(pkg)
    except metadata.PackageNotFoundError:
        return None


def _in_range(version: str, spec: str) -> bool | None:
    """``None`` when the range is not a PEP 440 specifier (e.g. ``not-imported``)."""
    try:
        from packaging.specifiers import InvalidSpecifier, SpecifierSet
        from packaging.version import InvalidVersion, Version

        return Version(version) in SpecifierSet(spec)
    except (ImportError, InvalidSpecifier, InvalidVersion):
        return None


def _doctor_package_checks(manifests: list[dict[str, Any]] | None) -> list[tuple[str, str, str]]:
    from . import __version__

    result = [(PASS, "ales_sdk", f"importable, version {__version__}")]
    if manifests is None:
        result.append((WARN, "ales_adapters", "not installed; integration manifests unavailable"))
        return result
    result.append((PASS, "ales_adapters", f"importable, {len(manifests)} manifests"))
    ranges: dict[str, set[str]] = {}
    for m in manifests:
        for pkg, spec in m.get("tested_upstream_versions", {}).items():
            ranges.setdefault(pkg, set()).add(spec)
    for pkg in sorted(ranges):
        specs = sorted(ranges[pkg])
        version = _installed_version(pkg)
        if version is None:
            continue  # optional upstream package not installed: nothing to check
        verdicts = [_in_range(version, sp) for sp in specs]
        if all(v is None for v in verdicts):
            continue
        if all(v is not False for v in verdicts):
            result.append((PASS, pkg, f"{version} within tested range {', '.join(specs)}"))
        else:
            result.append((WARN, pkg, f"{version} is outside the tested range {', '.join(specs)}"))
    return result


def _doctor_config_check() -> tuple[str, str, str]:
    p = Path(CONFIG_FILE)
    if not p.exists():
        return (
            WARN,
            "config",
            f"{CONFIG_FILE} not found (using environment/defaults; `ales init` writes one)",
        )
    try:
        import tomllib

        tomllib.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return (FAIL, "config", f"{CONFIG_FILE} unreadable: {e}")
    return (PASS, "config", f"{CONFIG_FILE} readable")


def _doctor_server_checks(server: str | None) -> list[tuple[str, str, str]]:
    configuration = _load_config()
    url = server or os.environ.get("ALES_BASE_URL") or configuration.get("base_url")
    if not url:
        return [
            (
                WARN,
                "server",
                "no server configured (--server, ALES_BASE_URL or base_url); network checks skipped",
            )
        ]
    has_token = bool(os.environ.get("ALES_AUTH_TOKEN") or configuration.get("auth_token"))
    previous = os.environ.get("ALES_BASE_URL")
    os.environ["ALES_BASE_URL"] = url
    result: list[tuple[str, str, str]] = []
    try:
        with _make_client() as client:
            for name, path in (("healthz", "/v1/healthz"), ("readyz", "/v1/readyz")):
                try:
                    client._request("GET", path, retries=0)
                    result.append((PASS, name, f"{path} ok"))
                except (AlesError, httpx.HTTPError) as e:
                    result.append((FAIL, name, f"{path}: {e}"[:200]))
            if not has_token:
                result.append(
                    (WARN, "snapshot key", "no auth token configured (ALES_AUTH_TOKEN / auth_token); skipped")
                )
            else:
                try:
                    info = client._request("GET", "/v1/snapshot/public_key", retries=0)
                    kid = info.get("key_id") if isinstance(info, dict) else "?"
                    if isinstance(info, dict) and info.get("ephemeral"):
                        result.append(
                            (
                                WARN,
                                "snapshot key",
                                f"fetched key_id={kid} but it is EPHEMERAL (changes on restart)",
                            )
                        )
                    else:
                        result.append((PASS, "snapshot key", f"fetched key_id={kid}"))
                except (AlesError, httpx.HTTPError) as e:
                    result.append((FAIL, "snapshot key", f"/v1/snapshot/public_key: {e}"[:200]))
    finally:
        if previous is None:
            os.environ.pop("ALES_BASE_URL", None)
        else:
            os.environ["ALES_BASE_URL"] = previous
    return result


def cmd_doctor(args: argparse.Namespace) -> int:
    checks = _doctor_package_checks(_load_manifests())
    checks.append(_doctor_config_check())
    checks += _doctor_server_checks(args.server)
    print(_render_checks("ALES doctor (client-side checks)", checks))
    print(
        "\n  Server-side configuration (database, keys, purge targets): run `python -m ales_server.preflight` on the server."
    )
    return 1 if any(st == FAIL for st, _, _ in checks) else 0


_NOT_INSTALLED = "ales_adapters is not installed; no integration manifests available."
_INSPECT_COLS = (
    "source_ingestion",
    "parent_preservation",
    "retrieval_interception",
    "memory_interception",
    "model_context_interception",
    "tool_egress_interception",
    "physical_purge",
    "session_reset",
)


def cmd_integrations_inspect(_: argparse.Namespace) -> int:
    manifests = _load_manifests()
    if manifests is None:
        print(_NOT_INSTALLED)
        return 1
    for m in manifests:
        print(f"{m['adapter']}  [{m['enforcement_level']}]")
        for c in _INSPECT_COLS:
            print(f"    {c:<28}{m[c]}")
        if m.get("tested_upstream_versions"):
            print(
                f"    {'tested_upstream_versions':<28}{json.dumps(m['tested_upstream_versions'], sort_keys=True)}"
            )
        if m.get("notes"):
            print(f"    {'notes':<28}{m['notes']}")
    return 0


def _find_conformance_report() -> Path | None:
    for p in (
        Path.cwd() / "conformance" / "report.md",
        Path.cwd() / "report.md",
        _REPO_ROOT / "conformance" / "report.md",
    ):
        if p.is_file():
            return p
    return None


def _parse_manifest_states(text: str) -> dict[str, str]:
    """adapter -> VERIFIED / UNVERIFIED / n/a from the report's ``## Capability manifests`` table."""
    states: dict[str, str] = {}
    in_section = False
    for line in text.splitlines():
        if line.startswith("## "):
            in_section = line.strip() == "## Capability manifests"
            continue
        if (
            in_section
            and line.startswith("|")
            and not line.startswith("|---")
            and not line.startswith("| adapter")
        ):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) >= 2:
                states[cells[0]] = cells[-1]
    return states


def cmd_coverage_report(args: argparse.Namespace) -> int:
    manifests = _load_manifests()
    if manifests is None:
        print(_NOT_INSTALLED)
        return 1
    report = _find_conformance_report()
    states = _parse_manifest_states(report.read_text(encoding="utf-8")) if report else {}
    rows = [
        {**m, "conformance": states.get(m["adapter"], "UNKNOWN" if report is None else "UNVERIFIED")}
        for m in manifests
    ]
    if args.json:
        print(
            json.dumps(
                {"conformance_report": str(report) if report else None, "adapters": rows},
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    print(f"conformance report: {report if report else 'not found (verification states UNKNOWN)'}")
    w = max(len(r["adapter"]) for r in rows)
    for r in rows:
        retr = r["retrieval_interception"].split(":")[0]
        print(
            f"  {r['adapter']:<{w}}  {r['enforcement_level']:<14}  retrieval={retr:<11}  {r['conformance']}"
        )
    unverified = [r["adapter"] for r in rows if r["conformance"] == "UNVERIFIED"]
    if unverified:
        print(f"\n  UNVERIFIED retrieval claims: {', '.join(unverified)}")
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
    p = sub.add_parser("doctor", help="diagnose the local integration environment")
    p.add_argument("--server", default=None, help="server base URL (default: ALES_BASE_URL / ales.toml)")
    p.set_defaults(func=cmd_doctor)
    p = sub.add_parser("integrations", help="integration capability manifests")
    isub = p.add_subparsers(dest="integrations_command", required=True)
    ip = isub.add_parser("inspect", help="print the adapter capability manifest table")
    ip.set_defaults(func=cmd_integrations_inspect)
    p = sub.add_parser("coverage", help="coverage reporting")
    csub = p.add_subparsers(dest="coverage_command", required=True)
    cp = csub.add_parser("report", help="manifests merged with conformance verification states")
    cp.add_argument("--json", action="store_true")
    cp.set_defaults(func=cmd_coverage_report)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
