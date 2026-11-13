"""``python -m ales_server.preflight``: evaluate the CURRENT environment without starting the server.

Prints a PASS / WARN / FAIL table (or JSON with ``--json``) and exits 1 when any check FAILs.
The production rules are the very same function ``create_app`` calls (``hardening.production_violations``),
so a green preflight means the process will pass its startup checks. No network is touched except the
configured database (a plain ``SELECT 1`` plus the migration revision); purge targets and the JWKS URI
are validated structurally and by importability only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.engine import make_url

from .auth import Authenticator
from .config import ConfigError, Settings, env_bool
from .denylist import parse_denylist
from .hardening import (
    dev_unsafe_settings,
    is_memory_sqlite,
    is_sqlite,
    make_engine,
    production_violations,
    purge_policy_issue,
    purge_targets_configured,
)
from .purge_config import build_purge_wiring
from .snapshot import SnapshotSigner

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
DEFAULT_DATABASE_URL = "sqlite:///./invariant.db"


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str


@dataclass
class PreflightReport:
    environment: str = "development"
    checks: list[Check] = field(default_factory=list)

    def add(self, name: str, status: str, detail: str) -> None:
        self.checks.append(Check(name, status, detail))

    def by_name(self, name: str) -> Check:
        return next(c for c in self.checks if c.name == name)

    @property
    def failed(self) -> bool:
        return any(c.status == FAIL for c in self.checks)

    @property
    def exit_code(self) -> int:
        return 1 if self.failed else 0

    def to_dict(self) -> dict[str, Any]:
        counts = {s: sum(1 for c in self.checks if c.status == s) for s in (PASS, WARN, FAIL)}
        return {
            "environment": self.environment,
            "ok": not self.failed,
            "counts": counts,
            "checks": [{"name": c.name, "status": c.status, "detail": c.detail} for c in self.checks],
        }

    def render(self) -> str:
        width = max((len(c.name) for c in self.checks), default=4)
        lines = [f"ALES preflight (ALES_ENV={self.environment})", ""]
        for c in self.checks:
            lines.append(f"  {c.status:<4}  {c.name:<{width}}  {c.detail}")
        d = self.to_dict()["counts"]
        lines += ["", f"  {d[PASS]} pass, {d[WARN]} warn, {d[FAIL]} fail -> {'FAIL' if self.failed else 'OK'}"]
        return "\n".join(lines)


def _readable(path: str) -> str | None:
    try:
        Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        return str(exc)
    return None


def _writable(path: str) -> str | None:
    p = Path(path)
    target = p if p.exists() else p.parent
    if not target.exists():
        return f"directory {str(target)!r} does not exist"
    if not os.access(target, os.W_OK):
        return f"{str(target)!r} is not writable"
    return None


def _check_database(report: PreflightReport, e: Mapping[str, str], url: str) -> None:
    from ales_core.migrations import current_revision, head_revision

    skip = env_bool(e, "ALES_SKIP_STARTUP_MIGRATIONS")
    parsed = make_url(url)
    shown = parsed.render_as_string(hide_password=True)
    if is_memory_sqlite(url):
        report.add("database", PASS, f"{shown} (in-memory; migrated at startup)")
        return
    if is_sqlite(url) and parsed.database and not Path(parsed.database).exists():
        report.add("database", WARN if not skip else FAIL,
                   f"{shown}: file does not exist" + ("; created and migrated at startup" if not skip else
                                                      " and ALES_SKIP_STARTUP_MIGRATIONS is set"))
        return
    try:
        engine = make_engine(url, connect_timeout=None if is_sqlite(url) else 5)
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            at, head = current_revision(engine), head_revision()
        finally:
            engine.dispose()
    except Exception as exc:  # noqa: BLE001 - report any driver failure, never raise
        report.add("database", FAIL, f"{shown}: unreachable ({type(exc).__name__}: {str(exc)[:120]})")
        return
    if at == head:
        report.add("database", PASS, f"{shown}: reachable, migration revision {at} is current")
    elif skip:
        report.add("database", FAIL, f"{shown}: revision {at!r} is behind head {head!r} and startup migrations are skipped")
    else:
        report.add("database", WARN, f"{shown}: revision {at!r} is behind head {head!r}; startup will migrate it")


def run_preflight(
    env: Mapping[str, str] | None = None, *, database_url: str | None = None, deep: bool = False
) -> PreflightReport:
    """Evaluate ``env`` (default ``os.environ``) and return the report; never raises on bad configuration."""
    e = os.environ if env is None else env
    report = PreflightReport()
    url = database_url or e.get("DATABASE_URL") or DEFAULT_DATABASE_URL

    try:
        settings = Settings.from_env(e)
    except ConfigError as exc:
        report.add("settings", FAIL, str(exc))
        return report
    report.environment = settings.environment
    report.add("settings", PASS, "environment variables parse")
    prod = settings.production

    auth: Authenticator | None
    try:
        auth = Authenticator.from_env(e)
    except ConfigError as exc:
        report.add("authentication", FAIL, str(exc))
        auth = None
    if auth is not None:
        _report_auth(report, auth)

    key_material = e.get("ALES_SNAPSHOT_KEY")
    if key_material:
        try:
            SnapshotSigner.load(key_material, key_id=e.get("ALES_SNAPSHOT_KEY_ID") or None)
            report.add("snapshot_key", PASS, "persistent ALES_SNAPSHOT_KEY loads")
        except ConfigError as exc:
            report.add("snapshot_key", FAIL, str(exc))
    else:
        report.add("snapshot_key", WARN,
                   "no ALES_SNAPSHOT_KEY: per-process ephemeral key; offline snapshot verification breaks across "
                   "restarts and replicas")

    if auth is not None:
        if prod:
            violations = production_violations(
                e, settings, auth, url=url, allow_anonymous=None, key_material=key_material
            )
            if violations:
                for i, v in enumerate(violations, 1):
                    report.add(f"production_rule_{i}", FAIL, v)
            else:
                report.add("production_rules", PASS, "all production startup rules satisfied")
        else:
            would = production_violations(e, settings, auth, url=url, allow_anonymous=None, key_material=key_material)
            if would:
                report.add("production_rules", WARN,
                           f"development mode; {len(would)} rule(s) would refuse a production start: " + "; ".join(would))
            else:
                report.add("production_rules", PASS, "development mode; would also pass production rules")

    _check_purge(report, e, settings, deep=deep)
    _check_database(report, e, url)

    deny = (e.get("ALES_DENYLIST_FILE") or "").strip()
    if not deny:
        report.add("denylist_file", PASS, "not configured (optional emergency revocation)")
    else:
        err = _readable(deny)
        if err is None:
            try:
                s, js, _kids, ji = parse_denylist(Path(deny).read_text(encoding="utf-8"), "ALES_DENYLIST_FILE")
                report.add("denylist_file", PASS, f"readable, {len(s)} subject(s), {len(js)} jwt sub(s), {len(ji)} jti(s)")
            except ConfigError as exc:
                report.add("denylist_file", FAIL, str(exc))
        else:
            report.add("denylist_file", FAIL, f"cannot read {deny!r}: {err}")

    export = (e.get("ALES_AUDIT_EXPORT_FILE") or "").strip()
    if not export:
        report.add("audit_export", WARN if prod else PASS, "ALES_AUDIT_EXPORT_FILE not set: no off-database audit copy")
    else:
        err = _writable(export)
        report.add("audit_export", FAIL if err else PASS, err or f"{export!r} is writable")

    mode = settings.enforce_workloads
    report.add("workloads", PASS if mode == "strict" else WARN,
               f"ALES_ENFORCE_WORKLOADS={mode}" + ("" if mode == "strict" else
                                                  " (agents without a registered workload are not fully enforced)"
                                                  if mode == "auto" else " (agent_id is an unverified label)"))
    report.add("grants", PASS if settings.require_grants else WARN,
               "ALES_REQUIRE_GRANTS on" if settings.require_grants else "ALES_REQUIRE_GRANTS off (grants gate not pinned)")

    if auth is not None:
        unsafe = dev_unsafe_settings(settings, auth, url=url, key_material=key_material)
        if prod and settings.approval_allow_self:
            report.add("unsafe_settings", FAIL, "ALES_APPROVAL_ALLOW_SELF=1 disables approval separation of duties")
        elif unsafe:
            report.add("unsafe_settings", WARN, "; ".join(unsafe))
        else:
            report.add("unsafe_settings", PASS, "no unsafe development settings in effect")
    return report


def _report_auth(report: PreflightReport, auth: Authenticator) -> None:
    parts = []
    if auth.registry is not None and len(auth.registry):
        parts.append(f"{len(auth.registry)} static token(s)")
    if auth.oidc is not None:
        parts.append("OIDC" + (" (live JWKS)" if auth.oidc.remote is not None else " (static JWKS)")
                     + (", require_jti" if auth.oidc.require_jti else ""))
    if parts:
        report.add("authentication", PASS, ", ".join(parts))
    elif auth.allow_anonymous:
        report.add("authentication", WARN, "anonymous dev access only (every caller has all roles)")
    else:
        report.add("authentication", FAIL, "no tokens or OIDC configured: every protected route answers 503")


def _check_purge(report: PreflightReport, e: Mapping[str, str], settings: Settings, *, deep: bool = False) -> None:
    policy = settings.purge_policy
    issue = purge_policy_issue(e, settings)
    if issue:
        report.add("purge", FAIL, issue)
        return
    if policy == "deny-only":
        report.add("purge", WARN, "ALES_PURGE_POLICY=deny-only: use-time denial only; revoked bytes remain in stores "
                                  "until purged externally")
        return
    if not purge_targets_configured(e):
        # production: already a production_rule FAIL; here only the factual state
        report.add("purge", FAIL if settings.production else WARN,
                   "policy=purge but ALES_PURGE_TARGETS is not set: purge is LOG-ONLY, revoked bytes remain in stores")
        return
    try:
        wiring = build_purge_wiring(e)  # parses specs and checks ales_adapters + each target's client lib
    except ConfigError as exc:
        report.add("purge", FAIL, str(exc))
        return
    names = ",".join(wiring.target_names()) if wiring is not None else ""
    if not deep or wiring is None:
        report.add(
            "purge", PASS, f"policy=purge, targets importable: {names} (connections not tested; use --deep)"
        )
        return
    results = wiring.probe_targets()
    bad = {n: err for n, err in results.items() if err is not None}
    if bad:
        for n, err in sorted(bad.items()):
            report.add(f"purge_target_{n}", FAIL, f"unreachable: {err}")
    else:
        report.add("purge", PASS, f"policy=purge, all targets reachable: {names}")


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m ales_server.preflight", description=__doc__.split("\n\n")[0])
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument(
        "--deep", action="store_true", help="also open each purge-target store and perform one read round-trip"
    )
    args = ap.parse_args(argv)
    report = run_preflight(deep=args.deep)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.render())
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
