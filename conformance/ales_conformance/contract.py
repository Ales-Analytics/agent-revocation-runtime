"""The adapter conformance contract.

An enforcing adapter is exercised through a tiny ``Subject`` protocol::

    ingest(parents) -> ObjectRef          # store something derived from the parent envelopes
    read(ref, principal) -> ReadOutcome   # value-or-None plus whether/why it was blocked

``AdapterConformance`` registers two sources, ingests one object from each, revokes the first source
and checks the five contract clauses (a)-(e). ``IngestionConformance`` is the analogous contract for
source connectors that can only emit events (they are labelled INGESTION_ONLY, never ENFORCING).
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ales_sdk import InvariantClient, new_source

KNOWN_REASON_CODES = frozenset(
    {
        "ANCESTOR_ACL_REVOKED",
        "ANCESTOR_DELETED",
        "ANCESTOR_SUPERSEDED",
        "ANCESTOR_EXPIRED",
        "ANCESTOR_QUARANTINED",
        "PRINCIPAL_NOT_IN_SCOPE",
        "PURPOSE_NOT_IN_SCOPE",
        "LINEAGE_INCOMPLETE",
        "OBJECT_UNKNOWN",
        "TENANT_MISMATCH",
        "POLICY_SNAPSHOT_STALE",
        "OK",
    }
)


@dataclass
class ObjectRef:
    context_id: str
    handle: Any = None


@dataclass
class ReadOutcome:
    value: Any | None
    blocked: bool = False
    reasons: list[str] = field(default_factory=list)


class Subject(Protocol):
    name: str

    def ingest(self, parents: Sequence[Mapping[str, Any]]) -> ObjectRef: ...

    def read(self, ref: ObjectRef, principal: Mapping[str, str]) -> ReadOutcome: ...


@dataclass
class CheckResult:
    id: str
    name: str
    passed: bool
    detail: str = ""


@dataclass
class ConformanceReport:
    adapter: str
    checks: list[CheckResult]
    passed: bool
    enforcement_level: str

    @property
    def checks_passed(self) -> int:
        return sum(1 for c in self.checks if c.passed)

    @property
    def summary(self) -> str:
        return f"{self.checks_passed}/{len(self.checks)}"


class AdapterConformance:
    """Run the enforcement contract against a subject."""

    TENANT_PURPOSE = "conformance"

    def __init__(self, subject: Subject, client: InvariantClient, principal: Mapping[str, str] | None = None):
        self.subject = subject
        self.client = client
        self.principal = dict(principal or {"type": "user", "id": "conformance-user"})

    def run(self) -> ConformanceReport:
        s, c, p = self.subject, self.client, self.principal
        checks: list[CheckResult] = []

        def add(cid: str, name: str, ok: bool, detail: str = "") -> bool:
            checks.append(CheckResult(cid, name, bool(ok), detail))
            return bool(ok)

        tid = c.tenant_id
        revoked_src = new_source(
            tid,
            f"conf/{s.name}/revoked",
            f"{s.name} revoked body",
            "conformance",
            classification="confidential",
        )
        other_src = new_source(
            tid, f"conf/{s.name}/other", f"{s.name} other body", "conformance", classification="confidential"
        )
        c.register_source(revoked_src)
        c.register_source(other_src)
        try:
            ref_rev = s.ingest([revoked_src])
            ref_other = s.ingest([other_src])
        except Exception as e:  # noqa: BLE001
            add("setup", "subject ingests derived objects", False, f"{type(e).__name__}: {e}")
            return ConformanceReport(s.name, checks, False, "NON_ENFORCING")

        pre = s.read(ref_rev, p)
        add(
            "a",
            "pre-revocation read allowed",
            pre.value is not None and not pre.blocked,
            f"value={'set' if pre.value is not None else None} blocked={pre.blocked}",
        )

        c.submit_revocation(
            {"source_id": revoked_src["context_id"], "reason": "acl_changed", "actor": "conformance"}
        )
        post = s.read(ref_rev, p)
        b_ok = add(
            "b",
            "post-revocation read blocked",
            post.value is None and post.blocked,
            f"value={'LEAKED' if post.value is not None else None} blocked={post.blocked}",
        )
        add(
            "c",
            "blocked read carries a reason code",
            bool(post.reasons)
            and set(post.reasons) <= KNOWN_REASON_CODES
            and "ANCESTOR_ACL_REVOKED" in post.reasons,
            str(post.reasons),
        )

        again = [s.read(ref_rev, p) for _ in range(3)]
        add(
            "d",
            "re-read after block stays blocked (no resurrection)",
            all(r.value is None for r in again),
            f"values={[r.value is not None for r in again]}",
        )

        control = s.read(ref_other, p)
        add(
            "e",
            "other-source read unaffected (no over-blocking)",
            control.value is not None and not control.blocked,
            f"blocked={control.blocked}",
        )

        passed = all(ch.passed for ch in checks)
        level = "ENFORCING" if passed else ("PARTIAL" if b_ok else "NON_ENFORCING")
        return ConformanceReport(s.name, checks, passed, level)


class IngestionConformance:
    """Event-emission contract for source connectors (cannot block; label INGESTION_ONLY).

    ``factory(client, root: Path)`` returns a connector exposing ``scan()`` and ``watch_once()``.
    """

    def __init__(self, name: str, client: InvariantClient, factory: Callable[[InvariantClient, Path], Any]):
        self.name = name
        self.client = client
        self.factory = factory

    def run(self) -> ConformanceReport:
        checks: list[CheckResult] = []

        def add(cid: str, label: str, ok: bool, detail: str = "") -> None:
            checks.append(CheckResult(cid, label, bool(ok), detail))

        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "root"
            root.mkdir()
            (root / "gone.txt").write_text("to be deleted")
            (root / "changed.txt").write_text("version one")
            (root / "acl.txt").write_text("acl body")
            (root / "acl.txt.acl.json").write_text(json.dumps({"principal_scope": ["alice", "bob"]}))
            (root / "stable.txt").write_text("never changes")
            conn = self.factory(self.client, Path(td))
            envs = {e["object_id"]: e for e in conn.scan()}
            add(
                "i1",
                "scan registers every file as a source",
                set(envs) == {"gone.txt", "changed.txt", "acl.txt", "stable.txt"}
                and all(e["kind"] == "source" for e in envs.values()),
                str(sorted(envs)),
            )
            seen: list[dict[str, Any]] = []
            add("i2", "unchanged tree emits no events", conn.watch_once() == [])

            (root / "gone.txt").unlink()
            ev = conn.watch_once()
            seen.extend(ev)
            add(
                "i3",
                "delete emits a deleted event for the source",
                len(ev) == 1
                and ev[0]["reason"] == "deleted"
                and ev[0]["source_id"] == envs["gone.txt"]["context_id"],
                str([e["reason"] for e in ev]),
            )

            (root / "changed.txt").write_text("version two")
            ev = conn.watch_once()
            seen.extend(ev)
            add(
                "i4",
                "content change emits version_superseded for the old version",
                len(ev) == 1
                and ev[0]["reason"] == "version_superseded"
                and ev[0].get("source_version") == envs["changed.txt"]["object_version"],
                str([e["reason"] for e in ev]),
            )

            (root / "acl.txt.acl.json").write_text(json.dumps({"principal_scope": ["alice"]}))
            ev = conn.watch_once()
            seen.extend(ev)
            add(
                "i5",
                "ACL narrowing emits acl_changed",
                len(ev) == 1 and ev[0]["reason"] == "acl_changed",
                str([e["reason"] for e in ev]),
            )

            add(
                "i6",
                "emitted events were accepted by the control plane",
                len(seen) == 3 and all(e.get("revocation_epoch") is not None for e in seen),
                f"{len(seen)} events",
            )
        passed = all(c.passed for c in checks)
        return ConformanceReport(self.name, checks, passed, "INGESTION_ONLY" if passed else "FAILED")
