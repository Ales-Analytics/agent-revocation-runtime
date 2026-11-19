"""Filesystem source connector.

Registers every file under ``root_dir`` as a source envelope and turns file-system changes into
RevocationEvents:

* file deleted                 -> ``deleted``
* content changed              -> ``version_superseded`` (old version revoked, new version registered)
* ``<file>.acl.json`` narrowed -> ``acl_changed`` (old context revoked, re-registered with the new ACL)

A sidecar ``<file>.acl.json`` may hold ``{"classification", "principal_scope", "purpose_scope"}``.
Without it files are ``internal`` and unrestricted. State is kept in a JSON checkpoint so a restart
does not re-emit events or lose track of deleted files.

This connector only ingests and emits events; it cannot block reads (coverage: can_block n/a).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ales_sdk.client import InvariantClient
from ales_sdk.envelope import CLASSIFICATION_ORDER, new_source

SOURCE_SYSTEM = "filesystem"
ACL_SUFFIX = ".acl.json"
DEFAULT_ACL: dict[str, Any] = {"classification": "internal", "principal_scope": None, "purpose_scope": None}


def _acl_digest(acl: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(acl, sort_keys=True).encode()).hexdigest()[:16]


def _scope_loses(old: list[str] | None, new: list[str] | None) -> bool:
    """True if ``new`` grants access to fewer parties than ``old`` (None = unrestricted)."""
    if old is None:
        return new is not None
    if new is None:
        return False
    return bool(set(old) - set(new))


def acl_narrowed(old: dict[str, Any], new: dict[str, Any]) -> bool:
    if CLASSIFICATION_ORDER.index(new["classification"]) > CLASSIFICATION_ORDER.index(old["classification"]):
        return True
    return _scope_loses(old["principal_scope"], new["principal_scope"]) or _scope_loses(
        old["purpose_scope"], new["purpose_scope"]
    )


class FilesystemSourceConnector:
    def __init__(
        self,
        client: InvariantClient,
        root_dir: str | Path,
        tenant_id: str,
        checkpoint_path: str | Path | None = None,
    ) -> None:
        self.client = client
        self.root = Path(root_dir)
        self.tenant_id = tenant_id
        self.checkpoint_path = (
            Path(checkpoint_path) if checkpoint_path else self.root / ".ales_fs_checkpoint.json"
        )
        self.state: dict[str, dict[str, Any]] = {}
        if self.checkpoint_path.exists():
            self.state = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))

    def _files(self) -> dict[str, Path]:
        result: dict[str, Path] = {}
        for p in sorted(self.root.rglob("*")):
            if not p.is_file() or p.name.endswith(ACL_SUFFIX) or p == self.checkpoint_path:
                continue
            result[p.relative_to(self.root).as_posix()] = p
        return result

    @staticmethod
    def _read_acl(path: Path) -> dict[str, Any]:
        sidecar = path.with_name(path.name + ACL_SUFFIX)
        acl = dict(DEFAULT_ACL)
        if sidecar.exists():
            raw = json.loads(sidecar.read_text(encoding="utf-8"))
            for k in acl:
                if raw.get(k) is not None:
                    acl[k] = raw[k]
        return acl

    def _save(self) -> None:
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        self.checkpoint_path.write_text(json.dumps(self.state, indent=2, sort_keys=True), encoding="utf-8")

    def _register(self, rel: str, content: bytes, version: str, acl: dict[str, Any]) -> dict[str, Any]:
        env = new_source(
            self.tenant_id,
            rel,
            content,
            SOURCE_SYSTEM,
            object_version=version,
            classification=acl["classification"],
            principal_scope=acl["principal_scope"],
            purpose_scope=acl["purpose_scope"],
        )
        self.client.register_source(env)
        self.state[rel] = {
            "context_id": env["context_id"],
            "version": version,
            "digest": env["content_digest"],
            "acl": acl,
            "acl_digest": _acl_digest(acl),
        }
        return env

    def _revoke(self, entry: dict[str, Any], reason: str) -> dict[str, Any]:
        event = {
            "tenant_id": self.tenant_id,
            "source_id": entry["context_id"],
            "source_version": entry["version"],
            "reason": reason,
            "actor": "ales-fs-connector",
        }
        response = self.client.submit_revocation(event)
        return {
            **event,
            "event_id": response.get("event_id"),
            "revocation_epoch": response.get("revocation_epoch"),
        }

    def scan(self) -> list[dict[str, Any]]:
        """Register every file not yet tracked. Returns the envelopes registered."""
        registered = []
        for rel, path in self._files().items():
            if rel in self.state:
                continue
            content = path.read_bytes()
            version = hashlib.sha256(content).hexdigest()[:12]
            registered.append(self._register(rel, content, version, self._read_acl(path)))
        self._save()
        return registered

    def watch_once(self) -> list[dict[str, Any]]:
        """Diff the tree against the checkpoint and emit revocation events. Returns emitted events."""
        events: list[dict[str, Any]] = []
        files = self._files()

        for rel in sorted(set(self.state) - set(files)):
            events.append(self._revoke(self.state.pop(rel), "deleted"))

        for rel, path in files.items():
            entry = self.state.get(rel)
            if entry is None:
                continue  # new file: scan() below picks it up
            content = path.read_bytes()
            version = hashlib.sha256(content).hexdigest()[:12]
            acl = self._read_acl(path)
            if version != entry["version"]:
                events.append(self._revoke(entry, "version_superseded"))
                self._register(rel, content, version, acl)
            elif _acl_digest(acl) != entry["acl_digest"]:
                if acl_narrowed(entry["acl"], acl):
                    events.append(self._revoke(entry, "acl_changed"))
                self._register(rel, content, version, acl)

        self.scan()  # new files + persists checkpoint
        return events
