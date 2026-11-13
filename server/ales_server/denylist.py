"""DB-free credential denylist and a cheap mtime watcher shared with the token-file hot reload.

Emergency identity revocation without a restart or a database round trip: ``ALES_DENYLIST_FILE``
is a JSON object ``{"subjects": [...], "jwt_subs": [...], "jwt_jtis": [...], "key_ids": [...]}``.

* ``subjects``: any authenticated identity (static token or OIDC) whose subject is listed gets 401.
* ``jwt_subs``: like ``subjects`` but matched only against OIDC tokens (the mapped subject claim).
* ``jwt_jtis``: per-token revocation: an OIDC token whose ``jti`` claim is listed gets 401 even though its
  signature, ``exp`` and subject are fine. Tokens without a ``jti`` are unaffected unless the OIDC config sets
  ``"require_jti": true``.
* ``key_ids``: accepted for forward compatibility but NOT enforced here; revoke issuer keys with
  ``PATCH /v1/admin/keys/{key_id}`` (``status: revoked``). A non-empty list logs a warning.

The file is stat-ed at request time but at most once per ``interval`` seconds (default 5); only a
changed ``(mtime_ns, size)`` triggers a re-read. A malformed or unreadable file on a *reload* is
logged and the last good content stays in force (an operator typo must not silently un-deny a
subject, nor lock everyone out). A malformed file at *startup* is a :class:`ConfigError`.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path

from .config import ConfigError

log = logging.getLogger("ales.server.denylist")

RELOAD_INTERVAL = 5.0  # seconds between stat() calls; the credential-revocation propagation bound


class FileWatch:
    """Detects changes of one file by ``(st_mtime_ns, st_size)``, polling at most once per ``interval``."""

    def __init__(self, path: str, *, interval: float = RELOAD_INTERVAL, clock: Callable[[], float] = time.monotonic):
        self.path = path
        self.interval = interval
        self.clock = clock
        self._lock = threading.Lock()
        self._last = clock()
        self._sig: tuple[int, int] | None = self._stat()

    def set_clock(self, clock: Callable[[], float]) -> None:
        """Swap the time source (tests) and restart the poll interval from now."""
        with self._lock:
            self.clock = clock
            self._last = clock()

    def _stat(self) -> tuple[int, int] | None:
        try:
            st = os.stat(self.path)
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size)

    def changed(self) -> bool:
        """True (once) when the file differs from what was last seen. Cheap: a stat at most every interval."""
        now = self.clock()
        with self._lock:
            if now - self._last < self.interval:
                return False
            self._last = now
            sig = self._stat()
            if sig == self._sig:
                return False
            self._sig = sig
            return True


def parse_denylist(text: str, source: str) -> tuple[frozenset[str], frozenset[str], frozenset[str], frozenset[str]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{source} is not valid JSON: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{source} must be a JSON object")
    out: list[frozenset[str]] = []
    for key in ("subjects", "jwt_subs", "key_ids", "jwt_jtis"):
        val = data.get(key, [])
        if not isinstance(val, list) or not all(isinstance(v, str) and v for v in val):
            raise ConfigError(f"{source}: {key!r} must be a list of non-empty strings")
        out.append(frozenset(val))
    return out[0], out[1], out[2], out[3]


class Denylist:
    def __init__(
        self,
        path: str,
        *,
        interval: float = RELOAD_INTERVAL,
        clock: Callable[[], float] = time.monotonic,
        on_reload: Callable[[str], None] | None = None,
    ):
        self.path = path
        self._on_reload = on_reload or (lambda _outcome: None)
        self.subjects: frozenset[str]
        self.jwt_subs: frozenset[str]
        self.key_ids: frozenset[str]
        self.jwt_jtis: frozenset[str]
        self._load(startup=True)
        self._watch = FileWatch(path, interval=interval, clock=clock)

    @property
    def clock(self) -> Callable[[], float]:
        return self._watch.clock

    @clock.setter
    def clock(self, value: Callable[[], float]) -> None:
        self._watch.set_clock(value)

    def _load(self, *, startup: bool) -> None:
        try:
            text = Path(self.path).read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"cannot read ALES_DENYLIST_FILE {self.path!r}: {exc}") from exc
        subjects, jwt_subs, key_ids, jwt_jtis = parse_denylist(text, "ALES_DENYLIST_FILE")
        if key_ids:
            log.warning(
                "ALES_DENYLIST_FILE key_ids are not enforced; revoke issuer keys with "
                "PATCH /v1/admin/keys/{key_id} status=revoked"
            )
        self.subjects, self.jwt_subs, self.key_ids, self.jwt_jtis = subjects, jwt_subs, key_ids, jwt_jtis
        if not startup:
            log.warning("denylist reloaded: %d subject(s), %d jwt sub(s), %d jwt jti(s)", len(subjects), len(jwt_subs), len(jwt_jtis))

    def refresh(self) -> None:
        if not self._watch.changed():
            return
        try:
            self._load(startup=False)
            self._on_reload("ok")
        except ConfigError as exc:
            log.error("denylist reload failed, keeping the last good content: %s", exc)
            self._on_reload("error")

    def denies(self, subject: str, *, jwt: bool = False) -> bool:
        self.refresh()
        return subject in self.subjects or (jwt and subject in self.jwt_subs)

    def denies_jti(self, jti: str | None) -> bool:
        self.refresh()
        return jti is not None and jti in self.jwt_jtis
