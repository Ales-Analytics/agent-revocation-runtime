"""Worker handler labelling: log-only default vs real purge handlers (and a Mapping passed to create_app)."""

from __future__ import annotations

from collections.abc import Iterator, Mapping

from ales_server import create_app
from ales_server.worker import handlers_mode, log_only_handler
from fastapi.testclient import TestClient
from server_helpers import T1, TOKENS


def _purge_handler(*names: str):
    def h(row):  # pragma: no cover - never dispatched here
        return None

    h.purge_targets = list(names)  # type: ignore[attr-defined]
    return h


class _RegistryLike(Mapping):
    """Duck-typed stand-in for ales_adapters.PurgeRegistry (a Mapping of kind -> handler)."""

    def __init__(self) -> None:
        self._h = {"chunk": _purge_handler("vector"), "cache": _purge_handler("cache", "vector")}

    def __getitem__(self, k):
        return self._h[k]

    def __iter__(self) -> Iterator[str]:
        return iter(self._h)

    def __len__(self) -> int:
        return len(self._h)


def test_handlers_mode_labels():
    assert handlers_mode({"*": log_only_handler}) == "log_only"
    assert handlers_mode({}) == "log_only"
    assert handlers_mode({"*": lambda r: None}) == "custom"
    assert handlers_mode({"chunk": _purge_handler("vector"), "cache": _purge_handler("cache")}) == "purge:cache,vector"
    # a mix of real purge handlers and an unlabelled one is reported as custom, not as purge
    assert handlers_mode({"chunk": _purge_handler("vector"), "x": lambda r: None}) == "custom"


def test_stats_reports_purge_handler_names_when_registry_wired():
    app = create_app("sqlite://", tokens=TOKENS, outbox_interval=0, outbox_handlers=_RegistryLike())
    stats = TestClient(app).get("/v1/outbox/stats", headers=T1).json()
    assert stats["worker"]["handlers"] == "purge:cache,vector"


def test_stats_default_remains_log_only():
    app = create_app("sqlite://", tokens=TOKENS, outbox_interval=0)
    assert TestClient(app).get("/v1/outbox/stats", headers=T1).json()["worker"]["handlers"] == "log_only"
