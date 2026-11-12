import sys
from pathlib import Path

# server/ and sdk-python/ are not installed as importable packages in every environment.
_ROOT = Path(__file__).resolve().parents[2]
for _p in (_ROOT / "sdk-python", _ROOT / "server"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import pytest
from ales_server import create_app
from fastapi.testclient import TestClient
from server_helpers import T1, TOKENS


@pytest.fixture
def make_client():
    """Factory: ``make_client(**create_app_kwargs)`` -> TestClient with the standard token map."""
    opened: list[TestClient] = []

    def _make(database_url: str = "sqlite://", **kw) -> TestClient:
        kw.setdefault("tokens", TOKENS)
        kw.setdefault("outbox_interval", 0)
        tc = TestClient(create_app(database_url, **kw), headers=dict(T1))
        tc.__enter__()
        opened.append(tc)
        return tc

    yield _make
    for tc in opened:
        tc.__exit__(None, None, None)


@pytest.fixture
def client(make_client):
    """Authenticated (tenant t1, all roles) client on a fresh in-memory DB."""
    return make_client()
