import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for _p in (ROOT / "sdk-python", ROOT / "sdk-python" / "tests", ROOT / "adapters"):
    sys.path.insert(0, str(_p))

for _p in (ROOT / "core", ROOT / "server"):  # appended: installed copies win; needed for end-to-end purge tests
    if str(_p) not in sys.path:
        sys.path.append(str(_p))

# Reuse the SDK FakeServer MockTransport and fixtures (server, clock, make_client).
from ales_sdk import new_source
from sdk_fixtures import FakeServer, clock, make_client, server  # noqa: F401

PRINCIPAL = {"type": "user", "id": "alice"}


@pytest.fixture
def client(make_client):  # noqa: F811
    return make_client()


@pytest.fixture
def src(client):
    """A registered source envelope."""
    env = new_source("t1", "doc-1", "hello", "test")
    client.register_source(env)
    return env
