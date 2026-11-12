import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for _p in (ROOT / "sdk-python", ROOT / "sdk-python" / "tests", ROOT / "connectors"):
    sys.path.insert(0, str(_p))

# Reuse the SDK FakeServer MockTransport and fixtures (server, clock, make_client).
from sdk_fixtures import FakeServer, clock, make_client, server  # noqa: F401


@pytest.fixture
def client(make_client):  # noqa: F811
    return make_client()


def revocations(fake):
    return [b for m, p, b in fake.requests if p == "/v1/revocations"]


def reasons(events):
    return [e["reason"] for e in events]
