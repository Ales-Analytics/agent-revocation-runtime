"""Shared helpers for the server test-suite (not a conftest: imported by name)."""

from __future__ import annotations

import base64
import sys
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sdk-python"))
sys.path.insert(0, str(ROOT / "server"))

from ales_core import ContextEnvelope, RevocationEvent, sign_model
from ales_sdk import new_derivative, new_source

ALL = ["ingest", "revoke", "read", "admin"]
P = {"type": "user", "id": "alice"}

TOKENS = {
    "tok-t1-all": {"tenant_id": "t1", "roles": ALL, "subject": "svc-t1"},
    "tok-t1-read": {"tenant_id": "t1", "roles": ["read"], "subject": "reader-t1"},
    "tok-t1-ingest": {"tenant_id": "t1", "roles": ["ingest"], "subject": "ingester-t1"},
    "tok-t1-revoke": {"tenant_id": "t1", "roles": ["revoke"], "subject": "revoker-t1"},
    "tok-t1-admin": {"tenant_id": "t1", "roles": ["admin"], "subject": "admin-t1"},
    "tok-t2-all": {"tenant_id": "t2", "roles": ALL, "subject": "svc-t2"},
}


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


T1 = bearer("tok-t1-all")
T2 = bearer("tok-t2-all")


def pub_b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def seed_b64(key: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat

    return base64.b64encode(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()


def chain(tenant: str = "t1", classification: str = "confidential"):
    src = new_source(tenant, "doc", b"secret", "kb", classification=classification)
    chunk = new_derivative("chunk", [src], tenant, "chunk", b"c")
    summ = new_derivative("summary", [chunk], tenant, "summary", b"s")
    return src, chunk, summ


def sign_env(env: dict, key: Ed25519PrivateKey, key_id: str) -> dict:
    model = sign_model(ContextEnvelope.model_validate(env), key, key_id)
    return model.model_dump(mode="json")


def sign_event(event: dict, key: Ed25519PrivateKey, key_id: str) -> dict:
    model = sign_model(RevocationEvent.model_validate(event), key, key_id)
    return model.model_dump(mode="json")


def authorize_body(tenant: str, context_id: str, purpose: str = "rag") -> dict:
    return {"tenant_id": tenant, "principal": P, "purpose": purpose, "objects": [{"context_id": context_id}]}


class TestClientTransport(httpx.BaseTransport):
    """Sync httpx transport routing SDK requests into a TestClient; ``down`` simulates an outage."""

    __test__ = False

    def __init__(self, tc: TestClient):
        self.tc = tc
        self.down = False

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("simulated outage", request=request)
        headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")}
        resp = self.tc.request(request.method, str(request.url), content=request.content, headers=headers)
        out_headers = [
            (k, v)
            for k, v in resp.headers.items()
            if k.lower() not in ("content-encoding", "transfer-encoding", "content-length")
        ]
        return httpx.Response(resp.status_code, headers=out_headers, content=resp.content, request=request)


class FakeClock:
    def __init__(self, start: float = 1000.0):
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds
