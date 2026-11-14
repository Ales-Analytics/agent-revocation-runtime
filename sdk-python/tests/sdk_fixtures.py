import base64
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx
import jsonschema
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "sdk-python"))

SPEC = ROOT / "spec"


def _load(name):
    return json.loads((SPEC / name).read_text(encoding="utf-8"))


ENVELOPE_SCHEMA = _load("context_envelope.schema.json")
REVOCATION_SCHEMA = _load("revocation_event.schema.json")
_DECISION = _load("decision_api.schema.json")


def _def_validator(name):
    schema = {"$defs": _DECISION["$defs"], "$ref": f"#/$defs/{name}"}
    return jsonschema.Draft202012Validator(schema)


REQ_VALIDATOR = _def_validator("AuthorizeRequest")
RESP_VALIDATOR = _def_validator("AuthorizeResponse")
ENV_VALIDATOR = jsonschema.Draft202012Validator(ENVELOPE_SCHEMA)
REV_VALIDATOR = jsonschema.Draft202012Validator(REVOCATION_SCHEMA)

DEFAULT_TOKEN = "test-token"


def _canonical(payload):
    """Mirror of ales_sdk.snapshot.canonical_bytes, written independently on purpose."""
    obj = {k: v for k, v in payload.items() if k not in ("signature", "key_id")}
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class FakeServer:
    """Scripted in-memory server. Flips derivatives to DENY once an ancestor source is revoked.

    By default every request is accepted regardless of credentials (backwards compatible). Set
    ``strict_auth = True`` to require ``Authorization: Bearer <token>`` where the token must be a
    key of ``tokens`` (token -> tenant) and the tenant must match ``X-Tenant-Id``/body tenant.
    """

    def __init__(self):
        self.epoch = 0
        self.policy_version = "p1"
        self.envelopes = {}
        self.revoked = set()
        self.requests = []  # (method, path, body) -- shape relied upon by adapters/tests
        self.headers_log = []  # parallel to ``requests``: dict of request headers
        self.down = False
        self.deny_all = False
        self.valid_until = None  # RFC3339 str: stamped on ALLOW verdicts + response (pending revocation)
        self.ignore_revocations = False
        # opt-in version awareness: echo each requested version on its verdict, and DENY any
        # (context_id, version) listed in ``revoked_versions``. Off by default (legacy behaviour).
        self.version_aware = False
        self.revoked_versions = set()
        self.latest_versions = {}  # cid -> version echoed when a request omits the version
        self.deny_agents = set()  # agent_ids whose requests are DENYed (agent-aware decisions)
        # auth
        self.strict_auth = False
        self.tokens = {DEFAULT_TOKEN: "t1"}
        # snapshot
        self._signing_key = Ed25519PrivateKey.generate()
        self.public_key_b64 = base64.b64encode(
            self._signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()
        self.lease_seconds = 300
        self.snapshot_tenant = None  # None -> the requesting tenant
        self.snapshot_epoch = None  # None -> current epoch
        self.snapshot_issued_at = None  # None -> now
        self.corrupt_snapshot_signature = False
        self.snapshot_extra = {}  # unsigned tampering applied AFTER signing
        self.snapshot_status = 200
        # fault injection: path -> (remaining, status or None for connection error)
        self._faults = {}

    def fail_next(self, path, n=1, status=None):
        """Make the next ``n`` requests to ``path`` fail (connection error, or ``status``)."""
        self._faults[path] = [n, status]

    # -- snapshot ----------------------------------------------------------------------------
    def sign(self, payload):
        sig = self._signing_key.sign(_canonical(payload))
        return {**payload, "signature": base64.b64encode(sig).decode(), "key_id": "test-key"}

    def make_snapshot(self, tenant):
        payload = {
            "tenant_id": self.snapshot_tenant or tenant,
            "revocation_epoch": self.epoch if self.snapshot_epoch is None else self.snapshot_epoch,
            "policy_version": self.policy_version,
            "issued_at": self.snapshot_issued_at or datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "lease_seconds": self.lease_seconds,
        }
        snap = self.sign(payload)
        if self.corrupt_snapshot_signature:
            raw = bytearray(base64.b64decode(snap["signature"]))
            raw[0] ^= 0xFF
            snap["signature"] = base64.b64encode(bytes(raw)).decode()
        snap.update(self.snapshot_extra)
        return snap

    # -- auth --------------------------------------------------------------------------------
    def _check_auth(self, request, body):
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] not in self.tokens:
            return httpx.Response(401, json={"detail": "invalid or missing bearer token"})
        tenant = self.tokens[auth[7:]]
        claimed = {request.headers.get("x-tenant-id")}
        if isinstance(body, dict) and "tenant_id" in body:
            claimed.add(body["tenant_id"])
        if claimed - {None, tenant}:
            return httpx.Response(403, json={"detail": "tenant mismatch: token is bound to another tenant"})
        return None

    def _root_revoked(self, cid):
        env = self.envelopes.get(cid)
        if env is None:
            return None
        if cid in self.revoked and not self.ignore_revocations:
            return True
        return any(self._root_revoked(p["context_id"]) for p in env["parent_refs"])

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("down", request=request)
        path = request.url.path
        fault = self._faults.get(path)
        if fault and fault[0] > 0:
            fault[0] -= 1
            if fault[1] is None:
                raise httpx.ConnectError("injected fault", request=request)
            return httpx.Response(fault[1], json={"detail": "injected fault"})
        body = json.loads(request.content) if request.content else None
        self.requests.append((request.method, path, body))
        self.headers_log.append(dict(request.headers))
        if self.strict_auth and path not in ("/v1/healthz", "/v1/readyz"):
            denied = self._check_auth(request, body)
            if denied is not None:
                return denied
        if path == "/v1/healthz":
            return httpx.Response(200, json={"status": "ok"})
        if path == "/v1/snapshot":
            if self.snapshot_status != 200:
                return httpx.Response(self.snapshot_status, json={"detail": "no snapshot"})
            return httpx.Response(200, json=self.make_snapshot(request.headers.get("x-tenant-id", "t1")))
        if path in ("/v1/sources", "/v1/derivations"):
            ENV_VALIDATOR.validate(body)
            self.envelopes[body["context_id"]] = body
            return httpx.Response(
                201, json={"context_id": body["context_id"], "object_version": body["object_version"]}
            )
        if path == "/v1/revocations":
            REV_VALIDATOR.validate(body)
            self.revoked.add(body["source_id"])
            self.epoch += 1
            return httpx.Response(202, json={"event_id": body["event_id"], "revocation_epoch": self.epoch})
        if path == "/v1/authorize":
            REQ_VALIDATOR.validate(body)
            objs = []
            for o in body["objects"]:
                r = self._root_revoked(o["context_id"])
                cid = o["context_id"]
                ver = o.get("version")
                if self.version_aware and ver is None:
                    ver = self.latest_versions.get(cid)
                vrev = self.version_aware and (cid, ver) in self.revoked_versions
                if self.deny_all or r or vrev or body.get("agent_id") in self.deny_agents:
                    objs.append({"context_id": cid, "decision": "DENY", "reason": ["ANCESTOR_ACL_REVOKED"]})
                elif r is None:
                    objs.append({"context_id": cid, "decision": "UNKNOWN", "reason": ["OBJECT_UNKNOWN"]})
                else:
                    objs.append({"context_id": cid, "decision": "ALLOW", "reason": ["OK"]})
                    if self.valid_until is not None:
                        objs[-1]["valid_until"] = self.valid_until
            if self.version_aware:
                for o, v in zip(objs, body["objects"], strict=True):
                    ver = v.get("version") or self.latest_versions.get(o["context_id"])
                    if ver is not None:
                        o["version"] = ver
            decs = {o["decision"] for o in objs}
            overall = "ALLOW" if decs == {"ALLOW"} else ("DENY" if "DENY" in decs else "UNKNOWN")
            resp = {
                "decision": overall,
                "reason": sorted({r for o in objs for r in o["reason"]}),
                "revocation_epoch": self.epoch,
                "policy_version": self.policy_version,
                "trace_id": uuid.uuid4().hex,
                "objects": objs,
            }
            if self.valid_until is not None:
                resp["valid_until"] = self.valid_until
            RESP_VALIDATOR.validate(resp)
            return httpx.Response(200, json=resp)
        if path.startswith("/v1/lineage/"):
            return httpx.Response(200, json={"context_id": path.rsplit("/", 1)[1], "ancestors": []})
        if path == "/v1/verify":
            return httpx.Response(200, json={"adapter": body["adapter"], "passed": True})
        return httpx.Response(404, json={"error": "not found"})

    def transport(self):
        return httpx.MockTransport(self.handler)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def server():
    return FakeServer()


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def make_client(server, clock):
    from ales_sdk import InvariantClient

    sleeps = []

    def _make(**kw):
        kw.setdefault("clock", clock)
        kw.setdefault("auth_token", DEFAULT_TOKEN)
        kw.setdefault("snapshot_public_key", server.public_key_b64)
        kw.setdefault("sleep", sleeps.append)  # retries never really sleep in tests
        return InvariantClient("http://ales.test", "t1", transport=server.transport(), **kw)

    _make.sleeps = sleeps
    return _make
