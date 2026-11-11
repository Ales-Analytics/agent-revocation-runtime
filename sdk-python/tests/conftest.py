import json
import sys
import uuid
from pathlib import Path

import httpx
import jsonschema
import pytest

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


class FakeServer:
    """Scripted in-memory server. Flips derivatives to DENY once an ancestor source is revoked."""

    def __init__(self):
        self.epoch = 0
        self.policy_version = "p1"
        self.envelopes = {}
        self.revoked = set()
        self.requests = []
        self.down = False
        self.deny_all = False
        self.ignore_revocations = False

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
        body = json.loads(request.content) if request.content else None
        self.requests.append((request.method, path, body))
        if path == "/v1/healthz":
            return httpx.Response(200, json={"status": "ok"})
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
                if self.deny_all or r:
                    objs.append({"context_id": cid, "decision": "DENY", "reason": ["ANCESTOR_ACL_REVOKED"]})
                elif r is None:
                    objs.append({"context_id": cid, "decision": "UNKNOWN", "reason": ["OBJECT_UNKNOWN"]})
                else:
                    objs.append({"context_id": cid, "decision": "ALLOW", "reason": ["OK"]})
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

    def _make(**kw):
        kw.setdefault("clock", clock)
        return InvariantClient("http://ales.test", "t1", transport=server.transport(), **kw)

    return _make
