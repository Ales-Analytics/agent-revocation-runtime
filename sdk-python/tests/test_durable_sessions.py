"""Durable session exposures in the SDK (opt-in): reporting, best-effort retry, handoff, reset."""

from __future__ import annotations

import json

import httpx
import pytest
from ales_sdk import InvariantClient
from ales_sdk.errors import AlesConnectionError, InvalidRequestError
from ales_sdk.handoff import handoff
from ales_sdk.session_taint import SessionTaint

ALICE = {"type": "user", "id": "alice"}


class Recorder:
    """httpx transport that records requests and answers the session endpoints."""

    def __init__(self):
        self.calls: list[tuple[str, str, dict | None]] = []
        self.fail = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.calls.append((request.method, request.url.path, body))
        if self.fail:
            raise httpx.ConnectError("down", request=request)
        if request.url.path == "/v1/handoffs":
            return httpx.Response(200, json={"decision": "ALLOW", "reason": ["OK"]})
        if request.url.path.endswith("/exposures"):
            return httpx.Response(
                200, json={"recorded": len(body["exposures"]), "session_id": "s", "generation": 0,
                           "needs_reset": False, "exposure_count": len(body["exposures"])},
            )
        if request.url.path.endswith("/reset"):
            return httpx.Response(200, json={"session_id": "s", "generation": 1, "needs_reset": False})
        return httpx.Response(200, json={"session_id": "s", "generation": 0, "needs_reset": True,
                                         "exposure_count": 2})


def make(rec: Recorder, **kw) -> InvariantClient:
    return InvariantClient(
        "http://ales.test", "t1", auth_token="tok", transport=httpx.MockTransport(rec), max_retries=0,
        breaker_threshold=0, **kw,
    )


def test_default_mode_never_calls_the_server_for_sessions():
    rec = Recorder()
    c = make(rec)
    c.session_taint.record("s", [("c1", "v1")], principal=ALICE, purpose="rag")
    assert rec.calls == [] and not c.session_taint.durable


def test_durable_record_reports_grouped_by_principal_and_workload():
    rec = Recorder()
    c = make(rec, durable_sessions=True)
    assert c.session_taint.durable
    c.session_taint.record("s", [("c1", "v1"), ("c2", None)], principal=ALICE, purpose="rag", workload="agent-1")
    c.session_taint.record("s", ["c3"], principal={"type": "agent", "id": "bot"}, purpose="rag")
    posts = [(p, b) for m, p, b in rec.calls if m == "POST"]
    assert [p for p, _ in posts] == ["/v1/sessions/s/exposures"] * 2
    assert posts[0][1] == {
        "principal": {"type": "user", "id": "alice"}, "workload": "agent-1",
        "exposures": [{"context_id": "c1", "version": "v1"}, {"context_id": "c2", "version": None}],
    }
    assert posts[1][1]["principal"] == {"type": "agent", "id": "bot"} and "workload" not in posts[1][1]
    # the exposure is only reported once
    c.session_taint.flush("s")
    assert len([1 for m, *_ in rec.calls if m == "POST"]) == 2
    # local enforce() data is unchanged by durable mode
    assert {e.context_id for e in c.session_taint.exposures_for("s")} == {"c1", "c2", "c3"}


def test_failed_report_stays_pending_and_never_raises_on_the_hot_path():
    rec = Recorder()
    c = make(rec, durable_sessions=True)
    rec.fail = True
    c.session_taint.record("s", [("c1", "v1")], principal=ALICE, purpose="rag")  # must not raise
    assert c.session_taint.last_report_error and "AlesConnectionError" in c.session_taint.last_report_error
    assert c.session_taint.contexts_for("s") == {"c1"}  # local record intact
    rec.fail = False
    c.session_taint.record("s", [("c2", "v1")], principal=ALICE, purpose="rag")
    assert c.session_taint.last_report_error is None
    last = [b for m, p, b in rec.calls if m == "POST" and p.endswith("/exposures")][-1]
    assert {e["context_id"] for e in last["exposures"]} == {"c1", "c2"}  # the earlier one was retried


def test_explicit_report_skips_principalless_exposures_unless_supplied():
    rec = Recorder()
    c = make(rec)
    c.session_taint.record("s", ["bare"])  # no principal recorded
    c.session_taint.record("s", [("c1", "v1")], principal=ALICE, purpose="rag")
    res = SessionTaint.report(c.session_taint, c, "s")
    assert (res.reported, res.skipped) == (1, 1)
    res = c.session_taint.report(c, "s", principal={"type": "service", "id": "gw"})
    assert (res.reported, res.skipped) == (2, 0)
    rec.fail = True
    with pytest.raises(AlesConnectionError):  # explicit form raises the client's errors
        c.session_taint.report(c, "s", principal=ALICE)


def test_handoff_records_receiver_side_exposure_when_durable():
    rec = Recorder()
    c = make(rec, durable_sessions=True)
    c.session_taint.record("sender", [("c1", "v1")], principal=ALICE, purpose="rag")
    rec.calls.clear()
    result = handoff(c, "sender", "receiver", from_workload="a", to_workload="b", purpose="rag")
    assert result.exposures_copied == 1
    posts = [p for m, p, _ in rec.calls if m == "POST"]
    assert "/v1/handoffs" in posts and "/v1/sessions/receiver/exposures" in posts
    assert "/v1/sessions/sender/exposures" not in posts  # the sender was already reported at record time


def test_session_helpers_and_reset_clears_local_record():
    rec = Recorder()
    c = make(rec)
    assert c.session_exposures("s")["needs_reset"] is True
    c.session_taint.record("s", ["c1"], principal=ALICE, purpose="rag")
    assert c.reset_session("s")["generation"] == 1
    assert c.session_taint.contexts_for("s") == set()
    with pytest.raises(InvalidRequestError):
        c.report_session_exposures("s", ALICE, [])
    with pytest.raises(InvalidRequestError):
        c.report_session_exposures("s", {"type": "user"}, ["c1"])
    assert ("GET", "/v1/sessions/s", None) in rec.calls
