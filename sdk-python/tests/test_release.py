"""SDK release gate client (``authorize_release``): contract, fail modes, no caching."""

from __future__ import annotations

import json

import httpx
import pytest
from ales_sdk import (
    AlesHTTPError,
    HumanReviewPending,
    InvalidRequestError,
    InvariantClient,
    ReleaseDenied,
    ReleaseReceipt,
)

P = {"type": "user", "id": "alice"}


def receipt(decision="ALLOW", reason=None):
    return {
        "receipt_id": "11111111-1111-1111-1111-111111111111",
        "decision": decision,
        "reason": reason or (["OK"] if decision == "ALLOW" else ["RELEASE_DENIED", "EXTERNAL_POLICY_DENIED"]),
        "valid_until": "2099-01-01T00:00:00.000000Z",
        "revocation_epoch": 3,
        "policy_version": "p0",
    }


def make(handler, **kw):
    seen: list[httpx.Request] = []

    def h(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return handler(req)

    c = InvariantClient("http://ales.test", "t1", auth_token="tok", transport=httpx.MockTransport(h),
                        sleep=lambda s: None, **kw)
    return c, seen


def test_allow_sends_spec_body_and_returns_receipt():
    c, seen = make(lambda r: httpx.Response(200, json=receipt()))
    rc = c.authorize_release(P, "send_email", "mail:a.com", "outreach", ["c1", ("c2", "v2")],
                             workload="mailer", session_id="s1")
    assert isinstance(rc, ReleaseReceipt) and rc.allowed and rc.revocation_epoch == 3 and not rc.synthesised
    body = json.loads(seen[0].content)
    assert seen[0].url.path == "/v1/releases" and seen[0].method == "POST"
    assert body == {
        "principal": P, "action": "send_email", "destination": "mail:a.com", "purpose": "outreach",
        "objects": [{"context_id": "c1"}, {"context_id": "c2", "version": "v2"}],
        "workload": "mailer", "session_id": "s1",
    }


def test_never_cached_every_call_hits_server():
    c, seen = make(lambda r: httpx.Response(200, json=receipt()))
    for _ in range(3):
        c.authorize_release(P, "a", "d", "p", ["c1"])
    assert len(seen) == 3


def test_deny_raises_under_enforce_with_reasons_and_receipt():
    c, _ = make(lambda r: httpx.Response(200, json=receipt("DENY")))
    with pytest.raises(ReleaseDenied) as ei:
        c.authorize_release(P, "a", "d", "p", ["c1"])
    assert ei.value.reasons == ["RELEASE_DENIED", "EXTERNAL_POLICY_DENIED"] and ei.value.receipt.decision == "DENY"


@pytest.mark.parametrize("mode", ["ENFORCE", "BOUNDED_OFFLINE", "WARN"])
def test_non_allow_blocks_in_blocking_modes(mode):
    kw = {"snapshot_public_key": "A" * 43 + "="} if mode == "BOUNDED_OFFLINE" else {}
    c, _ = make(lambda r: httpx.Response(200, json=receipt("UNKNOWN")), fail_mode=mode, **kw)
    with pytest.raises(ReleaseDenied):
        c.authorize_release(P, "a", "d", "p", ["c1"])


def test_observe_does_not_raise():
    c, _ = make(lambda r: httpx.Response(200, json=receipt("DENY")), fail_mode="OBSERVE")
    assert c.authorize_release(P, "a", "d", "p", ["c1"]).decision == "DENY"


def test_human_review_raises_pending():
    c, _ = make(lambda r: httpx.Response(200, json=receipt("HUMAN_REVIEW", ["RELEASE_DENIED", "APPROVAL_PENDING"])))
    with pytest.raises(HumanReviewPending) as ei:
        c.authorize_release(P, "a", "d", "p", ["c1"])
    assert "APPROVAL_PENDING" in ei.value.reasons


def test_unreachable_gate_is_unknown_and_fails_closed():
    def boom(r):
        raise httpx.ConnectError("down", request=r)

    c, seen = make(boom)
    with pytest.raises(ReleaseDenied) as ei:
        c.authorize_release(P, "a", "d", "p", ["c1"])
    assert ei.value.receipt.synthesised and ei.value.receipt.decision == "UNKNOWN"
    assert len(seen) == 1  # POST that mints a receipt is not retried
    c2, _ = make(boom, fail_mode="OBSERVE")
    assert c2.authorize_release(P, "a", "d", "p", ["c1"]).synthesised


def test_undeployed_endpoint_and_503():
    c, _ = make(lambda r: httpx.Response(404, json={"error": "nf"}))
    with pytest.raises(ReleaseDenied) as ei:
        c.authorize_release(P, "a", "d", "p", ["c1"])
    assert "RELEASE_ENDPOINT_UNAVAILABLE" in ei.value.reasons
    c, _ = make(lambda r: httpx.Response(503, json={}))
    with pytest.raises(ReleaseDenied) as ei:
        c.authorize_release(P, "a", "d", "p", ["c1"])
    assert "RELEASE_SERVER_UNAVAILABLE" in ei.value.reasons


def test_other_http_errors_propagate_and_bad_input_rejected():
    c, _ = make(lambda r: httpx.Response(422, json={"error": "validation_error"}))
    with pytest.raises(AlesHTTPError):
        c.authorize_release(P, "a", "d", "p", ["c1"])
    with pytest.raises(InvalidRequestError):
        c.authorize_release(P, "a", "d", "p", [])
    with pytest.raises(InvalidRequestError):
        c.authorize_release({"type": "user"}, "a", "d", "p", ["c1"])


def test_malformed_receipt_is_response_error():
    from ales_sdk import ResponseError

    c, _ = make(lambda r: httpx.Response(200, json={"decision": "ALLOW"}))
    with pytest.raises(ResponseError):
        c.authorize_release(P, "a", "d", "p", ["c1"])
