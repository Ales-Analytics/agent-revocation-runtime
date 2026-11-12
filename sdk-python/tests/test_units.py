import re

import pytest
from ales_sdk import (
    DecisionCache,
    FailMode,
    SessionTaint,
    digest,
    make_key,
    new_derivative,
    new_source,
    resolve,
)
from sdk_fixtures import ENV_VALIDATOR

# ---- envelope ----


def test_digest_format():
    d = digest(b"hello")
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", d)
    assert digest("hello") == d


def test_source_and_derivative_valid_against_schema():
    src = new_source("t1", "doc", b"x", "kb", classification="confidential", principal_scope=["a", "b"])
    ENV_VALIDATOR.validate(src)
    src2 = new_source(
        "t1", "doc2", b"y", "kb", classification="internal", principal_scope=["b", "c"],
        expires_at="2030-01-01T00:00:00Z",
    )
    chunk = new_derivative("chunk", [src, src2], "t1", "c", b"z")
    ENV_VALIDATOR.validate(chunk)
    assert chunk["classification"] == "confidential"
    assert chunk["principal_scope"] == ["b"]
    assert chunk["expires_at"] == "2030-01-01T00:00:00Z"
    assert len(chunk["parent_refs"]) == 2


def test_derivative_requires_parents_and_valid_kind():
    with pytest.raises(ValueError):
        new_derivative("chunk", [], "t", "o", b"x")
    with pytest.raises(ValueError):
        new_derivative("source", [{"context_id": "a", "object_version": "1"}], "t", "o", b"x")


# ---- decision cache ----


def test_cache_allow_only_and_epoch_invalidation(clock):
    c = DecisionCache(clock=clock)
    k = make_key("t1", "user", "u", "p", "c1", None, "pv")
    assert c.put(k, "DENY", 0) is False
    assert c.put(k, "UNKNOWN", 0) is False
    assert c.get(k) is None
    assert c.put(k, "ALLOW", 3)
    assert c.get(k) == 3
    assert c.invalidate_if_epoch_advanced(3) == 0
    assert c.invalidate_if_epoch_advanced(4) == 1
    assert c.get(k) is None
    # stale-epoch ALLOW refused after the epoch advanced
    assert c.put(k, "ALLOW", 3) is False


def test_cache_ttl_cap(clock):
    c = DecisionCache(max_ttl=10, clock=clock)
    k = make_key("t1", "user", "u", "p", "c1", "1", "pv")
    c.put(k, "ALLOW", 0, ttl=1000)
    clock.t += 9
    assert c.get(k) == 0
    clock.t += 2
    assert c.get(k) is None


# ---- fail modes ----


@pytest.mark.parametrize("decision", ["ALLOW", "DENY", "UNKNOWN"])
@pytest.mark.parametrize("cls", ["restricted", "public"])
def test_fail_mode_matrix(decision, cls):
    ok = decision == "ALLOW"
    protected = cls != "public"

    a = resolve(decision, FailMode.ENFORCE, cls)
    assert a.allow is ok and not a.needs_override and not a.observed_only

    a = resolve(decision, FailMode.OBSERVE, cls)
    assert a.allow is True and a.observed_only is (not ok)

    a = resolve(decision, "WARN", cls)
    if ok:
        assert a.allow and not a.needs_override
    elif protected:
        assert not a.allow and a.needs_override
    else:
        assert a.allow and a.observed_only

    # BOUNDED_OFFLINE: online == enforce; lease valid == cached decision; expired == deny protected
    assert resolve(decision, FailMode.BOUNDED_OFFLINE, cls, None).allow is ok
    assert resolve(decision, FailMode.BOUNDED_OFFLINE, cls, True).allow is ok
    expired = resolve(decision, FailMode.BOUNDED_OFFLINE, cls, False)
    if protected:
        assert expired.allow is False
    else:
        assert expired.allow is (decision != "DENY")


def test_enforce_blocks_quarantine():
    assert resolve("QUARANTINE", FailMode.ENFORCE, "internal").allow is False


# ---- session taint ----


def test_session_taint():
    t = SessionTaint()
    t.record("s1", ["a", "b"])
    t.record("s1", ["c"])
    assert t.contexts_for("s1") == {"a", "b", "c"}
    assert t.contexts_for("zzz") == set()
    assert t.is_tainted("s1", ["b", "x"])
    assert not t.is_tainted("s1", ["x"])
    assert not t.is_tainted("nope", ["a"])


# ---- valid_until (pending future-dated revocation) ----


class _Wall:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def test_cache_refuses_entry_past_valid_until(clock):
    wall = _Wall()
    c = DecisionCache(clock=clock, wall_clock=wall, max_clock_skew=0)
    k = make_key("t1", "user", "u", "p", "c1", None, "pv")
    assert c.put(k, "ALLOW", 1, valid_until=wall.t + 10)
    assert c.get(k) == 1
    wall.t += 9.9
    assert c.get(k) == 1  # TTL (monotonic) is unaffected
    wall.t += 0.2
    assert c.get(k) is None  # past valid_until: miss even though TTL and epoch are fine
    assert len(c) == 0


def test_cache_valid_until_honours_skew_allowance(clock):
    wall = _Wall()
    c = DecisionCache(clock=clock, wall_clock=wall, max_clock_skew=5)
    k = make_key("t1", "user", "u", "p", "c1", None, "pv")
    assert c.put(k, "ALLOW", 1, valid_until=wall.t + 20)
    wall.t += 14.9
    assert c.get(k) == 1
    wall.t += 0.2  # within 5 s of valid_until: stop serving early
    assert c.get(k) is None
    # an ALLOW already inside the skew window (or past) is never stored
    assert c.put(k, "ALLOW", 1, valid_until=wall.t + 3) is False
    assert c.put(k, "ALLOW", 1, valid_until=wall.t - 100) is False
    assert c.get(k) is None


def test_cache_without_valid_until_unchanged(clock):
    wall = _Wall()
    c = DecisionCache(clock=clock, wall_clock=wall)
    k = make_key("t1", "user", "u", "p", "c1", None, "pv")
    c.put(k, "ALLOW", 1)
    wall.t += 10_000  # wall clock jumps: only TTL/epoch matter when no valid_until was given
    assert c.get(k) == 1
