"""Runs the revoke-rag-source demo flow in-process and asserts every checkpoint passes."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

DEMO_PATH = Path(__file__).resolve().parents[1] / "revoke-rag-source" / "demo.py"


def _load_demo():
    spec = importlib.util.spec_from_file_location("revoke_rag_source_demo", DEMO_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve field types through sys.modules
    spec.loader.exec_module(module)
    return module


demo = _load_demo()


def test_local_flow_all_checkpoints_pass():
    checks = demo.run_local(out=lambda *_a, **_k: None)
    failed = [c for c in checks if not c.ok]
    assert failed == [], [f"{c.label}: expected {c.expected!r}, got {c.got!r}" for c in failed]
    assert demo.all_passed(checks)
    labels = [c.label for c in checks]
    assert "5" in labels and "6.memory" in labels and "6.lineage" in labels
    assert labels[-1] == "12"
    audit = next(c for c in checks if c.label == "12")
    assert audit.ok and "ok=True" in audit.got


def test_main_exits_zero_in_local_mode(capsys):
    assert demo.main([]) == 0
    out = capsys.readouterr().out
    assert "ALL PASS" in out
    assert "before any physical purge" in out
