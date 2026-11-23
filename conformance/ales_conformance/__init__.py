"""Adapter conformance suite for Agent Revocation Runtime."""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
for _sub in ("core", "server", "sdk-python", "adapters"):
    _p = str(_ROOT / _sub)
    if _p not in sys.path:
        sys.path.append(_p)

from .contract import (
    AdapterConformance,
    CheckResult,
    ConformanceReport,
    IngestionConformance,
    ObjectRef,
    ReadOutcome,
    Subject,
)

__all__ = [
    "AdapterConformance",
    "CheckResult",
    "ConformanceReport",
    "IngestionConformance",
    "ObjectRef",
    "ReadOutcome",
    "Subject",
]
