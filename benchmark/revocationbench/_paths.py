"""Make the in-repo packages importable without an install (appended, so installed copies win)."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

for _sub in ("core", "server", "sdk-python", "adapters"):
    _p = str(REPO_ROOT / _sub)
    if _p not in sys.path:
        sys.path.append(_p)
