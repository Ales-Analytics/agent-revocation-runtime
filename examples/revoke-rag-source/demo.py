"""Run the packaged RAG revocation demo from a source checkout."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
for package in ("core", "sdk-python", "server", "adapters"):
    sys.path.insert(0, str(ROOT / package))

from ales_sdk import revoke_demo


def __getattr__(name: str) -> Any:
    return getattr(revoke_demo, name)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(revoke_demo.main())
