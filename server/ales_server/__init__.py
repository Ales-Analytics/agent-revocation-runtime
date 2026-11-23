"""Agent Revocation Runtime control plane (FastAPI)."""

from typing import Any

from .main import create_app


def __getattr__(name: str) -> Any:
    if name == "app":  # lazy: see ales_server.main.__getattr__
        from . import main

        return main.app
    raise AttributeError(name)


__all__ = ["app", "create_app"]
