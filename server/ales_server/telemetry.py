"""Optional OpenTelemetry spans and structured decision logging. Never logs document content."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

logger = logging.getLogger("ales.server")

try:  # optional dependency
    from opentelemetry import trace as _otel_trace

    _tracer: Any = _otel_trace.get_tracer("ales_server")
except ImportError:  # pragma: no cover - optional dependency
    _tracer = None


@contextmanager
def span(name: str, **attrs: Any) -> Iterator[Any]:
    """Create an OTel span when opentelemetry-api is importable; otherwise a no-op."""
    if _tracer is None:
        yield None
        return
    with _tracer.start_as_current_span(name) as s:
        for k, v in attrs.items():
            if v is not None:
                s.set_attribute(k, v)
        yield s


def log_json(event: str, **fields: Any) -> None:
    logger.info(json.dumps({"event": event, **fields}, default=str, sort_keys=True))


def log_decision(
    *, tenant_id: str, principal_id: str, decision: str, reasons: list[str], trace_id: str
) -> None:
    log_json(
        "authorize",
        tenant_id=tenant_id,
        principal_id=principal_id,
        decision=decision,
        reasons=reasons,
        trace_id=trace_id,
    )
