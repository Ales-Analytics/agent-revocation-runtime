"""Pure-ASGI request body size cap (413). Runs before authentication so oversized bodies are never parsed."""

from __future__ import annotations

import json

from starlette.types import ASGIApp, Message, Receive, Scope, Send


class BodySizeLimitMiddleware:
    """Reject bodies larger than ``max_bytes``.

    A declared ``Content-Length`` over the cap is refused immediately. Chunked / undeclared bodies
    are buffered up to the cap and refused the moment they exceed it, so a lying or absent
    Content-Length cannot bypass the limit. Accepted bodies are replayed to the application.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def _reject(self, send: Send, status: int, detail: str) -> None:
        body = json.dumps({"detail": detail}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = 0
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    declared = max(declared, int(value))
                except ValueError:
                    await self._reject(send, 400, "invalid Content-Length")
                    return
        if declared < 0:
            await self._reject(send, 400, "invalid Content-Length")
            return
        if declared > self.max_bytes:
            await self._reject(send, 413, f"request body exceeds {self.max_bytes} bytes")
            return

        chunks: list[bytes] = []
        total = 0
        while True:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                return
            part = msg.get("body", b"")
            total += len(part)
            if total > self.max_bytes:
                await self._reject(send, 413, f"request body exceeds {self.max_bytes} bytes")
                return
            chunks.append(part)
            if not msg.get("more_body", False):
                break

        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()  # later calls surface the client disconnect

        await self.app(scope, replay, send)
