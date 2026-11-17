# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Pure ASGI middlewares: security headers and request body limits."""

import json
from collections.abc import Callable

from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from vexledger.config.logging import request_id_var


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, *, hsts: bool) -> None:
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope["path"]

        async def wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                h = MutableHeaders(scope=message)
                h.setdefault("X-Content-Type-Options", "nosniff")
                h.setdefault("X-Frame-Options", "DENY")
                h.setdefault("Referrer-Policy", "no-referrer")
                if path.startswith("/api/"):
                    h.setdefault(
                        "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
                    )
                    h.setdefault("Cache-Control", "no-store")
                if self.hsts:
                    h.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            await send(message)

        await self.app(scope, receive, wrapper)


class BodyLimitMiddleware:
    """Reject oversized bodies by Content-Length and by bytes actually streamed."""

    def __init__(self, app: ASGIApp, *, limit_for: Callable[[str], int]) -> None:
        self.app = app
        self.limit_for = limit_for

    async def _reject(self, send: Send, status: int, code: str, message: str) -> None:
        body = json.dumps(
            {
                "error": {
                    "code": code,
                    "message": message,
                    "request_id": request_id_var.get() or None,
                }
            }
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"connection", b"close"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.limit_for(scope["path"])
        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None:
            if not declared.isdigit():
                await self._reject(send, 400, "bad_request", "invalid Content-Length")
                return
            if int(declared) > limit:
                await self._reject(send, 413, "payload_too_large", f"body exceeds {limit} bytes")
                return
        received = 0

        async def counting_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    # An HTTPException survives FastAPI's body parsing (anything else becomes 400).
                    raise HTTPException(413, f"body exceeds {limit} bytes")
            return message

        await self.app(scope, counting_receive, send)
