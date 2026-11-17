# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Request id propagation and one structured access log line per request."""

import logging
import re
import time
import uuid

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from vexledger.config.logging import request_id_var

REQUEST_ID_HEADER = "x-request-id"
_SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
_log = logging.getLogger("vexledger.access")


def resolve_request_id(incoming: str | None) -> str:
    """Reuse a well-formed client id, otherwise mint one (client input is untrusted)."""
    if incoming is not None and _SAFE_ID.fullmatch(incoming):
        return incoming
    return uuid.uuid4().hex


class RequestIdMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope["headers"])
        incoming = headers.get(REQUEST_ID_HEADER.encode())
        rid = resolve_request_id(incoming.decode("latin-1") if incoming else None)
        scope["request_id"] = rid  # the 500 handler runs after this middleware has unwound
        token = request_id_var.set(rid)
        started = time.perf_counter()
        status = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                MutableHeaders(scope=message)[REQUEST_ID_HEADER] = rid
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            _log.info(
                "request",
                extra={
                    "extra_fields": {
                        "method": scope["method"],
                        "path": scope["path"],
                        "status": status,
                        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                    }
                },
            )
            request_id_var.reset(token)
