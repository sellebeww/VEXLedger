# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""One error shape for every failure: {"error": {"code", "message", "field", "details", ...}}.

Codes are stable strings (domain codes come from `ErrorCode`); messages are for humans. Nothing
here ever echoes a stack trace or the submitted input.
"""

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from redis.exceptions import RedisError
from sqlalchemy.exc import OperationalError
from starlette.exceptions import HTTPException as StarletteHTTPException

from vexledger.config.logging import request_id_var
from vexledger.db.errors import ConflictError, NotFoundError
from vexledger.domain.errors import ExportError, StatementValidationError
from vexledger.services.evidence_storage import EvidenceRejectedError, RejectionCode
from vexledger.services.sbom import SbomError, SbomTooLargeError

_log = logging.getLogger("vexledger.api")
_STATUS_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    413: "payload_too_large",
    429: "rate_limited",
}


class ErrorBody(BaseModel):
    code: str
    message: str
    field: str | None = None
    details: dict[str, Any] | None = None
    request_id: str | None = None


class ErrorOut(BaseModel):
    error: ErrorBody


class ApiError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        field: str | None = None,
        details: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.field = field
        self.details = details
        self.headers = headers


def error_response(
    status: int,
    code: str,
    message: str,
    *,
    field: str | None = None,
    details: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    request_id: str | None = None,
) -> JSONResponse:
    body = ErrorBody(
        code=code,
        message=message,
        field=field,
        details=details,
        request_id=request_id or request_id_var.get() or None,
    )
    return JSONResponse(
        {"error": body.model_dump(exclude_none=True)}, status_code=status, headers=headers
    )


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api(_: Request, exc: ApiError) -> JSONResponse:
        return error_response(
            exc.status, exc.code, exc.message, field=exc.field, details=exc.details,
            headers=exc.headers,
        )  # fmt: skip

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _STATUS_CODES.get(exc.status_code, "error")
        return error_response(
            exc.status_code, code, str(exc.detail), headers=getattr(exc, "headers", None)
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        items = [
            {"loc": [str(x) for x in e["loc"]], "message": e["msg"], "type": e["type"]}
            for e in exc.errors()[:20]
        ]
        return error_response(
            422, "validation_error", "request validation failed", details={"errors": items}
        )

    @app.exception_handler(NotFoundError)
    async def _not_found(_: Request, exc: NotFoundError) -> JSONResponse:
        return error_response(404, "not_found", str(exc))

    @app.exception_handler(ConflictError)
    async def _conflict(_: Request, exc: ConflictError) -> JSONResponse:
        details = (
            {"current_head_id": str(exc.current_head_id)}
            if exc.current_head_id is not None
            else None
        )
        return error_response(409, "conflict", str(exc), details=details)

    @app.exception_handler(StatementValidationError)
    async def _statement(_: Request, exc: StatementValidationError) -> JSONResponse:
        return error_response(422, exc.code.value, str(exc), field=exc.field)

    @app.exception_handler(ExportError)
    async def _export(_: Request, exc: ExportError) -> JSONResponse:
        return error_response(422, exc.code.value, str(exc))

    @app.exception_handler(SbomError)
    async def _sbom(_: Request, exc: SbomError) -> JSONResponse:
        status = 413 if isinstance(exc, SbomTooLargeError) else 422
        return error_response(
            status,
            exc.code,
            str(exc),
            details={"problems": list(exc.problems[:20])} if exc.problems else None,
        )

    @app.exception_handler(EvidenceRejectedError)
    async def _evidence(_: Request, exc: EvidenceRejectedError) -> JSONResponse:
        status = {RejectionCode.TOO_LARGE: 413, RejectionCode.NOT_FOUND: 404}.get(exc.code, 422)
        return error_response(status, exc.code.value, str(exc))

    @app.exception_handler(RedisError)
    @app.exception_handler(OperationalError)
    async def _backend_down(request: Request, exc: Exception) -> JSONResponse:
        # Sessions, rate limits and data live in Redis/Postgres: fail closed with a clear 503.
        _log.error("backend unavailable", exc_info=exc)
        return error_response(
            503,
            "service_unavailable",
            "a required backing service is unavailable; try again shortly",
            request_id=request.scope.get("request_id"),
            headers={"retry-after": "5"},
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        _log.error("unhandled error", exc_info=exc)  # the trace goes to the log, never the client
        rid: str | None = request.scope.get("request_id")
        return error_response(
            500,
            "internal_error",
            "internal server error",
            request_id=rid,
            headers={"x-request-id": rid} if rid else None,
        )


Resp = dict[int | str, dict[str, Any]]
_401: Resp = {401: {"model": ErrorOut, "description": "Not authenticated"}}
_403: Resp = {
    403: {"model": ErrorOut, "description": "Role not allowed, or CSRF token missing or wrong"}
}
_404: Resp = {404: {"model": ErrorOut, "description": "Not found"}}
_409: Resp = {409: {"model": ErrorOut, "description": "Conflict with the current state"}}
_413: Resp = {413: {"model": ErrorOut, "description": "Request body too large"}}
_422: Resp = {422: {"model": ErrorOut, "description": "Validation failed (stable `error.code`)"}}

AUTHED: Resp = _401 | _403  # endpoint without input or lookups
READ: Resp = AUTHED | _404
WRITE: Resp = AUTHED | _404 | _409 | _413 | _422
VALIDATED: Resp = AUTHED | _413 | _422
