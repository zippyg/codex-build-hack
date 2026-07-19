from __future__ import annotations

import hmac
import re
import threading
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

from fastapi import FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, ValidationError
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .artifacts_v2 import ArtifactStore
from .contracts_v2 import ContractError, parse_json_strict
from .reports_v2 import freeze_report
from .state_v2 import EventCursorExpired, StateConflict, StateError, StateStore


IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
DEFAULT_ALLOWED_HOSTS = {"127.0.0.1", "::1", "localhost", "promptectomy.local"}
DEFAULT_ALLOWED_ORIGINS = {
    "http://127.0.0.1",
    "http://localhost",
    "https://127.0.0.1",
    "https://localhost",
}
BodyModel = TypeVar("BodyModel", bound=BaseModel)


class CreateRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run: dict[str, Any]
    event: dict[str, Any]


class AppendEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event: dict[str, Any]
    target_status: str | None = None


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp, *, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope["headers"]}
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError:
                await self._reject(scope, send, "invalid_content_length", 400)
                return
            if declared < 0 or declared > self.max_bytes:
                await self._reject(scope, send, "request_body_too_large", 413)
                return
        consumed = 0

        async def bounded_receive() -> Message:
            nonlocal consumed
            message = await receive()
            if message["type"] == "http.request":
                consumed += len(message.get("body", b""))
                if consumed > self.max_bytes:
                    raise _BodyTooLarge
            return message

        try:
            await self.app(scope, bounded_receive, send)
        except _BodyTooLarge:
            await self._reject(scope, send, "request_body_too_large", 413)

    @staticmethod
    async def _reject(scope: Scope, send: Send, code: str, status: int) -> None:
        response = JSONResponse(
            {"error": {"code": code, "safe_message": code.replace("_", " ")}},
            status_code=status,
        )
        await response(scope, _empty_receive, send)


class _BodyTooLarge(Exception):
    pass


async def _empty_receive() -> Message:
    return {"type": "http.request", "body": b"", "more_body": False}


@dataclass
class _RateWindow:
    requests: deque[float] = field(default_factory=deque)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def accept(self, *, now: float, limit: int, seconds: float) -> bool:
        with self.lock:
            while self.requests and self.requests[0] <= now - seconds:
                self.requests.popleft()
            if len(self.requests) >= limit:
                return False
            self.requests.append(now)
            return True


def create_app(
    state: StateStore,
    artifacts: ArtifactStore,
    *,
    capability_token: str,
    allowed_hosts: set[str] | None = None,
    allowed_origins: set[str] | None = None,
    max_body_bytes: int = 2_000_000,
    requests_per_minute: int = 600,
) -> FastAPI:
    if len(capability_token.encode("utf-8")) < 32:
        raise ValueError("local API capability token must contain at least 32 bytes")
    hosts = DEFAULT_ALLOWED_HOSTS if allowed_hosts is None else allowed_hosts
    origins = DEFAULT_ALLOWED_ORIGINS if allowed_origins is None else allowed_origins
    rate = _RateWindow()
    app = FastAPI(
        title="PROMPTECTOMY local API",
        version="2.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(BodyLimitMiddleware, max_bytes=max_body_bytes)

    @app.middleware("http")
    async def enforce_boundary(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        host = request.url.hostname
        if host not in hosts:
            return _error("invalid_host", "The request Host is not accepted.", 400)
        origin = request.headers.get("origin")
        if origin is not None and origin not in origins:
            return _error("invalid_origin", "The request Origin is not accepted.", 403)
        authorization = request.headers.get("authorization", "")
        scheme, separator, provided = authorization.partition(" ")
        if not separator or scheme.lower() != "bearer" or not hmac.compare_digest(
            provided, capability_token
        ):
            return _error("invalid_capability", "A valid local capability is required.", 401)
        if not rate.accept(
            now=time.monotonic(), limit=requests_per_minute, seconds=60.0
        ):
            return _error("rate_limited", "The local API request limit was reached.", 429)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        return response

    @app.exception_handler(ContractError)
    async def contract_error(_: Request, __: ContractError) -> JSONResponse:
        return _error("invalid_contract", "The request contract is invalid.", 422)

    @app.exception_handler(RequestValidationError)
    async def request_error(_: Request, __: RequestValidationError) -> JSONResponse:
        return _error("invalid_request", "The HTTP request is invalid.", 422)

    @app.exception_handler(StateConflict)
    async def conflict_error(_: Request, __: StateConflict) -> JSONResponse:
        return _error(
            "state_conflict", "The request conflicts with current local state.", 409
        )

    @app.exception_handler(EventCursorExpired)
    async def cursor_error(_: Request, __: EventCursorExpired) -> JSONResponse:
        return _error(
            "event_cursor_expired", "The requested event cursor has expired.", 410
        )

    @app.exception_handler(StateError)
    async def state_error(_: Request, __: StateError) -> JSONResponse:
        return _error("state_error", "The local state request is invalid.", 400)

    @app.get("/v2/health")
    async def health() -> dict[str, str]:
        state.integrity_check()
        return {"schema_version": "2.0.0", "status": "ready"}

    @app.post("/v2/runs", status_code=201)
    async def create_run(
        request: Request,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        idempotency_key = _validate_idempotency_key(idempotency_key)
        body = await _parse_body(request, CreateRunRequest)
        return state.create_run(
            body.run, body.event, idempotency_key=idempotency_key
        )

    @app.get("/v2/runs/{run_id}")
    async def get_run(run_id: str) -> Any:
        run = state.get_run(run_id)
        if run is None:
            return _error("run_not_found", "The requested run does not exist.", 404)
        return run

    @app.get("/v2/runs/{run_id}/events")
    async def get_events(
        run_id: str, after: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        events = state.events_after(run_id, after, limit=limit)
        return {
            "schema_version": "2.0.0",
            "run_id": run_id,
            "after": after,
            "events": events,
            "next_after": after if not events else events[-1]["sequence"],
        }

    @app.post("/v2/runs/{run_id}/events")
    async def append_event(
        run_id: str,
        request: Request,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ) -> dict[str, Any]:
        idempotency_key = _validate_idempotency_key(idempotency_key)
        body = await _parse_body(request, AppendEventRequest)
        if body.event.get("run_id") != run_id:
            raise StateConflict("event run ID does not match the request path")
        return state.append_event(
            body.event,
            target_status=body.target_status,
            idempotency_key=idempotency_key,
        )

    @app.post("/v2/runs/{run_id}/report", status_code=201)
    async def create_report(run_id: str) -> dict[str, str]:
        report = freeze_report(state, artifacts, run_id)
        return {
            "schema_version": "2.0.0",
            "snapshot_artifact_id": report.snapshot_artifact_id,
            "markdown_artifact_id": report.markdown_artifact_id,
            "snapshot_digest": report.snapshot_digest,
            "markdown_digest": report.markdown_digest,
        }

    @app.get("/v2/artifacts/{algorithm}/{digest}")
    async def get_artifact(algorithm: str, digest: str) -> Response:
        identifier = f"{algorithm}:{digest}"
        record = state.artifact_record(identifier)
        if record is None:
            return _error("artifact_not_found", "The requested artifact does not exist.", 404)
        content = artifacts.read(identifier, allowed_classes={"safe"})
        return Response(
            content,
            media_type=record[1],
            headers={"Content-Disposition": f'attachment; filename="{digest}.artifact"'},
        )

    return app


def _validate_idempotency_key(value: str | None) -> str:
    if value is None or IDEMPOTENCY_KEY.fullmatch(value) is None:
        raise StateConflict("Idempotency-Key is missing or invalid")
    return value


async def _parse_body(
    request: Request, model: type[BodyModel]
) -> BodyModel:
    content_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
    if content_type != "application/json":
        raise ContractError("request Content-Type must be application/json")
    value = parse_json_strict(await request.body())
    try:
        return model.model_validate(value)
    except ValidationError as exc:
        raise ContractError("request body does not match the endpoint contract") from exc


def _error(code: str, safe_message: str, status: int) -> JSONResponse:
    return JSONResponse(
        {"error": {"code": code, "safe_message": safe_message}},
        status_code=status,
    )
