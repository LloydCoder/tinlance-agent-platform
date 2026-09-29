"""Minimal hardened HTTP boundary for the versioned Platform API contract."""

from __future__ import annotations

import json
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .service import (
    API_VERSION,
    AgentPlatformAPI,
    APIRequest,
    AuthenticationError,
    IdempotencyConflictError,
    PrincipalResolver,
)

MAX_REQUEST_BYTES = 1 * 1024 * 1024
_TRACEPARENT = re.compile(r"^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$")


def _bearer(value: str | None) -> str:
    if value is None or not value.startswith("Bearer "):
        raise AuthenticationError("bearer authentication is required")
    token = value[7:].strip()
    if not token or any(character.isspace() for character in token):
        raise AuthenticationError("invalid bearer authentication")
    return token


def _traceparent(value: str | None) -> str | None:
    if value is None:
        return None
    if not _TRACEPARENT.fullmatch(value):
        raise ValueError("traceparent must use W3C Trace Context format")
    trace_id = value[3:35]
    span_id = value[36:52]
    if trace_id == "0" * 32 or span_id == "0" * 16:
        raise ValueError("traceparent identifiers must not be all zero")
    return value


def _request_id(value: str | None) -> str:
    if value is None or not value or value != value.strip() or len(value) > 256:
        raise ValueError("X-Request-ID is required and must be normalized")
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in value):
        raise ValueError("X-Request-ID contains invalid characters")
    return value


def serve(
    api: AgentPlatformAPI,
    resolver: PrincipalResolver,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
) -> ThreadingHTTPServer:
    """Start a local/reference HTTP server.

    Production deployments should place a hardened TLS/reverse-proxy boundary
    in front of this handler and inject a standards-based token verifier.
    """

    class Handler(BaseHTTPRequestHandler):
        server_version = "TinlanceAgentPlatform/1.1"
        sys_version = ""

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/v1/agent-platform":
                self._respond(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._respond(HTTPStatus.BAD_REQUEST, {"error": "invalid_content_length"})
                return
            if length < 0 or length > MAX_REQUEST_BYTES:
                self._respond(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    {"error": "request_too_large"},
                )
                return
            if "application/json" not in self.headers.get("Content-Type", "").lower():
                self._respond(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "json_required"})
                return
            try:
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError("request body is truncated")
                body = json.loads(raw.decode("utf-8"))
                if not isinstance(body, dict):
                    raise ValueError("request must be a JSON object")
                request_version = self.headers.get("X-Tinlance-API-Version")
                if request_version != API_VERSION:
                    self._respond(HTTPStatus.UPGRADE_REQUIRED, {"error": "api_version_required"})
                    return
                token = _bearer(self.headers.get("Authorization"))
                principal = resolver.resolve(token)
                tenant_id = body.get("tenant_id")
                subject_id = body.get("subject_id")
                operation = body.get("operation")
                payload = body.get("payload", {})
                if tenant_id != principal.tenant_id or subject_id != principal.subject_id:
                    raise PermissionError("request identity does not match authenticated principal")
                if not isinstance(operation, str) or not operation.strip():
                    raise ValueError("operation is required")
                if not isinstance(payload, dict):
                    raise ValueError("payload must be an object")
                request_id = _request_id(self.headers.get("X-Request-ID"))
                idempotency_key = self.headers.get("Idempotency-Key")
                if idempotency_key is not None and _request_id(idempotency_key) != request_id:
                    raise ValueError("Idempotency-Key must match X-Request-ID")
                request = APIRequest(
                    principal.tenant_id,
                    principal.subject_id,
                    operation,
                    payload,
                    request_id,
                    _traceparent(self.headers.get("traceparent")),
                )
                response = api.dispatch(request)
                self._respond(
                    HTTPStatus.OK,
                    {"status": response.status, "payload": response.payload},
                )
            except AuthenticationError:
                self._respond(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            except IdempotencyConflictError:
                self._respond(HTTPStatus.CONFLICT, {"error": "idempotency_conflict"})
            except PermissionError:
                self._respond(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            except (ValueError, KeyError):
                self._respond(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            except Exception:
                self._respond(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "platform_error"})

        def _respond(self, status: HTTPStatus, body: dict[str, object]) -> None:
            raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Tinlance-API-Version", API_VERSION)
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    return server
