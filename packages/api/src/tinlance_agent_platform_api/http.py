"""Minimal hardened HTTP boundary for the versioned Platform API contract."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Protocol
from urllib.parse import urlsplit

from .service import (
    API_VERSION,
    AgentPlatformAPI,
    APIRequest,
    AuthenticationError,
    ExecutionAPIError,
    IdempotencyConflictError,
    PrincipalResolver,
)


class MCPHTTPResponse(Protocol):
    status_code: int
    headers: Mapping[str, str]
    body: bytes


class MCPHTTPService(Protocol):
    def handle(self, headers: Mapping[str, str], raw_body: bytes) -> MCPHTTPResponse: ...


class A2AHTTPService(Protocol):
    def handle(self, headers: Mapping[str, str], raw_body: bytes) -> MCPHTTPResponse: ...

    def card_response(self) -> MCPHTTPResponse: ...


class JWKSProvider(Protocol):
    def jwks(self) -> dict[str, list[dict[str, str]]]: ...


class SessionRevoker(Protocol):
    def revoke_session(
        self,
        bearer_token: str,
        *,
        request_id: str,
        dpop_proof: str | None = None,
        method: str | None = None,
        uri: str | None = None,
    ) -> None: ...


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


def _public_origin(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError
        _ = parsed.port
        return f"https://{parsed.netloc.lower()}"
    except (TypeError, ValueError) as exc:
        raise ValueError("DPoP public origin must be a normalized HTTPS origin") from exc


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
    mcp_service: MCPHTTPService | None = None,
    a2a_service: A2AHTTPService | None = None,
    jwks_provider: JWKSProvider | None = None,
    session_revoker: SessionRevoker | None = None,
    public_origin: str | None = None,
) -> ThreadingHTTPServer:
    """Start a local/reference HTTP server.

    Production deployments should place a hardened TLS/reverse-proxy boundary
    in front of this handler and inject a standards-based token verifier.
    DPoP requires a configured canonical HTTPS public origin; Host headers are
    never trusted as the proof target authority.
    """
    normalized_public_origin = _public_origin(public_origin)

    class Handler(BaseHTTPRequestHandler):
        server_version = "TinlanceAgentPlatform/1.1"
        sys_version = ""

        def _reject_ambiguous_headers(self, names: tuple[str, ...]) -> bool:
            for name in names:
                values = self.headers.get_all(name, [])
                if values is not None and len(values) > 1:
                    self._respond(HTTPStatus.BAD_REQUEST, {"error": "duplicate_header"})
                    return True
            if self.headers.get_all("Transfer-Encoding"):
                self._respond(HTTPStatus.BAD_REQUEST, {"error": "unsupported_transfer_encoding"})
                return True
            return False

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/.well-known/jwks.json":
                if jwks_provider is None:
                    self._respond(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                    return
                try:
                    document = jwks_provider.jwks()
                    keys = document.get("keys")
                    if (
                        set(document) != {"keys"}
                        or not isinstance(keys, list)
                        or not keys
                        or len(keys) > 16
                        or any(
                            not isinstance(key, dict)
                            or set(key) != {"kty", "use", "alg", "kid", "n", "e"}
                            or key.get("kty") != "RSA"
                            or key.get("use") != "sig"
                            or key.get("alg") != "RS256"
                            or any(
                                not isinstance(value, str) or not value for value in key.values()
                            )
                            for key in keys
                        )
                    ):
                        raise ValueError("JWKS must contain only bounded public RS256 RSA keys")
                    raw = json.dumps(document, separators=(",", ":"), sort_keys=True).encode(
                        "utf-8"
                    )
                    if len(raw) > 64 * 1024:
                        raise ValueError("JWKS document exceeds the response limit")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/jwk-set+json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.send_header(
                        "Cache-Control", "public, max-age=60, stale-while-revalidate=30"
                    )
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.end_headers()
                    self.wfile.write(raw)
                except Exception:
                    self._respond(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "jwks_unavailable"})
                return
            if self.path != "/.well-known/agent-card.json" or a2a_service is None:
                self._respond(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            try:
                self._send_protocol_response(a2a_service.card_response())
            except Exception:
                self._respond(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "a2a_card_error"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path == "/v1/session/revoke":
                if self._reject_ambiguous_headers(
                    (
                        "Content-Length",
                        "Content-Type",
                        "Authorization",
                        "X-Tinlance-API-Version",
                        "X-Request-ID",
                        "DPoP",
                    )
                ):
                    return
                if session_revoker is None:
                    self._respond(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                    return
                try:
                    length = int(self.headers.get("Content-Length", ""))
                except ValueError:
                    self._respond(HTTPStatus.BAD_REQUEST, {"error": "invalid_content_length"})
                    return
                if length < 0 or length > 1024:
                    self._respond(
                        HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                        {"error": "request_too_large"},
                    )
                    return
                if "application/json" not in self.headers.get("Content-Type", "").lower():
                    self._respond(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "json_required"})
                    return
                if self.headers.get("X-Tinlance-API-Version") != API_VERSION:
                    self._respond(HTTPStatus.UPGRADE_REQUIRED, {"error": "api_version_required"})
                    return
                try:
                    request_id = _request_id(self.headers.get("X-Request-ID"))
                    raw = self.rfile.read(length)
                    if len(raw) != length:
                        raise ValueError("request body is truncated")
                    body = json.loads(raw.decode("utf-8"))
                    if not isinstance(body, dict) or body:
                        raise ValueError("session revocation body must be an empty JSON object")
                    token = _bearer(self.headers.get("Authorization"))
                    dpop_proof = self.headers.get("DPoP")
                    dpop_uri = None
                    if dpop_proof is not None:
                        if (
                            normalized_public_origin is None
                            or not self.path.startswith("/")
                            or self.path.startswith("//")
                        ):
                            raise AuthenticationError("DPoP public request target is unavailable")
                        dpop_uri = f"{normalized_public_origin}{self.path}"
                    try:
                        if dpop_proof is None:
                            session_revoker.revoke_session(token, request_id=request_id)
                        else:
                            session_revoker.revoke_session(
                                token,
                                request_id=request_id,
                                dpop_proof=dpop_proof,
                                method="POST",
                                uri=dpop_uri,
                            )
                    except PermissionError as exc:
                        raise AuthenticationError(
                            "bearer identity could not be authenticated"
                        ) from exc
                    except Exception:
                        self._respond(
                            HTTPStatus.SERVICE_UNAVAILABLE,
                            {"error": "session_revocation_unavailable"},
                        )
                        return
                    self._respond(HTTPStatus.OK, {"status": "revoked"})
                except AuthenticationError:
                    self._respond(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                except (ValueError, KeyError):
                    self._respond(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
                return
            if self.path == "/a2a":
                if self._reject_ambiguous_headers(
                    (
                        "Content-Length",
                        "Content-Type",
                        "Authorization",
                        "Origin",
                        "A2A-Version",
                        "Idempotency-Key",
                        "traceparent",
                    )
                ):
                    return
                if a2a_service is None:
                    self._respond(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                    return
                try:
                    length = int(self.headers.get("Content-Length", ""))
                except ValueError:
                    self._respond(HTTPStatus.BAD_REQUEST, {"error": "invalid_content_length"})
                    return
                if length < 0 or length > MAX_REQUEST_BYTES:
                    self._respond(
                        HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "request_too_large"}
                    )
                    return
                try:
                    raw = self.rfile.read(length)
                    if len(raw) != length:
                        raise ValueError("request body is truncated")
                    protocol_response = a2a_service.handle(dict(self.headers.items()), raw)
                    self._send_protocol_response(protocol_response)
                except Exception:
                    self._respond(
                        HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "a2a_transport_error"}
                    )
                return
            if self.path == "/mcp":
                if self._reject_ambiguous_headers(
                    (
                        "Content-Length",
                        "Content-Type",
                        "Authorization",
                        "Origin",
                        "MCP-Protocol-Version",
                        "Mcp-Method",
                        "Mcp-Name",
                    )
                ):
                    return
                if mcp_service is None:
                    self._respond(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                    return
                try:
                    length = int(self.headers.get("Content-Length", ""))
                except ValueError:
                    self._respond(HTTPStatus.BAD_REQUEST, {"error": "invalid_content_length"})
                    return
                if length < 0 or length > MAX_REQUEST_BYTES:
                    self._respond(
                        HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "request_too_large"}
                    )
                    return
                if "application/json" not in self.headers.get("Content-Type", "").lower():
                    self._respond(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "json_required"})
                    return
                try:
                    raw = self.rfile.read(length)
                    if len(raw) != length:
                        raise ValueError("request body is truncated")
                    mcp_response = mcp_service.handle(dict(self.headers.items()), raw)
                    self.send_response(mcp_response.status_code)
                    response_headers = {
                        key.lower(): value for key, value in mcp_response.headers.items()
                    }
                    for key, value in mcp_response.headers.items():
                        self.send_header(key, value)
                    if "content-length" not in response_headers:
                        self.send_header("Content-Length", str(len(mcp_response.body)))
                    self.end_headers()
                    self.wfile.write(mcp_response.body)
                except Exception:
                    self._respond(
                        HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "mcp_transport_error"}
                    )
                return
            if self.path != "/v1/agent-platform":
                self._respond(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            if self._reject_ambiguous_headers(
                (
                    "Content-Length",
                    "Content-Type",
                    "Authorization",
                    "X-Tinlance-API-Version",
                    "X-Request-ID",
                    "Idempotency-Key",
                    "traceparent",
                    "DPoP",
                )
            ):
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
                dpop_proof = self.headers.get("DPoP")
                try:
                    if dpop_proof is None:
                        principal = resolver.resolve(token)
                    else:
                        resolve_with_dpop = getattr(resolver, "resolve_with_dpop", None)
                        if (
                            not callable(resolve_with_dpop)
                            or normalized_public_origin is None
                            or not self.path.startswith("/")
                            or self.path.startswith("//")
                        ):
                            raise AuthenticationError("DPoP request verification is unavailable")
                        principal = resolve_with_dpop(
                            token,
                            dpop_proof,
                            method="POST",
                            uri=f"{normalized_public_origin}{self.path}",
                        )
                except PermissionError as exc:
                    raise AuthenticationError("bearer identity could not be authenticated") from exc
                tenant_id = body.get("tenant_id", principal.tenant_id)
                subject_id = body.get("subject_id", principal.subject_id)
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
                if idempotency_key is not None:
                    idempotency_key = _request_id(idempotency_key)
                request = APIRequest(
                    principal.tenant_id,
                    principal.subject_id,
                    operation,
                    payload,
                    request_id,
                    _traceparent(self.headers.get("traceparent")),
                    idempotency_key,
                    principal,
                )
                api_response = api.dispatch(request)
                self._respond(
                    HTTPStatus.OK,
                    {"status": api_response.status, "payload": api_response.payload},
                )
            except AuthenticationError:
                self._respond(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            except IdempotencyConflictError as exc:
                self._respond(
                    HTTPStatus.CONFLICT,
                    {"error": exc.code, "retryable": getattr(exc, "retryable", False)},
                )
            except ExecutionAPIError as exc:
                self._respond(
                    HTTPStatus.CONFLICT,
                    {"error": exc.code, "retryable": exc.retryable},
                )
            except PermissionError:
                self._respond(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            except (ValueError, KeyError):
                self._respond(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            except Exception:
                self._respond(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "platform_error"})

        def _send_protocol_response(self, response: MCPHTTPResponse) -> None:
            normalized_headers = {key.lower(): value for key, value in response.headers.items()}
            self.send_response(response.status_code)
            for key, value in response.headers.items():
                self.send_header(key, value)
            if "content-length" not in normalized_headers:
                self.send_header("Content-Length", str(len(response.body)))
            self.end_headers()
            self.wfile.write(response.body)

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
