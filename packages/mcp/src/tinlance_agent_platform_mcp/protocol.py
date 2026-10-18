"""Stateless MCP 2026-07-28 request adapter for the governed Platform API."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import urlparse

from tinlance_agent_platform_api.service import (
    AgentPlatformAPI,
    APIRequest,
    AuthenticationError,
    ExecutionAPIError,
    IdempotencyConflictError,
    PrincipalResolver,
)

MCP_PROTOCOL_VERSION = "2026-07-28"
MAX_REQUEST_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 1_048_576
MAX_ARGUMENTS = 64
MAX_STRING_LENGTH = 16_384
MAX_NESTING_DEPTH = 8
_TRACEPARENT = re.compile(r"^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$")


@dataclass(frozen=True, slots=True)
class MCPToolDefinition:
    name: str
    description: str
    operation: str
    input_schema: Mapping[str, object]
    consequential: bool = False
    idempotency_argument: str | None = None

    def __post_init__(self) -> None:
        for value, label in (
            (self.name, "tool name"),
            (self.description, "tool description"),
            (self.operation, "Platform operation"),
        ):
            if not value or value != value.strip():
                raise ValueError(f"{label} must be non-empty and normalized")
        if self.consequential and not self.idempotency_argument:
            raise ValueError("consequential MCP tools require an idempotency argument")
        if self.idempotency_argument is not None and (
            not self.idempotency_argument or self.idempotency_argument != self.idempotency_argument.strip()
        ):
            raise ValueError("idempotency argument name must be normalized")
        if self.input_schema.get("type") != "object":
            raise ValueError("MCP tool input schema must be an object schema")
        properties = self.input_schema.get("properties", {})
        required = self.input_schema.get("required", [])
        if not isinstance(properties, Mapping) or not isinstance(required, list):
            raise ValueError("MCP tool input schema properties/required are invalid")
        if any(not isinstance(key, str) for key in properties):
            raise ValueError("MCP tool input schema property names must be strings")
        if any(not isinstance(key, str) or key not in properties for key in required):
            raise ValueError("MCP tool input schema required keys must exist in properties")


@dataclass(frozen=True, slots=True)
class MCPHTTPResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes


def _headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in headers.items()}


def _traceparent(value: str | None) -> str | None:
    if value is None:
        return None
    if not _TRACEPARENT.fullmatch(value):
        raise ValueError("traceparent must use W3C Trace Context format")
    if value[3:35] == "0" * 32 or value[36:52] == "0" * 16:
        raise ValueError("traceparent identifiers must not be all zero")
    return value


def _validate_origin(origin: str | None, allowed_origins: frozenset[str]) -> None:
    if origin is None:
        return
    if origin == "null" or origin not in allowed_origins:
        raise PermissionError("MCP Origin is not allowed")
    parsed = urlparse(origin)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc or parsed.path or parsed.query or parsed.fragment:
        raise PermissionError("MCP Origin is invalid")


def _validate_value(value: object, *, depth: int = 0) -> None:
    if depth > MAX_NESTING_DEPTH:
        raise ValueError("MCP argument nesting exceeds safety limit")
    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            raise ValueError("MCP string argument exceeds safety limit")
        return
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, Mapping):
        if len(value) > MAX_ARGUMENTS:
            raise ValueError("MCP argument object exceeds safety limit")
        for key, nested in value.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError("MCP argument keys must be non-empty strings")
            _validate_value(nested, depth=depth + 1)
        return
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_ARGUMENTS:
            raise ValueError("MCP argument array exceeds safety limit")
        for nested in value:
            _validate_value(nested, depth=depth + 1)
        return
    raise TypeError("unsupported MCP argument type")


def _matches_schema(value: object, schema: Mapping[str, object], path: str = "arguments") -> None:
    expected = schema.get("type")
    valid = {
        "object": isinstance(value, Mapping),
        "array": isinstance(value, (list, tuple)),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(str(expected))
    if valid is not True:
        raise ValueError(f"{path} does not match declared JSON schema type")
    if isinstance(value, str):
        max_length = schema.get("maxLength")
        if isinstance(max_length, int) and len(value) > max_length:
            raise ValueError(f"{path} exceeds maxLength")
        enum = schema.get("enum")
        if isinstance(enum, list) and value not in enum:
            raise ValueError(f"{path} is not an allowed enum value")
    if isinstance(value, Mapping):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, Mapping) or not isinstance(required, list):
            raise ValueError("declared JSON schema is invalid")
        missing = [key for key in required if key not in value]
        if missing:
            raise ValueError(f"{path} is missing required properties")
        if schema.get("additionalProperties", False) is False:
            if any(key not in properties for key in value):
                raise ValueError(f"{path} contains undeclared properties")
        for key, nested in value.items():
            child_schema = properties.get(key)
            if child_schema is not None:
                if not isinstance(child_schema, Mapping):
                    raise ValueError("declared JSON schema property is invalid")
                _matches_schema(nested, child_schema, f"{path}.{key}")


class MCPProtocolService:
    """MCP JSON-RPC surface; every tool call becomes an authenticated Platform request."""

    def __init__(
        self,
        api: AgentPlatformAPI,
        resolver: PrincipalResolver,
        tools: tuple[MCPToolDefinition, ...],
        *,
        allowed_origins: tuple[str, ...] = (),
        server_name: str = "tinlance-agent-platform",
        server_version: str = "1.1.0",
        list_ttl_ms: int = 30_000,
    ) -> None:
        if not server_name.strip() or not server_version.strip():
            raise ValueError("MCP server identity is required")
        if not 1_000 <= list_ttl_ms <= 300_000:
            raise ValueError("MCP list cache TTL must be between 1s and 5m")
        origins = frozenset(allowed_origins)
        for origin in origins:
            parsed = urlparse(origin)
            if (
                origin == "null"
                or parsed.scheme not in {"https", "http"}
                or not parsed.netloc
                or parsed.path
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("allowed MCP origins must be normalized origins")
            if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
                raise ValueError("cleartext MCP origins are allowed only for loopback development")
        if len({tool.name for tool in tools}) != len(tools):
            raise ValueError("MCP tool names must be unique")
        self._api = api
        self._resolver = resolver
        self._tools = {tool.name: tool for tool in tools}
        self._allowed_origins = origins
        self._server_name = server_name
        self._server_version = server_version
        self._list_ttl_ms = list_ttl_ms

    def handle(self, headers: Mapping[str, str], raw_body: bytes) -> MCPHTTPResponse:
        normalized = _headers(headers)
        try:
            if len(raw_body) > MAX_REQUEST_BYTES:
                return self._http_error(413, "request_too_large")
            if "application/json" not in normalized.get("content-type", "").lower():
                return self._http_error(415, "json_required")
            _validate_origin(normalized.get("origin"), self._allowed_origins)
            if normalized.get("mcp-protocol-version") != MCP_PROTOCOL_VERSION:
                return self._http_error(400, "unsupported_mcp_protocol_version")
            token = normalized.get("authorization", "")
            if not token.startswith("Bearer ") or not token[7:].strip():
                return self._http_error(401, "unauthorized")
            try:
                principal = self._resolver.resolve(token[7:].strip())
            except PermissionError:
                return self._http_error(401, "unauthorized")
            body = json.loads(raw_body.decode("utf-8"))
            if not isinstance(body, dict) or body.get("jsonrpc") != "2.0":
                return self._http_error(400, "invalid_jsonrpc_request")
            request_id = body.get("id")
            if isinstance(request_id, bool) or not isinstance(request_id, (str, int)):
                return self._http_error(400, "invalid_jsonrpc_id")
            method = body.get("method")
            if not isinstance(method, str) or normalized.get("mcp-method") != method:
                return self._rpc_error(request_id, -32600, "method header/body mismatch")
            params = body.get("params", {})
            if not isinstance(params, dict):
                return self._rpc_error(request_id, -32602, "params must be an object")
            if method == "server/discover":
                result: dict[str, object] = {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "serverInfo": {"name": self._server_name, "version": self._server_version},
                    "capabilities": {"tools": {}},
                }
            elif method == "tools/list":
                result = {
                    "tools": [
                        {
                            "name": tool.name,
                            "description": tool.description,
                            "inputSchema": dict(tool.input_schema),
                        }
                        for tool in sorted(self._tools.values(), key=lambda item: item.name)
                    ],
                    "ttlMs": self._list_ttl_ms,
                    "cacheScope": "private",
                }
            elif method == "tools/call":
                name = params.get("name")
                if not isinstance(name, str) or normalized.get("mcp-name") != name:
                    return self._rpc_error(request_id, -32602, "tool name header/body mismatch")
                tool = self._tools.get(name)
                if tool is None:
                    return self._rpc_error(request_id, -32601, "tool not found")
                arguments = params.get("arguments", {})
                if not isinstance(arguments, dict):
                    return self._rpc_error(request_id, -32602, "arguments must be an object")
                _validate_value(arguments)
                _matches_schema(arguments, tool.input_schema)
                idempotency_key = normalized.get("idempotency-key")
                payload = dict(arguments)
                if tool.idempotency_argument is not None:
                    supplied_key = payload.pop(tool.idempotency_argument, None)
                    if idempotency_key is not None and supplied_key is not None and idempotency_key != supplied_key:
                        return self._rpc_error(request_id, -32602, "conflicting idempotency keys")
                    idempotency_key = idempotency_key or supplied_key
                if tool.consequential and (
                    not isinstance(idempotency_key, str)
                    or not idempotency_key.strip()
                    or len(idempotency_key) > 256
                ):
                    return self._rpc_error(request_id, -32602, "consequential tool call requires an idempotency key")
                request_fingerprint = sha256(
                    f"{principal.tenant_id}:{principal.subject_id}:{request_id}".encode()
                ).hexdigest()[:32]
                request = APIRequest(
                    principal.tenant_id,
                    principal.subject_id,
                    tool.operation,
                    payload,
                    f"mcp-{request_fingerprint}",
                    _traceparent(normalized.get("traceparent")),
                    idempotency_key,
                    principal,
                )
                response = self._api.dispatch(request)
                result = {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {"status": response.status, "payload": response.payload},
                                separators=(",", ":"),
                                ensure_ascii=False,
                            ),
                        }
                    ],
                    "isError": response.status.lower() not in {"ok", "accepted", "success"},
                }
            else:
                return self._rpc_error(request_id, -32601, "method not supported")
            return self._json_response(
                200,
                {"jsonrpc": "2.0", "id": request_id, "result": result},
            )
        except AuthenticationError:
            return self._http_error(401, "unauthorized")
        except IdempotencyConflictError:
            return self._http_error(409, "idempotency_conflict")
        except ExecutionAPIError as exc:
            return self._http_error(409, exc.code)
        except PermissionError:
            return self._http_error(403, "forbidden")
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, KeyError):
            return self._http_error(400, "invalid_request")
        except Exception:
            return self._http_error(500, "platform_error")

    @staticmethod
    def _json_response(status_code: int, body: Mapping[str, object]) -> MCPHTTPResponse:
        encoded = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(encoded) > MAX_RESPONSE_BYTES:
            return MCPProtocolService._http_error(500, "response_too_large")
        return MCPHTTPResponse(
            status_code,
            {
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
            },
            encoded,
        )

    @classmethod
    def _rpc_error(cls, request_id: object, code: int, message: str) -> MCPHTTPResponse:
        return cls._json_response(
            200,
            {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}},
        )

    @staticmethod
    def _http_error(status_code: int, code: str) -> MCPHTTPResponse:
        encoded = json.dumps({"error": code}, separators=(",", ":")).encode("utf-8")
        return MCPHTTPResponse(
            status_code,
            {
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
            encoded,
        )
