"""Stateless MCP 2026-07-28 request adapter for the governed Platform API."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol, cast
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class MCPPlatformRequest:
    tenant_id: str
    subject_id: str
    operation: str
    payload: dict[str, object]
    request_id: str
    trace_id: str | None = None
    idempotency_key: str | None = None
    authenticated_principal: object | None = None


class MCPAuthenticatedPrincipal(Protocol):
    tenant_id: str
    subject_id: str
    scopes: frozenset[str]
    roles: frozenset[str]
    principal_type: str


class MCPPrincipalResolver(Protocol):
    def resolve(self, bearer_token: str) -> MCPAuthenticatedPrincipal: ...


class MCPPlatformResponse(Protocol):
    status: str
    payload: dict[str, object]


class MCPPlatformDispatcher(Protocol):
    def dispatch(self, request: object) -> MCPPlatformResponse: ...


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
    read_only: bool = False
    destructive: bool = False
    open_world: bool = True

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
        if self.consequential and self.read_only:
            raise ValueError("consequential MCP tools cannot be annotated read-only")
        if self.destructive and not self.consequential:
            raise ValueError("destructive MCP tools must be consequential")
        if self.idempotency_argument is not None and (
            not self.idempotency_argument
            or self.idempotency_argument != self.idempotency_argument.strip()
        ):
            raise ValueError("idempotency argument name must be normalized")
        if len(self.name) > 128 or re.fullmatch(r"[A-Za-z0-9_.-]+", self.name) is None:
            raise ValueError("MCP tool name must use 1-128 allowed ASCII characters")
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


class MCPRateLimiter(Protocol):
    """Injected shared rate-limit contract; implementations must be tenant-aware."""

    def allow(self, tenant_id: str, subject_id: str) -> bool: ...


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON numeric constant is not allowed: {value}")


def _headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in headers.items()}


def _traceparent(value: str | None) -> str | None:
    if value is None:
        return None
    if not _TRACEPARENT.fullmatch(value):
        raise ValueError("traceparent must use W3C Trace Context format")
    if value[:2] == "ff" or value[3:35] == "0" * 32 or value[36:52] == "0" * 16:
        raise ValueError("traceparent identifiers must not be all zero")
    return value


def _validate_origin(origin: str | None, allowed_origins: frozenset[str]) -> None:
    if origin is None:
        return
    if origin == "null" or origin not in allowed_origins:
        raise PermissionError("MCP Origin is not allowed")
    parsed = urlparse(origin)
    if (
        parsed.scheme not in {"https", "http"}
        or not parsed.netloc
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise PermissionError("MCP Origin is invalid")


def _validate_request_meta(params: Mapping[str, object], header_version: str) -> None:
    metadata = params.get("_meta")
    if not isinstance(metadata, Mapping):
        raise ValueError("MCP request requires per-request _meta")
    body_version = metadata.get("io.modelcontextprotocol/protocolVersion")
    if not isinstance(body_version, str) or body_version != header_version:
        raise ValueError("MCP protocol version header and request metadata must match")
    client_info = metadata.get("io.modelcontextprotocol/clientInfo")
    if client_info is not None:
        if not isinstance(client_info, Mapping):
            raise ValueError("MCP client identity metadata must be an object when supplied")
        for key in ("name", "version"):
            value = client_info.get(key)
            if not isinstance(value, str) or not value or value != value.strip():
                raise ValueError("MCP client identity fields must be normalized non-empty strings")
    capabilities = metadata.get("io.modelcontextprotocol/clientCapabilities")
    if not isinstance(capabilities, Mapping):
        raise ValueError("MCP request requires client capabilities metadata")
    _validate_value(metadata)


def _validate_value(value: object, *, depth: int = 0) -> None:
    if depth > MAX_NESTING_DEPTH:
        raise ValueError("MCP argument nesting exceeds safety limit")
    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            raise ValueError("MCP string argument exceeds safety limit")
        return
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite numeric arguments are not allowed")
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


def _matches_schema(
    value: object,
    schema: Mapping[str, object],
    path: str = "arguments",
    *,
    depth: int = 0,
) -> None:
    if depth > MAX_NESTING_DEPTH:
        raise ValueError("declared JSON schema exceeds nesting safety limit")
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
    enum = schema.get("enum")
    if isinstance(enum, list) and value not in enum:
        raise ValueError(f"{path} is not an allowed enum value")
    if "const" in schema and value != schema["const"]:
        raise ValueError(f"{path} does not match declared constant")
    if isinstance(value, str):
        min_length = schema.get("minLength", 0)
        max_length = schema.get("maxLength", MAX_STRING_LENGTH)
        if isinstance(min_length, int) and len(value) < min_length:
            raise ValueError(f"{path} is shorter than minLength")
        if isinstance(max_length, int) and len(value) > max_length:
            raise ValueError(f"{path} exceeds maxLength")
        pattern = schema.get("pattern")
        if pattern is not None:
            if not isinstance(pattern, str) or len(pattern) > 256:
                raise ValueError("declared string pattern is invalid or too long")
            try:
                if re.search(pattern, value) is None:
                    raise ValueError(f"{path} does not match declared pattern")
            except re.error as exc:
                raise ValueError("declared string pattern is invalid") from exc
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError(f"{path} must be a finite number")
        for keyword in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
            bound = schema.get(keyword)
            if bound is None:
                continue
            if not isinstance(bound, (int, float)) or isinstance(bound, bool):
                raise ValueError(f"declared {keyword} is invalid")
            if keyword == "minimum" and value < bound:
                raise ValueError(f"{path} violates {keyword}")
            if keyword == "maximum" and value > bound:
                raise ValueError(f"{path} violates {keyword}")
            if keyword == "exclusiveMinimum" and value <= bound:
                raise ValueError(f"{path} violates {keyword}")
            if keyword == "exclusiveMaximum" and value >= bound:
                raise ValueError(f"{path} violates {keyword}")
    if isinstance(value, (list, tuple)):
        minimum = schema.get("minItems", 0)
        maximum = schema.get("maxItems", MAX_ARGUMENTS)
        if isinstance(minimum, int) and len(value) < minimum:
            raise ValueError(f"{path} has fewer than minItems")
        if isinstance(maximum, int) and len(value) > maximum:
            raise ValueError(f"{path} exceeds maxItems")
        if schema.get("uniqueItems") is True:
            canonical = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            if len(canonical) != len(set(canonical)):
                raise ValueError(f"{path} contains duplicate items")
        item_schema = schema.get("items")
        if item_schema is not None:
            if not isinstance(item_schema, Mapping):
                raise ValueError("declared array items schema is invalid")
            for index, item in enumerate(value):
                _matches_schema(item, item_schema, f"{path}[{index}]", depth=depth + 1)
    if isinstance(value, Mapping):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, Mapping) or not isinstance(required, list):
            raise ValueError("declared JSON schema is invalid")
        if any(not isinstance(key, str) for key in required):
            raise ValueError("declared JSON schema required keys must be strings")
        minimum = schema.get("minProperties", 0)
        maximum = schema.get("maxProperties", MAX_ARGUMENTS)
        if isinstance(minimum, int) and len(value) < minimum:
            raise ValueError(f"{path} has fewer than minProperties")
        if isinstance(maximum, int) and len(value) > maximum:
            raise ValueError(f"{path} exceeds maxProperties")
        missing = [key for key in required if key not in value]
        if missing:
            raise ValueError(f"{path} is missing required properties")
        additional = schema.get("additionalProperties", False)
        undeclared = [key for key in value if key not in properties]
        if additional is False and undeclared:
            raise ValueError(f"{path} contains undeclared properties")
        if (
            additional is not False
            and additional is not True
            and not isinstance(additional, Mapping)
        ):
            raise ValueError("declared additionalProperties schema is invalid")
        for key, nested in value.items():
            child_schema = properties.get(key)
            if child_schema is None and isinstance(additional, Mapping):
                child_schema = additional
            if child_schema is not None:
                if not isinstance(child_schema, Mapping):
                    raise ValueError("declared JSON schema property is invalid")
                _matches_schema(nested, child_schema, f"{path}.{key}", depth=depth + 1)


class MCPProtocolService:
    """MCP JSON-RPC surface; every tool call becomes an authenticated Platform request."""

    def __init__(
        self,
        api: object,
        resolver: MCPPrincipalResolver,
        tools: tuple[MCPToolDefinition, ...],
        *,
        allowed_origins: tuple[str, ...] = (),
        rate_limiter: MCPRateLimiter | None = None,
        server_name: str = "tinlance-agent-platform",
        server_version: str = "1.1.0",
        list_ttl_ms: int = 30_000,
    ) -> None:
        if not server_name.strip() or not server_version.strip():
            raise ValueError("MCP server identity is required")
        if not 1_000 <= list_ttl_ms <= 300_000:
            raise ValueError("MCP list cache TTL must be between 1s and 5m")
        if rate_limiter is None:
            raise ValueError("MCP protocol service requires a shared rate limiter")
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
        self._api = cast(MCPPlatformDispatcher, api)
        self._resolver = resolver
        self._tools = {tool.name: tool for tool in tools}
        self._allowed_origins = origins
        self._rate_limiter = rate_limiter
        self._server_name = server_name
        self._server_version = server_version
        self._list_ttl_ms = list_ttl_ms

    def handle(self, headers: Mapping[str, str], raw_body: bytes) -> MCPHTTPResponse:
        normalized = _headers(headers)
        try:
            if len(raw_body) > MAX_REQUEST_BYTES:
                return self._http_error(413, "request_too_large")
            content_type = normalized.get("content-type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                return self._http_error(415, "json_required")
            _validate_origin(normalized.get("origin"), self._allowed_origins)
            token = normalized.get("authorization", "")
            if not token.startswith("Bearer ") or not token[7:].strip():
                return self._http_error(401, "unauthorized")
            try:
                principal = self._resolver.resolve(token[7:].strip())
            except PermissionError:
                return self._http_error(401, "unauthorized")
            if not self._rate_limiter.allow(principal.tenant_id, principal.subject_id):
                return self._http_error(429, "rate_limited")
            body = json.loads(
                raw_body.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
            if not isinstance(body, dict) or body.get("jsonrpc") != "2.0":
                return self._http_error(400, "invalid_jsonrpc_request")
            request_id = body.get("id")
            if (
                isinstance(request_id, bool)
                or not isinstance(request_id, (str, int))
                or (isinstance(request_id, str) and (not request_id or len(request_id) > 256))
            ):
                return self._http_error(400, "invalid_jsonrpc_id")
            header_version = normalized.get("mcp-protocol-version")
            if not header_version or header_version != header_version.strip():
                return self._rpc_http_error(400, request_id, -32020, "HeaderMismatch")
            if header_version != MCP_PROTOCOL_VERSION:
                return self._json_response(
                    400,
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {
                            "code": -32022,
                            "message": "UnsupportedProtocolVersion",
                            "data": {
                                "supported": [MCP_PROTOCOL_VERSION],
                                "requested": header_version,
                            },
                        },
                    },
                )
            method = body.get("method")
            params = body.get("params", {})
            if not isinstance(params, dict):
                return self._rpc_error(request_id, -32602, "params must be an object")
            metadata = params.get("_meta")
            body_version = (
                metadata.get("io.modelcontextprotocol/protocolVersion")
                if isinstance(metadata, Mapping)
                else None
            )
            if body_version != header_version:
                return self._rpc_http_error(400, request_id, -32020, "HeaderMismatch")
            if not isinstance(method, str) or normalized.get("mcp-method") != method:
                return self._rpc_http_error(400, request_id, -32020, "HeaderMismatch")
            _validate_request_meta(params, header_version)
            if method == "server/discover":
                result: dict[str, object] = {
                    "supportedVersions": [MCP_PROTOCOL_VERSION],
                    "capabilities": {"tools": {}},
                    "ttlMs": self._list_ttl_ms,
                    "cacheScope": "private",
                }
            elif method == "tools/list":
                result = {
                    "resultType": "complete",
                    "tools": [
                        {
                            "name": tool.name,
                            "description": tool.description,
                            "inputSchema": dict(tool.input_schema),
                            "annotations": {
                                "readOnlyHint": tool.read_only,
                                "destructiveHint": tool.destructive,
                                "idempotentHint": tool.idempotency_argument is not None,
                                "openWorldHint": tool.open_world,
                            },
                        }
                        for tool in sorted(self._tools.values(), key=lambda item: item.name)
                    ],
                    "ttlMs": self._list_ttl_ms,
                    "cacheScope": "private",
                }
            elif method == "tools/call":
                name = params.get("name")
                if not isinstance(name, str) or normalized.get("mcp-name") != name:
                    return self._rpc_http_error(400, request_id, -32020, "HeaderMismatch")
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
                    if (
                        idempotency_key is not None
                        and supplied_key is not None
                        and idempotency_key != supplied_key
                    ):
                        return self._rpc_error(request_id, -32602, "conflicting idempotency keys")
                    idempotency_key = idempotency_key or supplied_key
                if tool.consequential and (
                    not isinstance(idempotency_key, str)
                    or len(idempotency_key) < 16
                    or len(idempotency_key) > 256
                    or not idempotency_key.isascii()
                    or any(ord(char) < 33 or ord(char) > 126 for char in idempotency_key)
                ):
                    return self._rpc_error(
                        request_id,
                        -32602,
                        "consequential tool call requires a normalized idempotency key",
                    )
                request_fingerprint = sha256(
                    f"{principal.tenant_id}:{principal.subject_id}:{request_id}".encode()
                ).hexdigest()[:32]
                traceparent = _traceparent(normalized.get("traceparent"))
                trace_id = traceparent.split("-")[1] if traceparent is not None else None
                request = MCPPlatformRequest(
                    principal.tenant_id,
                    principal.subject_id,
                    tool.operation,
                    payload,
                    f"mcp-{request_fingerprint}",
                    trace_id,
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
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": self._decorate_result(result),
                },
            )
        except PermissionError as exc:
            status = getattr(exc, "http_status", 403)
            code = getattr(exc, "code", "forbidden")
            safe_status = status if isinstance(status, int) else 403
            safe_code = code if isinstance(code, str) else "forbidden"
            return self._http_error(safe_status, safe_code)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
            status = getattr(exc, "http_status", 400)
            code = getattr(exc, "code", "invalid_request")
            safe_status = status if isinstance(status, int) else 400
            safe_code = code if isinstance(code, str) else "invalid_request"
            return self._http_error(safe_status, safe_code)
        except Exception:
            return self._http_error(500, "platform_error")

    def _decorate_result(self, value: dict[str, object]) -> dict[str, object]:
        result = dict(value)
        result.setdefault("resultType", "complete")
        metadata = result.get("_meta")
        result_metadata = dict(metadata) if isinstance(metadata, Mapping) else {}
        result_metadata.setdefault(
            "io.modelcontextprotocol/serverInfo",
            {"name": self._server_name, "version": self._server_version},
        )
        result["_meta"] = result_metadata
        return result

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
    def _rpc_http_error(
        cls, status_code: int, request_id: object, code: int, message: str
    ) -> MCPHTTPResponse:
        return cls._json_response(
            status_code,
            {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}},
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
