"""Governed read-only HTTP adapter for World Intelligence queries."""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from tinlance_agent_platform_contracts import RiskTier

from .gateway import MCPTool, MCPToolGateway, ToolScope
from .protocol import MCPToolDefinition

MAX_RESPONSE_BYTES = 1_048_576
DEFAULT_TIMEOUT_SECONDS = 5.0
_PURPOSE_VALUE = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")
_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")


class WorldIntelligenceTokenIssuer(Protocol):
    """Platform identity adapter; purpose must be included as a signed token claim."""

    def issue_token(
        self,
        *,
        tenant_id: str,
        subject_id: str,
        audience: str,
        scopes: frozenset[str],
        purpose: str,
        request_id: str,
        traceparent: str | None,
        expires_in_seconds: int,
    ) -> str: ...


@dataclass(frozen=True, slots=True)
class WorldIntelligenceHTTPResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes


class WorldIntelligenceHTTPClient(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> WorldIntelligenceHTTPResponse: ...


class WorldIntelligenceTransportError(RuntimeError):
    def __init__(self, status_code: int | None, *, retryable: bool = False) -> None:
        super().__init__("World Intelligence request failed")
        self.status_code = status_code
        self.retryable = retryable


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        file: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


class _UrllibWorldIntelligenceHTTPClient:
    """Bounded HTTP client with redirects and ambient proxy configuration disabled."""

    def __init__(self, *, max_response_bytes: int = MAX_RESPONSE_BYTES) -> None:
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())
        self._max_response_bytes = max_response_bytes

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> WorldIntelligenceHTTPResponse:
        request = Request(url, data=body, headers=dict(headers), method=method)
        try:
            response = self._opener.open(request, timeout=timeout_seconds)
        except HTTPError as exc:
            response = exc
        except (URLError, TimeoutError, OSError) as exc:
            raise WorldIntelligenceTransportError(None, retryable=True) from exc
        with response:
            response_body = response.read(self._max_response_bytes + 1)
            if len(response_body) > self._max_response_bytes:
                raise WorldIntelligenceTransportError(None)
            return WorldIntelligenceHTTPResponse(
                response.status,
                {key.lower(): value for key, value in response.headers.items()},
                response_body,
            )


@dataclass(frozen=True, slots=True)
class _QuerySpec:
    capability: str
    resource: str
    route: str


_QUERY_SPECS: dict[str, _QuerySpec] = {
    "world_intelligence_query_entities": _QuerySpec(
        "world-intelligence.query_entity", "world-intelligence://entities", "/v1/entities"
    ),
    "world_intelligence_query_events": _QuerySpec(
        "world-intelligence.query_event", "world-intelligence://events", "/v1/events"
    ),
    "world_intelligence_query_world_state": _QuerySpec(
        "world-intelligence.query_world_state",
        "world-intelligence://world-state",
        "/v1/world-state",
    ),
    "world_intelligence_query_changes": _QuerySpec(
        "world-intelligence.query_changes", "world-intelligence://changes", "/v1/changes"
    ),
    "world_intelligence_query_signals": _QuerySpec(
        "world-intelligence.query_signals", "world-intelligence://signals", "/v1/signals"
    ),
    "world_intelligence_query_evidence": _QuerySpec(
        "world-intelligence.query_evidence", "world-intelligence://evidence", "/v1/evidence"
    ),
    "world_intelligence_query_provenance": _QuerySpec(
        "world-intelligence.query_provenance", "world-intelligence://provenance", "/v1/provenance"
    ),
    "world_intelligence_query_regions": _QuerySpec(
        "world-intelligence.query_region", "world-intelligence://regions", "/v1/regions"
    ),
}


def _display_name(name: str) -> str:
    return name.removeprefix("world_intelligence_query_").replace("_", " ")


WORLD_INTELLIGENCE_TOOL_REGISTRATIONS: tuple[MCPTool, ...] = tuple(
    MCPTool(
        name=name,
        description=(f"Read World Intelligence {_display_name(name)} under Platform policy."),
        capability=spec.capability,
        resource_pattern=spec.resource,
        action="read",
        risk=RiskTier.LOW,
    )
    for name, spec in _QUERY_SPECS.items()
)


def register_world_intelligence_tools(gateway: MCPToolGateway) -> None:
    """Register immutable read-only World Intelligence tools on a governed gateway."""
    for tool in WORLD_INTELLIGENCE_TOOL_REGISTRATIONS:
        gateway.register(tool)


class WorldIntelligenceHTTPTransport:
    """Platform-owned read transport. It never forwards the inbound caller bearer token."""

    def __init__(
        self,
        *,
        base_url: str,
        audience: str,
        token_issuer: WorldIntelligenceTokenIssuer,
        http_client: WorldIntelligenceHTTPClient | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        allow_loopback_http: bool = False,
    ) -> None:
        parsed = urlsplit(base_url)
        host = parsed.hostname
        if (
            parsed.scheme not in {"https", "http"}
            or host is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("World Intelligence base URL must be an HTTP(S) origin")
        if parsed.scheme != "https":
            try:
                loopback = host.lower() == "localhost" or ipaddress.ip_address(host).is_loopback
            except ValueError:
                loopback = False
            if not allow_loopback_http or not loopback:
                raise ValueError(
                    "plain HTTP is allowed only for explicitly enabled loopback development"
                )
        if audience != "world-intelligence" or audience != audience.strip():
            raise ValueError("World Intelligence audience must be the exact registered audience")
        if not 0.1 <= timeout_seconds <= 30:
            raise ValueError("World Intelligence timeout must be between 0.1 and 30 seconds")
        self._base_url = f"{parsed.scheme}://{parsed.netloc}"
        self._audience = audience
        self._token_issuer = token_issuer
        self._http = http_client or _UrllibWorldIntelligenceHTTPClient()
        self._timeout = timeout_seconds

    def call(
        self,
        tool_name: str,
        arguments: Mapping[str, object],
        scope: ToolScope,
    ) -> dict[str, object]:
        spec = _QUERY_SPECS.get(tool_name)
        if spec is None:
            raise LookupError("World Intelligence query tool is not registered")
        if (
            scope.capability != spec.capability
            or scope.resource != spec.resource
            or not scope.subject_id
            or not scope.request_id
        ):
            raise PermissionError("World Intelligence query lacks authenticated Platform scope")
        if not set(arguments).issubset({"purpose", "limit", "cursor"}):
            raise ValueError("World Intelligence query contains unsupported arguments")
        purpose = arguments.get("purpose")
        if not isinstance(purpose, str) or not _PURPOSE_VALUE.fullmatch(purpose):
            raise ValueError("an authorized normalized query purpose is required")
        limit = arguments.get("limit", 100)
        cursor = arguments.get("cursor", 0)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be an integer between 1 and 1000")
        if isinstance(cursor, bool) or not isinstance(cursor, int) or cursor < 0:
            raise ValueError("cursor must be a non-negative integer")
        token = self._token_issuer.issue_token(
            tenant_id=scope.tenant_id,
            subject_id=scope.subject_id,
            audience=self._audience,
            scopes=frozenset({"world-intelligence:query"}),
            purpose=purpose,
            request_id=scope.request_id,
            traceparent=scope.traceparent,
            expires_in_seconds=60,
        )
        if not token or token != token.strip() or any(character.isspace() for character in token):
            raise PermissionError("Platform token issuer returned an invalid downstream token")
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "X-Tinlance-Tenant-ID": scope.tenant_id,
            "X-Tinlance-Subject-ID": scope.subject_id,
            "X-Tinlance-Purpose": purpose,
            "X-Request-ID": scope.request_id,
        }
        if scope.traceparent is not None:
            headers["traceparent"] = scope.traceparent
        url = f"{self._base_url}{spec.route}?{urlencode({'limit': limit, 'cursor': cursor})}"
        response = self._http.request(
            "GET", url, headers=headers, body=None, timeout_seconds=self._timeout
        )
        if response.status_code != 200:
            raise WorldIntelligenceTransportError(
                response.status_code,
                retryable=response.status_code in {408, 425, 429, 500, 502, 503, 504},
            )
        if len(response.body) > MAX_RESPONSE_BYTES:
            raise WorldIntelligenceTransportError(response.status_code)
        if response.headers.get("content-type", "").split(";", 1)[0].lower() != "application/json":
            raise WorldIntelligenceTransportError(response.status_code)
        try:
            decoded = json.loads(response.body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise WorldIntelligenceTransportError(response.status_code) from exc
        if not isinstance(decoded, dict) or not isinstance(decoded.get("items"), list):
            raise WorldIntelligenceTransportError(response.status_code)
        if any(not isinstance(item, dict) for item in decoded["items"]):
            raise WorldIntelligenceTransportError(response.status_code)
        next_cursor = decoded.get("next_cursor")
        if next_cursor is not None and not isinstance(next_cursor, str):
            raise WorldIntelligenceTransportError(response.status_code)
        total = decoded.get("total")
        if total is not None and (not isinstance(total, int) or isinstance(total, bool)):
            raise WorldIntelligenceTransportError(response.status_code)
        return decoded


def _query_schema() -> dict[str, object]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["purpose"],
        "properties": {
            "purpose": {"type": "string", "pattern": "^[a-z][a-z0-9._:-]{0,127}$"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
            "cursor": {"type": "integer", "minimum": 0, "default": 0},
        },
    }


WORLD_INTELLIGENCE_MCP_TOOL_DEFINITIONS: tuple[MCPToolDefinition, ...] = tuple(
    MCPToolDefinition(
        name,
        (f"Read World Intelligence {_display_name(name)} through Platform policy."),
        f"world_intelligence.{name.removeprefix('world_intelligence_')}",
        _query_schema(),
        read_only=True,
        open_world=False,
    )
    for name in _QUERY_SPECS
)

def with_world_intelligence_tools(
    existing: tuple[MCPToolDefinition, ...],
) -> tuple[MCPToolDefinition, ...]:
    """Return a protocol tool set with World Intelligence tools, rejecting collisions."""
    combined = (*existing, *WORLD_INTELLIGENCE_MCP_TOOL_DEFINITIONS)
    names = [tool.name for tool in combined]
    operations = [tool.operation for tool in combined]
    if len(names) != len(set(names)) or len(operations) != len(set(operations)):
        raise ValueError("MCP tool names and operations must be unique")
    return combined


WORLD_INTELLIGENCE_OPERATION_TO_TOOL: dict[str, str] = {
    definition.operation: definition.name for definition in WORLD_INTELLIGENCE_MCP_TOOL_DEFINITIONS
}
