"""Governed HTTP adapter for Tinlance Web Intelligence (TWI).

The adapter mints a short-lived, audience-bound Platform token for every downstream call.
It never forwards the inbound MCP bearer token. Consequential source-evidence export is
registered with a mandatory approval gate and a required idempotency key.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Mapping
from dataclasses import dataclass
from http.client import HTTPResponse
from typing import Protocol
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import UUID

from tinlance_agent_platform_contracts import RiskTier

from .gateway import MCPTool, MCPToolGateway, ToolScope

MAX_RESPONSE_BYTES = 1_048_576
DEFAULT_TIMEOUT_SECONDS = 5.0
_IDEMPOTENCY_HEADER = "Idempotency-Key"


class TWIServiceTokenIssuer(Protocol):
    """Platform identity adapter that mints a TWI-audience token for a caller."""

    def issue_token(
        self,
        *,
        tenant_id: str,
        subject_id: str,
        audience: str,
        scopes: frozenset[str],
        request_id: str,
        traceparent: str | None,
        expires_in_seconds: int,
    ) -> str: ...


@dataclass(frozen=True, slots=True)
class TWIHTTPResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes


class TWIHTTPClient(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> TWIHTTPResponse: ...


class TWITransportError(RuntimeError):
    def __init__(self, status_code: int | None, *, retryable: bool = False) -> None:
        super().__init__("Tinlance Web Intelligence request failed")
        self.status_code = status_code
        self.retryable = retryable


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        file: HTTPResponse,
        code: int,
        message: str,
        headers: Mapping[str, str],
        new_url: str,
    ) -> None:
        return None


class _UrllibTWIHTTPClient:
    """Small bounded HTTP client with redirects and environment proxies disabled."""

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
    ) -> TWIHTTPResponse:
        request = Request(url, data=body, headers=dict(headers), method=method)
        try:
            response = self._opener.open(request, timeout=timeout_seconds)
        except HTTPError as exc:
            response = exc
        with response:
            response_body = response.read(self._max_response_bytes + 1)
            if len(response_body) > self._max_response_bytes:
                raise TWITransportError(None) from None
            response_headers = {
                key.lower(): value for key, value in response.headers.items()
            }
            return TWIHTTPResponse(response.status, response_headers, response_body)


@dataclass(frozen=True, slots=True)
class _ToolSpec:
    capability: str
    action: str
    resource_pattern: str
    required_scope: str
    method: str
    route: str
    idempotency_argument: str | None = None
    risk: RiskTier = RiskTier.LOW
    requires_approval: bool = False


_TOOL_SPECS: dict[str, _ToolSpec] = {
    "twi_search": _ToolSpec(
        "web.search", "submit", "web://search/*", "twi:search", "POST", "/v1/jobs",
        "idempotency_key", RiskTier.LOW,
    ),
    "twi_fetch": _ToolSpec(
        "web.fetch", "submit", "web://fetch/*", "twi:fetch", "POST", "/v1/jobs",
        "idempotency_key", RiskTier.MEDIUM,
    ),
    "twi_browser_navigate": _ToolSpec(
        "web.browser.navigate", "navigate", "web://browser/*", "twi:browser", "POST", "/v1/jobs",
        "idempotency_key", RiskTier.MEDIUM,
    ),
    "twi_job_read": _ToolSpec(
        "web.job.read", "read", "twi://jobs/{job_id}", "twi:jobs:read", "GET", "/v1/jobs/{job_id}"
    ),
    "twi_job_cancel": _ToolSpec(
        "web.job.cancel", "cancel", "twi://jobs/{job_id}", "twi:jobs:cancel", "POST",
        "/v1/jobs/{job_id}/cancel", risk=RiskTier.LOW,
    ),
    "twi_research_verify": _ToolSpec(
        "web.research.verify", "verify", "twi://research/verification/*",
        "twi:research:verify", "POST", "/v1/research/verify",
    ),
    "twi_world_intelligence_export": _ToolSpec(
        "world-intelligence.source-evidence.export", "submit",
        "world-intelligence://source-evidence/*", "twi:observations:export",
        "POST", "/v1/integrations/world-intelligence/exports",
        "idempotency_key", RiskTier.HIGH, True,
    ),
    "twi_world_intelligence_export_status": _ToolSpec(
        "world-intelligence.source-evidence.read", "read",
        "twi://world-intelligence/exports/{event_id}", "twi:observations:export:read",
        "GET", "/v1/integrations/world-intelligence/exports/{event_id}",
    ),
}


TWI_TOOL_REGISTRATIONS: tuple[MCPTool, ...] = tuple(
    MCPTool(
        name=name,
        description=description,
        capability=spec.capability,
        resource_pattern=spec.resource_pattern,
        action=spec.action,
        risk=spec.risk,
        requires_approval=spec.requires_approval,
        idempotency_argument=spec.idempotency_argument,
    )
    for name, description, spec in (
        (
            "twi_search",
            "Submit a bounded web search and return a durable job reference.",
            _TOOL_SPECS["twi_search"],
        ),
        (
            "twi_fetch",
            "Submit a policy-checked public web fetch and return a durable job reference.",
            _TOOL_SPECS["twi_fetch"],
        ),
        (
            "twi_browser_navigate",
            "Capture a public web page in a fresh isolated read-only browser context.",
            _TOOL_SPECS["twi_browser_navigate"],
        ),
        (
            "twi_job_read",
            "Read a job owned by the authenticated subject in the current tenant.",
            _TOOL_SPECS["twi_job_read"],
        ),
        (
            "twi_job_cancel",
            "Request cancellation of a job owned by the authenticated subject.",
            _TOOL_SPECS["twi_job_cancel"],
        ),
        (
            "twi_research_verify",
            "Verify that citation excerpts match caller-authorized TWI captures.",
            _TOOL_SPECS["twi_research_verify"],
        ),
        (
            "twi_world_intelligence_export",
            "Export verified source evidence to World Intelligence after human approval.",
            _TOOL_SPECS["twi_world_intelligence_export"],
        ),
        (
            "twi_world_intelligence_export_status",
            "Read the status of a source-evidence export owned by the authenticated subject.",
            _TOOL_SPECS["twi_world_intelligence_export_status"],
        ),
    )
)


def register_twi_tools(gateway: MCPToolGateway) -> None:
    """Register immutable TWI tool contracts on a Platform-governed gateway."""

    for tool in TWI_TOOL_REGISTRATIONS:
        gateway.register(tool)


class TWIHTTPTransport:
    """MCP transport adapter that invokes TWI's authenticated HTTP API."""

    def __init__(
        self,
        *,
        base_url: str,
        audience: str,
        token_issuer: TWIServiceTokenIssuer,
        http_client: TWIHTTPClient | None = None,
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
            raise ValueError("TWI base URL must be an HTTP(S) origin without credentials or path")
        if parsed.scheme != "https":
            try:
                loopback = host.lower() == "localhost" or ipaddress.ip_address(host).is_loopback
            except ValueError:
                loopback = False
            if not allow_loopback_http or not loopback:
                raise ValueError("plain HTTP is allowed only for explicitly enabled loopback development")
        if not audience or audience != audience.strip():
            raise ValueError("TWI audience must be explicit and normalized")
        if not 0.1 <= timeout_seconds <= 30:
            raise ValueError("TWI timeout must be between 0.1 and 30 seconds")
        self._base_url = f"{parsed.scheme}://{parsed.netloc}"
        self._audience = audience
        self._token_issuer = token_issuer
        self._http = http_client or _UrllibTWIHTTPClient()
        self._timeout = timeout_seconds

    def call(
        self,
        tool_name: str,
        arguments: Mapping[str, object],
        scope: ToolScope,
    ) -> dict[str, object]:
        spec = _TOOL_SPECS.get(tool_name)
        if spec is None:
            raise LookupError("TWI tool is not registered")
        if (
            scope.capability != spec.capability
            or scope.resource != spec.resource_pattern
            or not scope.subject_id
            or not scope.request_id
        ):
            raise PermissionError("TWI call is missing its authenticated subject/request scope")
        if spec.idempotency_argument is not None:
            key = arguments.get(spec.idempotency_argument)
            if (
                not isinstance(key, str)
                or not 16 <= len(key) <= 256
                or not key.isascii()
                or any(ord(character) < 33 or ord(character) > 126 for character in key)
            ):
                raise ValueError("TWI call requires a normalized idempotency key")
        path, payload = self._request_for(tool_name, arguments)
        token = self._token_issuer.issue_token(
            tenant_id=scope.tenant_id,
            subject_id=scope.subject_id,
            audience=self._audience,
            scopes=frozenset({spec.required_scope}),
            request_id=scope.request_id,
            traceparent=scope.traceparent,
            expires_in_seconds=60,
        )
        if not token or token != token.strip() or any(character.isspace() for character in token):
            raise PermissionError("Platform token issuer returned an invalid downstream token")
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "X-Request-ID": scope.request_id,
        }
        if scope.traceparent is not None:
            headers["traceparent"] = scope.traceparent
        if spec.idempotency_argument is not None:
            headers[_IDEMPOTENCY_HEADER] = str(arguments[spec.idempotency_argument])
        body = None if payload is None else json.dumps(
            payload, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        if body is not None:
            headers["Content-Type"] = "application/json"
        response = self._http.request(
            spec.method,
            f"{self._base_url}{path}",
            headers=headers,
            body=body,
            timeout_seconds=self._timeout,
        )
        if response.status_code not in {200, 201, 202, 204}:
            raise TWITransportError(
                response.status_code,
                retryable=response.status_code in {408, 425, 429, 500, 502, 503, 504},
            )
        if response.status_code == 204 or not response.body:
            return {}
        content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
        if content_type != "application/json":
            raise TWITransportError(response.status_code)
        try:
            decoded = json.loads(response.body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise TWITransportError(response.status_code) from exc
        if not isinstance(decoded, dict):
            raise TWITransportError(response.status_code)
        return decoded

    @staticmethod
    def _request_for(
        tool_name: str, arguments: Mapping[str, object]
    ) -> tuple[str, dict[str, object] | None]:
        if tool_name == "twi_search":
            return "/v1/jobs", {
                "kind": "search",
                "payload": {
                    "query": arguments.get("query"),
                    **({"limit": arguments["limit"]} if "limit" in arguments else {}),
                },
            }
        if tool_name == "twi_fetch":
            return "/v1/jobs", {"kind": "fetch", "payload": {"url": arguments.get("url")}}
        if tool_name == "twi_browser_navigate":
            browser_fields = ("url", "wait_until", "timeout_ms", "include_screenshot")
            return "/v1/jobs", {
                "kind": "browser",
                "payload": {key: arguments[key] for key in browser_fields if key in arguments},
            }
        if tool_name == "twi_job_read":
            return f"/v1/jobs/{quote(str(arguments.get('job_id', ''), safe=''))}", None
        if tool_name == "twi_job_cancel":
            return f"/v1/jobs/{quote(str(arguments.get('job_id', ''), safe=''))}/cancel", {}
        if tool_name == "twi_research_verify":
            return "/v1/research/verify", {"claims": arguments.get("claims")}
        if tool_name == "twi_world_intelligence_export":
            return "/v1/integrations/world-intelligence/exports", {
                key: arguments[key] for key in ("claim_id", "statement", "job_id", "quote")
            }
        if tool_name == "twi_world_intelligence_export_status":
            event_id = arguments.get("event_id")
            return (
                f"/v1/integrations/world-intelligence/exports/{quote(str(event_id), safe='')}",
                None,
            )
        raise LookupError("TWI tool is not registered")
