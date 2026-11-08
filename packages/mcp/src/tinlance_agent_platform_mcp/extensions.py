"""Governed HTTP adapter for Tinlance Extensions job operations.

The adapter mints short-lived, audience-bound Platform service tokens. It never
forwards inbound credentials and exposes only explicitly registered operations.
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import UUID

from tinlance_agent_platform_contracts import RiskTier

from .gateway import MCPTool, MCPToolGateway, ToolScope

EXTENSIONS_AUDIENCE = "tinlance-extensions-api"
DEFAULT_TIMEOUT_SECONDS = 5.0
MAX_RESPONSE_BYTES = 1_048_576
_JOB_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)


class ExtensionsServiceTokenIssuer(Protocol):
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
        principal_type: str = "user",
    ) -> str: ...


@dataclass(frozen=True, slots=True)
class ExtensionsHTTPResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes


class ExtensionsHTTPClient(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> ExtensionsHTTPResponse: ...


class ExtensionsTransportError(RuntimeError):
    def __init__(self, status_code: int | None, *, retryable: bool = False) -> None:
        super().__init__("Tinlance Extensions request failed")
        self.status_code = status_code
        self.retryable = retryable


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, request: Request, file: Any, code: int, message: str, headers: Any, new_url: str
    ) -> None:
        return None


class _UrllibExtensionsHTTPClient:
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
    ) -> ExtensionsHTTPResponse:
        request = Request(url, data=body, headers=dict(headers), method=method)
        try:
            response = self._opener.open(request, timeout=timeout_seconds)
        except HTTPError as exc:
            response = exc
        with response:
            payload = response.read(self._max_response_bytes + 1)
            if len(payload) > self._max_response_bytes:
                raise ExtensionsTransportError(None) from None
            return ExtensionsHTTPResponse(
                response.status,
                {key.lower(): value for key, value in response.headers.items()},
                payload,
            )


EXTENSIONS_JOB_CANCEL = MCPTool(
    name="extensions_job_cancel",
    description="Request cancellation of a tenant-owned Tinlance Extensions job.",
    capability="extensions.jobs.cancel",
    resource_pattern="extensions://jobs/{job_id}",
    action="cancel",
    risk=RiskTier.LOW,
)

EXTENSIONS_TOOL_REGISTRATIONS: tuple[MCPTool, ...] = (EXTENSIONS_JOB_CANCEL,)


def register_extensions_tools(gateway: MCPToolGateway) -> None:
    for tool in EXTENSIONS_TOOL_REGISTRATIONS:
        gateway.register(tool)


class ExtensionsHTTPTransport:
    """Send a Platform-minted, tenant/subject-scoped token to the Extensions API."""

    def __init__(
        self,
        *,
        base_url: str,
        token_issuer: ExtensionsServiceTokenIssuer,
        http_client: ExtensionsHTTPClient | None = None,
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
            raise ValueError(
                "Extensions base URL must be an HTTP(S) origin without credentials or path"
            )
        if parsed.scheme != "https":
            try:
                loopback = host.lower() == "localhost" or ipaddress.ip_address(host).is_loopback
            except ValueError:
                loopback = False
            if not allow_loopback_http or not loopback:
                raise ValueError(
                    "plain HTTP is allowed only for explicitly enabled loopback development"
                )
        if not 0.1 <= timeout_seconds <= 30:
            raise ValueError("Extensions timeout must be between 0.1 and 30 seconds")
        self._base_url = f"{parsed.scheme}://{parsed.netloc}"
        self._issuer = token_issuer
        self._http = http_client or _UrllibExtensionsHTTPClient()
        self._timeout = timeout_seconds

    def call(
        self, tool_name: str, arguments: Mapping[str, object], scope: ToolScope
    ) -> dict[str, object]:
        if tool_name != "extensions_job_cancel":
            raise LookupError("Extensions tool is not registered")
        if (
            scope.capability != EXTENSIONS_JOB_CANCEL.capability
            or scope.resource != EXTENSIONS_JOB_CANCEL.resource_pattern
            or not scope.subject_id
            or not scope.request_id
        ):
            raise PermissionError("Extensions call is missing authenticated subject/request scope")
        job_id = arguments.get("job_id")
        if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id):
            raise ValueError("Extensions job ID must be a canonical UUID")
        if str(UUID(job_id)) != job_id.lower():
            raise ValueError("Extensions job ID must be normalized")
        token = self._issuer.issue_token(
            tenant_id=scope.tenant_id,
            subject_id=scope.subject_id,
            audience=EXTENSIONS_AUDIENCE,
            scopes=frozenset({"extensions:jobs:cancel"}),
            request_id=scope.request_id,
            traceparent=scope.traceparent,
            expires_in_seconds=60,
            principal_type=scope.principal_type,
        )
        if not token or token != token.strip() or any(character.isspace() for character in token):
            raise PermissionError("Platform token issuer returned an invalid Extensions token")
        response = self._http.request(
            "POST",
            f"{self._base_url}/v1/jobs/{quote(job_id, safe='')}/cancel",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {token}",
                "X-Request-ID": scope.request_id,
                **({"traceparent": scope.traceparent} if scope.traceparent else {}),
            },
            body=None,
            timeout_seconds=self._timeout,
        )
        if response.status_code not in {200, 201, 202, 204}:
            raise ExtensionsTransportError(
                response.status_code,
                retryable=response.status_code in {408, 425, 429, 500, 502, 503, 504},
            )
        if response.status_code == 204 or not response.body:
            return {}
        content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
        if content_type != "application/json" and not content_type.endswith("+json"):
            raise ExtensionsTransportError(response.status_code)
        try:
            decoded = json.loads(response.body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ExtensionsTransportError(response.status_code) from exc
        if not isinstance(decoded, dict):
            raise ExtensionsTransportError(response.status_code)
        return decoded
