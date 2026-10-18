"""Provider-neutral A2A contracts with bounded delegation and endpoint trust.

Discovery metadata is descriptive, not authoritative. Remote communication must
enter the normal Platform identity, authorization and execution boundaries.
"""

from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import math
import re
import socket
import ssl
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast
from urllib.parse import urlparse
from uuid import UUID, uuid4

import rfc8785

A2A_SPECIFICATION_VERSION = "1.0.1"
A2A_PROTOCOL_VERSION = "1.0"
MAX_DELEGATION_TTL_SECONDS = 3600
MAX_REMOTE_RESPONSE_BYTES = 1_048_576


class AgentCardSignatureVerifier(Protocol):
    """Verifies a JWS signing input against a trusted key registry."""

    def verify(self, key_id: str, algorithm: str, signing_input: bytes, signature: str) -> bool: ...


class RemoteCredentialProvider(Protocol):
    """Issue short-lived credentials bound to a Platform-validated delegation.

    Implementations must verify that the delegation was minted by the trusted
    Platform authority; callers must not turn a locally constructed dataclass
    into remote authority.
    """

    def issue(self, delegation: RemoteDelegation) -> str: ...


class RemoteAgentTransport(Protocol):
    """Transport must pin one of the validated addresses and must not follow redirects."""

    def post(
        self,
        endpoint: str,
        resolved_addresses: tuple[str, ...],
        bearer_token: str,
        payload: Mapping[str, object],
        *,
        timeout_seconds: float,
        max_response_bytes: int,
        protocol_version: str,
        content_type: str,
    ) -> Mapping[str, object]: ...


def _required(value: str, name: str) -> None:
    if not value or value != value.strip():
        raise ValueError(f"{name} must be non-empty and normalized")


def _validate_url(endpoint: str, *, require_https: bool) -> tuple[str, str]:
    parsed = urlparse(endpoint)
    allowed_schemes = {"https"} if require_https else {"https", "http"}
    if parsed.scheme not in allowed_schemes or not parsed.hostname:
        raise ValueError("remote agent endpoint must be an absolute secure URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("remote agent endpoint must not embed credentials")
    if parsed.fragment or parsed.query:
        raise ValueError("remote agent endpoint must not contain query parameters or fragments")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("remote agent endpoint port is invalid") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("remote agent endpoint port is invalid")
    hostname = parsed.hostname.rstrip(".").lower()
    local_development = (
        not require_https
        and parsed.scheme == "http"
        and (hostname == "localhost" or hostname.endswith(".localhost"))
    )
    if (hostname == "localhost" or hostname.endswith(".localhost")) and not local_development:
        raise ValueError("remote agent endpoint must not target localhost")
    if parsed.scheme == "http" and not local_development:
        try:
            local_address = ipaddress.ip_address(hostname)
        except ValueError:
            local_address = None
        if local_address is None or not local_address.is_loopback:
            raise ValueError("cleartext HTTP is allowed only for loopback development")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        loopback_development = not require_https and parsed.scheme == "http" and address.is_loopback
        if not loopback_development:
            raise ValueError("remote agent endpoint must not target a non-public IP address")
    return hostname, parsed.scheme


def validate_remote_endpoint(
    endpoint: str,
    resolver: Callable[[str], Iterable[str]],
) -> tuple[str, ...]:
    """Resolve once and reject any non-public destination before outbound I/O.

    The transport must pin its connection to the returned addresses and must not
    follow redirects; re-resolving after validation would reintroduce DNS rebinding.
    """
    hostname, scheme = _validate_url(endpoint, require_https=True)
    if scheme != "https":
        raise ValueError("remote agent transport requires HTTPS")
    raw_addresses = tuple(resolver(hostname))
    if not raw_addresses:
        raise ValueError("remote agent endpoint did not resolve")
    normalized: list[str] = []
    for raw in raw_addresses:
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise ValueError("endpoint resolver returned an invalid IP address") from exc
        if not address.is_global:
            raise ValueError("remote agent endpoint resolves to a non-public IP address")
        value = str(address)
        if value not in normalized:
            normalized.append(value)
    return tuple(normalized)


@dataclass(frozen=True, slots=True)
class AgentSkill:
    skill_id: str
    description: str
    capabilities: frozenset[str]

    def __post_init__(self) -> None:
        _required(self.skill_id, "skill_id")
        _required(self.description, "skill description")
        for capability in self.capabilities:
            _required(capability, "skill capability")


@dataclass(frozen=True, slots=True)
class AgentCard:
    agent_id: UUID
    protocol_version: str
    name: str
    description: str
    endpoint: str
    skills: tuple[AgentSkill, ...]
    authentication_schemes: tuple[str, ...]
    card_version: str
    signature: str | None = None
    key_id: str | None = None
    signature_algorithm: str | None = None
    security_scheme_details: Mapping[str, Mapping[str, object]] | None = None

    def validate(self, *, require_https: bool = True) -> None:
        _validate_url(self.endpoint, require_https=require_https)
        if self.protocol_version != A2A_PROTOCOL_VERSION:
            raise ValueError("unsupported A2A protocol version")
        _required(self.name, "agent name")
        _required(self.description, "agent description")
        _required(self.card_version, "agent card version")
        if not self.skills:
            raise ValueError("agent card must declare at least one skill")
        if not self.authentication_schemes:
            raise ValueError("A2A Agent Card must declare authentication")
        if any(not scheme or scheme != scheme.strip() for scheme in self.authentication_schemes):
            raise ValueError("authentication schemes must be normalized")
        if any(
            any(marker in scheme.lower() for marker in ("secret", "api_key=", "bearer "))
            for scheme in self.authentication_schemes
        ):
            raise ValueError("agent cards must not contain credential material")
        if self.signature is not None:
            _required(self.signature, "signature")
            _required(self.key_id or "", "signature key ID")
            if self.signature_algorithm not in {"EdDSA", "ES256", "RS256"}:
                raise ValueError("unsupported Agent Card signature algorithm")

    @staticmethod
    def _base64url(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    def _protected_header(self) -> dict[str, str]:
        if not self.signature or not self.key_id or not self.signature_algorithm:
            raise ValueError("Agent Card signature metadata is incomplete")
        return {"alg": self.signature_algorithm, "typ": "JOSE", "kid": self.key_id}

    def _unsigned_payload(self) -> dict[str, object]:
        security_schemes: dict[str, object] = {}
        security_requirements: list[dict[str, list[str]]] = []
        details = self.security_scheme_details or {}
        for scheme in self.authentication_schemes:
            configured = details.get(scheme)
            if configured is not None:
                if len(configured) != 1:
                    raise ValueError("each A2A security scheme must define exactly one scheme type")
                security_schemes[scheme] = dict(configured)
            elif scheme.lower() in {"bearer", "http-bearer"}:
                security_schemes[scheme] = {"httpAuthSecurityScheme": {"scheme": "Bearer"}}
            else:
                raise ValueError(f"security scheme {scheme!r} requires explicit protocol details")
            security_requirements.append({scheme: []})
        payload: dict[str, object] = {
            "name": self.name,
            "description": self.description,
            "supportedInterfaces": [
                {
                    "url": self.endpoint,
                    "protocolBinding": "JSONRPC",
                    "protocolVersion": self.protocol_version,
                }
            ],
            "version": self.card_version,
            "capabilities": {
                "streaming": False,
                "pushNotifications": False,
                "extendedAgentCard": False,
            },
            "securitySchemes": security_schemes,
            "securityRequirements": security_requirements,
            "defaultInputModes": ["text/plain"],
            "defaultOutputModes": ["text/plain"],
            "skills": [
                {
                    "id": skill.skill_id,
                    "name": skill.skill_id,
                    "description": skill.description,
                    "tags": sorted(skill.capabilities),
                    "inputModes": ["text/plain"],
                    "outputModes": ["text/plain"],
                }
                for skill in self.skills
            ],
        }
        return payload

    def canonical_payload(self) -> bytes:
        """Return the RFC 8785 canonical UTF-8 representation of the unsigned card."""
        try:
            # The protocol payload is assembled from JSON-compatible values; the
            # canonicalizer performs the authoritative runtime validation.
            return rfc8785.dumps(cast(Any, self._unsigned_payload()))
        except (rfc8785.CanonicalizationError, TypeError, ValueError) as exc:
            raise ValueError("Agent Card cannot be represented as RFC 8785 canonical JSON") from exc

    def verify_signature(self, verifier: AgentCardSignatureVerifier) -> None:
        self.validate()
        if not self.signature or not self.key_id or not self.signature_algorithm:
            raise PermissionError("remote Agent Card must have a verifiable signature")
        protected = self._base64url(
            json.dumps(
                self._protected_header(),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        signing_input = (
            protected.encode("ascii")
            + b"."
            + self._base64url(self.canonical_payload()).encode("ascii")
        )
        if not verifier.verify(
            self.key_id,
            self.signature_algorithm,
            signing_input,
            self.signature,
        ):
            raise PermissionError("remote Agent Card signature is not trusted")

    def as_payload(self) -> dict[str, object]:
        """Serialize the A2A 1.0 Agent Card without embedding credentials."""
        payload = self._unsigned_payload()
        if self.signature and self.key_id and self.signature_algorithm:
            protected = self._base64url(
                json.dumps(
                    self._protected_header(),
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
            payload["signatures"] = [{"protected": protected, "signature": self.signature}]
        return payload


@dataclass(frozen=True, slots=True)
class RemoteDelegation:
    delegation_id: UUID
    tenant_id: str
    parent_agent_id: UUID
    remote_agent_id: UUID
    audience: str
    capabilities: frozenset[str]
    resource_scope: str
    delegation_nonce: str
    issued_at: datetime
    expires_at: datetime

    @classmethod
    def issue(
        cls,
        *,
        tenant_id: str,
        parent_agent_id: UUID,
        remote_agent_id: UUID,
        parent_capabilities: frozenset[str],
        requested_capabilities: frozenset[str],
        resource_scope: str,
        ttl_seconds: int = 300,
        now: datetime | None = None,
    ) -> RemoteDelegation:
        if not requested_capabilities <= parent_capabilities:
            raise PermissionError("remote delegation cannot widen parent authority")
        _required(tenant_id, "tenant")
        _required(resource_scope, "resource scope")
        if not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= MAX_DELEGATION_TTL_SECONDS:
            raise ValueError("delegation TTL must be between 1 and 3600 seconds")
        issued_at = now or datetime.now(UTC)
        if issued_at.tzinfo is None:
            raise ValueError("delegation issue time must be timezone-aware")
        issued_at = issued_at.astimezone(UTC)
        return cls(
            delegation_id=uuid4(),
            tenant_id=tenant_id,
            parent_agent_id=parent_agent_id,
            remote_agent_id=remote_agent_id,
            audience=str(remote_agent_id),
            capabilities=frozenset(requested_capabilities),
            resource_scope=resource_scope,
            delegation_nonce=str(uuid4()),
            issued_at=issued_at,
            expires_at=issued_at + timedelta(seconds=ttl_seconds),
        )

    def validate(
        self,
        *,
        expected_tenant_id: str,
        expected_issuer_id: UUID,
        expected_audience: str,
        now: datetime | None = None,
    ) -> None:
        _required(expected_tenant_id, "expected tenant")
        _required(expected_audience, "expected audience")
        if self.tenant_id != expected_tenant_id:
            raise PermissionError("delegation tenant does not match the authenticated tenant")
        if self.parent_agent_id != expected_issuer_id:
            raise PermissionError("delegation issuer does not match the trusted issuer")
        if self.audience != expected_audience or expected_audience != str(self.remote_agent_id):
            raise PermissionError(
                "delegation audience does not match the authenticated remote agent"
            )
        current_value = now or datetime.now(UTC)
        if current_value.tzinfo is None:
            raise ValueError("validation time must be timezone-aware")
        current = current_value.astimezone(UTC)
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("delegation timestamps must be timezone-aware")
        issued_at = self.issued_at.astimezone(UTC)
        expires_at = self.expires_at.astimezone(UTC)
        if (
            expires_at <= issued_at
            or (expires_at - issued_at).total_seconds() > MAX_DELEGATION_TTL_SECONDS
        ):
            raise PermissionError("delegation expiry is invalid")
        if issued_at > current + timedelta(seconds=30):
            raise PermissionError("delegation issue time is in the future")
        if current >= expires_at:
            raise PermissionError("remote delegation has expired")
        _required(self.tenant_id, "tenant")
        _required(self.resource_scope, "resource scope")
        _required(self.audience, "delegation audience")
        if self.audience != str(self.remote_agent_id):
            raise PermissionError("delegation audience does not match the remote agent")
        if not self.delegation_nonce.strip():
            raise PermissionError("delegation nonce is missing")


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that dials a previously validated IP, not a fresh DNS result."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        timeout: float,
        context: ssl.SSLContext,
        pinned_address: str,
    ) -> None:
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._pinned_address = str(ipaddress.ip_address(pinned_address))
        if not ipaddress.ip_address(self._pinned_address).is_global:
            raise ValueError("pinned remote A2A address must be globally routable")

    def connect(self) -> None:
        if self._tunnel_host:
            raise ValueError("proxy tunneling is not supported for pinned A2A transport")
        raw_socket = socket.create_connection(
            (self._pinned_address, self.port),
            self.timeout,
            self.source_address,
        )
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


def _validate_json_object_keys(value: object, path: str = "A2A payload") -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} object keys must be strings")
            _validate_json_object_keys(nested, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            _validate_json_object_keys(nested, f"{path}[{index}]")


class PinnedHTTPSRemoteAgentTransport:
    """Bounded HTTPS transport for A2A that pins the validated IP and never follows redirects.

    The hostname remains the TLS SNI/certificate-verification identity and HTTP Host
    identity; only the TCP destination is replaced with the address set validated by
    `validate_remote_endpoint`. No DNS lookup is performed by this transport.
    """

    def post(
        self,
        endpoint: str,
        resolved_addresses: tuple[str, ...],
        bearer_token: str,
        payload: Mapping[str, object],
        *,
        timeout_seconds: float,
        max_response_bytes: int,
        protocol_version: str,
        content_type: str,
    ) -> Mapping[str, object]:
        hostname, scheme = _validate_url(endpoint, require_https=True)
        if scheme != "https":
            raise ValueError("remote A2A transport requires HTTPS")
        if protocol_version != A2A_PROTOCOL_VERSION:
            raise ValueError("unsupported A2A wire protocol version")
        if content_type != "application/a2a+json":
            raise ValueError("A2A 1.0.1 HTTP binding requires application/a2a+json")
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0 or timeout_seconds > 30:
            raise ValueError("A2A timeout must be finite and between 0 and 30 seconds")
        if not 1 <= max_response_bytes <= MAX_REMOTE_RESPONSE_BYTES:
            raise ValueError("A2A response limit is outside the supported bound")
        if (
            not isinstance(bearer_token, str)
            or not bearer_token
            or bearer_token != bearer_token.strip()
            or re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", bearer_token) is None
        ):
            raise ValueError("A2A scoped credential is invalid")
        if not resolved_addresses:
            raise ValueError("A2A transport requires validated destination addresses")

        addresses: list[str] = []
        for value in resolved_addresses:
            try:
                address = ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError("A2A transport received an invalid pinned address") from exc
            if not address.is_global:
                raise ValueError("A2A transport refuses non-public pinned addresses")
            addresses.append(str(address))

        _validate_json_object_keys(payload)
        try:
            encoded = json.dumps(
                dict(payload),
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("A2A request payload is not valid JSON data") from exc
        if len(encoded) > MAX_REMOTE_RESPONSE_BYTES:
            raise ValueError("A2A request exceeds maximum size")

        parsed = urlparse(endpoint)
        target = parsed.path or "/"
        connection = _PinnedHTTPSConnection(
            hostname,
            parsed.port or 443,
            timeout=timeout_seconds,
            context=ssl.create_default_context(),
            pinned_address=addresses[0],
        )
        try:
            connection.request(
                "POST",
                target,
                body=encoded,
                headers={
                    "Authorization": f"Bearer {bearer_token}",
                    "Content-Type": content_type,
                    "Accept": content_type,
                    "A2A-Version": protocol_version,
                },
            )
            response = connection.getresponse()
            if not 200 <= response.status < 300:
                raise ValueError(f"remote A2A endpoint returned HTTP {response.status}")
            response_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            if response_type != content_type:
                raise ValueError("remote A2A endpoint returned an unexpected content type")
            raw = response.read(max_response_bytes + 1)
            if len(raw) > max_response_bytes:
                raise ValueError("remote A2A response exceeds maximum size")
            try:
                decoded = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise ValueError("remote A2A endpoint returned invalid JSON") from exc
            if not isinstance(decoded, dict):
                raise ValueError("remote A2A response must be a JSON object")
            return decoded
        except (OSError, TimeoutError, http.client.HTTPException) as exc:
            # Do not surface remote response bodies, headers, or credentials.
            raise RuntimeError("remote A2A transport failed") from exc
        finally:
            connection.close()


class A2AClient:
    """Minimal outbound A2A client with trusted-card and SSRF checks."""

    def __init__(
        self,
        *,
        resolver: Callable[[str], Iterable[str]],
        transport: RemoteAgentTransport,
        card_verifier: AgentCardSignatureVerifier,
        credential_provider: RemoteCredentialProvider,
    ) -> None:
        self._resolver = resolver
        self._transport = transport
        self._card_verifier = card_verifier
        self._credential_provider = credential_provider

    def send(
        self,
        card: AgentCard,
        delegation: RemoteDelegation,
        payload: Mapping[str, object],
        *,
        expected_tenant_id: str,
        expected_issuer_id: UUID,
        required_capabilities: frozenset[str],
        resource_scope: str,
        now: datetime | None = None,
        timeout_seconds: float = 10.0,
    ) -> Mapping[str, object]:
        card.verify_signature(self._card_verifier)
        delegation.validate(
            expected_tenant_id=expected_tenant_id,
            expected_issuer_id=expected_issuer_id,
            expected_audience=str(card.agent_id),
            now=now,
        )
        if not required_capabilities <= delegation.capabilities:
            raise PermissionError("remote delegation does not grant required capabilities")
        if resource_scope != delegation.resource_scope:
            raise PermissionError("remote delegation resource scope does not match the request")
        bearer_token = self._credential_provider.issue(delegation)
        if (
            not isinstance(bearer_token, str)
            or not bearer_token
            or bearer_token != bearer_token.strip()
        ):
            raise PermissionError("Platform credential provider returned no scoped A2A credential")
        if not 0 < timeout_seconds <= 30:
            raise ValueError("A2A timeout must be between 0 and 30 seconds")
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(encoded) > MAX_REMOTE_RESPONSE_BYTES:
            raise ValueError("A2A request exceeds maximum size")
        addresses = validate_remote_endpoint(card.endpoint, self._resolver)
        # Transport contract requires the validated address set and forbids redirects.
        response = self._transport.post(
            card.endpoint,
            addresses,
            bearer_token,
            payload,
            timeout_seconds=timeout_seconds,
            max_response_bytes=MAX_REMOTE_RESPONSE_BYTES,
            protocol_version=A2A_PROTOCOL_VERSION,
            content_type="application/a2a+json",
        )
        response_size = len(
            json.dumps(response, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        )
        if response_size > MAX_REMOTE_RESPONSE_BYTES:
            raise ValueError("A2A response exceeds maximum size")
        return response
