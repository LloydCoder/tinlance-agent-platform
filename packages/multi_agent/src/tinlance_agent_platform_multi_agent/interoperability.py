"""Provider-neutral A2A contracts with bounded delegation and endpoint trust.

Discovery metadata is descriptive, not authoritative. Remote communication must
enter the normal Platform identity, authorization and execution boundaries.
"""
from __future__ import annotations

import ipaddress
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from urllib.parse import urlparse
from uuid import UUID, uuid4


A2A_PROTOCOL_VERSION = "1.0.0"
MAX_DELEGATION_TTL_SECONDS = 3600
MAX_REMOTE_RESPONSE_BYTES = 1_048_576


class AgentCardSignatureVerifier(Protocol):
    """Verifies a canonical card payload against a trusted key registry."""

    def verify(self, key_id: str, algorithm: str, payload: bytes, signature: str) -> bool: ...


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
    if parsed.fragment:
        raise ValueError("remote agent endpoint must not contain a fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("remote agent endpoint port is invalid") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("remote agent endpoint port is invalid")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError("remote agent endpoint must not target localhost")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
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

    def validate(self, *, require_https: bool = True) -> None:
        _validate_url(self.endpoint, require_https=require_https)
        if self.protocol_version != A2A_PROTOCOL_VERSION:
            raise ValueError("unsupported A2A protocol version")
        _required(self.name, "agent name")
        _required(self.description, "agent description")
        _required(self.card_version, "agent card version")
        if not self.skills:
            raise ValueError("agent card must declare at least one skill")
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
            _required(self.signature_algorithm or "", "signature algorithm")

    def canonical_payload(self) -> bytes:
        payload = {
            "agent_id": str(self.agent_id),
            "protocol_version": self.protocol_version,
            "name": self.name,
            "description": self.description,
            "endpoint": self.endpoint,
            "skills": [
                {
                    "skill_id": skill.skill_id,
                    "description": skill.description,
                    "capabilities": sorted(skill.capabilities),
                }
                for skill in self.skills
            ],
            "authentication_schemes": list(self.authentication_schemes),
            "card_version": self.card_version,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def verify_signature(self, verifier: AgentCardSignatureVerifier) -> None:
        self.validate()
        if not self.signature or not self.key_id or not self.signature_algorithm:
            raise PermissionError("remote Agent Card must have a verifiable signature")
        if not verifier.verify(
            self.key_id,
            self.signature_algorithm,
            self.canonical_payload(),
            self.signature,
        ):
            raise PermissionError("remote Agent Card signature is not trusted")

    def as_payload(self) -> dict[str, object]:
        """Serialize credential-free discovery metadata; never include tokens."""
        return {
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
            "securitySchemes": {
                scheme: {"type": "http", "scheme": "bearer"}
                for scheme in self.authentication_schemes
            },
            "skills": [
                {
                    "id": skill.skill_id,
                    "name": skill.skill_id,
                    "description": skill.description,
                    "tags": sorted(skill.capabilities),
                }
                for skill in self.skills
            ],
            "extensions": [
                {
                    "uri": "urn:tinlance:agent-card-signature:v1",
                    "required": True,
                    "params": {
                        "keyId": self.key_id,
                        "algorithm": self.signature_algorithm,
                        "signature": self.signature,
                    },
                }
            ] if self.signature and self.key_id and self.signature_algorithm else [],
        }


@dataclass(frozen=True, slots=True)
class RemoteDelegation:
    delegation_id: UUID
    tenant_id: str
    parent_agent_id: UUID
    remote_agent_id: UUID
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
            capabilities=frozenset(requested_capabilities),
            resource_scope=resource_scope,
            delegation_nonce=str(uuid4()),
            issued_at=issued_at,
            expires_at=issued_at + timedelta(seconds=ttl_seconds),
        )

    def validate(self, *, now: datetime | None = None) -> None:
        current = (now or datetime.now(UTC)).astimezone(UTC)
        if current.tzinfo is None:
            raise ValueError("validation time must be timezone-aware")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("delegation timestamps must be timezone-aware")
        issued_at = self.issued_at.astimezone(UTC)
        expires_at = self.expires_at.astimezone(UTC)
        if expires_at <= issued_at or (expires_at - issued_at).total_seconds() > MAX_DELEGATION_TTL_SECONDS:
            raise PermissionError("delegation expiry is invalid")
        if issued_at > current + timedelta(seconds=30):
            raise PermissionError("delegation issue time is in the future")
        if current >= expires_at:
            raise PermissionError("remote delegation has expired")
        _required(self.tenant_id, "tenant")
        _required(self.resource_scope, "resource scope")
        if not self.delegation_nonce.strip():
            raise PermissionError("delegation nonce is missing")


class A2AClient:
    """Minimal outbound A2A client with trusted-card and SSRF checks."""

    def __init__(
        self,
        *,
        resolver: Callable[[str], Iterable[str]],
        transport: RemoteAgentTransport,
        card_verifier: AgentCardSignatureVerifier,
    ) -> None:
        self._resolver = resolver
        self._transport = transport
        self._card_verifier = card_verifier

    def send(
        self,
        card: AgentCard,
        bearer_token: str,
        payload: Mapping[str, object],
        *,
        timeout_seconds: float = 10.0,
    ) -> Mapping[str, object]:
        card.verify_signature(self._card_verifier)
        if not bearer_token or bearer_token != bearer_token.strip():
            raise PermissionError("A2A bearer credential is required")
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
        )
        if len(json.dumps(response, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > MAX_REMOTE_RESPONSE_BYTES:
            raise ValueError("A2A response exceeds maximum size")
        return response
