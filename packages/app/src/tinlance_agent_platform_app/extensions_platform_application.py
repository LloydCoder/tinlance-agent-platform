"""Platform composition for governed Tinlance Extensions operations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from tinlance_agent_platform_api.service import (
    AgentPlatformAPI,
    APIHandler,
    APIRequest,
    APIResponse,
)
from tinlance_agent_platform_contracts import (
    CapabilityRequest,
    DataClass,
    Principal,
    RequestContext,
    Reversibility,
    RiskTier,
    TraceLineageContext,
)
from tinlance_agent_platform_identity.service_tokens import (
    KMSClient,
    KMSRS256Signer,
    PlatformServiceTokenIssuer,
)
from tinlance_agent_platform_mcp.extensions import (
    EXTENSIONS_AUDIENCE,
    EXTENSIONS_DEAD_LETTER_REPLAY,
    ExtensionsHTTPClient,
    ExtensionsHTTPTransport,
    ExtensionsTransportError,
    register_extensions_tools,
)
from tinlance_agent_platform_mcp.gateway import ApprovalVerifier, MCPToolGateway, ToolScope

_OPERATION_TO_TOOL = {
    "extensions.jobs.cancel": "extensions_job_cancel",
    "extensions.outbox.dead_letter.replay": "extensions_dead_letter_replay",
}
_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_JOB_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")


def extensions_mcp_request_id(*, tenant_id: str, subject_id: str, jsonrpc_request_id: str) -> str:
    """Mirror MCPProtocolService request-ID derivation for approval preparation."""
    if not all((tenant_id, subject_id, jsonrpc_request_id)):
        raise ValueError("MCP replay request identity is incomplete")
    fingerprint = sha256(f"{tenant_id}:{subject_id}:{jsonrpc_request_id}".encode()).hexdigest()[:32]
    return f"mcp-{fingerprint}"


def extensions_dead_letter_replay_run_id(
    *, tenant_id: str, subject_id: str, request_id: str
) -> UUID:
    """Return the deterministic Platform run identifier used for replay approvals."""
    values = (tenant_id, subject_id, request_id)
    if not all(values) or any(value != value.strip() for value in values):
        raise ValueError("Extensions replay run identity must be normalized")
    return uuid5(
        NAMESPACE_URL,
        f"extensions:{tenant_id}:{subject_id}:{request_id}:extensions_dead_letter_replay",
    )


def compute_extensions_dead_letter_replay_intent_fingerprint(
    *,
    tenant_id: str,
    subject_id: str,
    run_id: str,
    arguments: dict[str, object],
) -> str:
    """Bind replay approval to the exact tenant, actor, run, event and idempotency key."""
    if set(arguments) != {"event_id", "idempotency_key"}:
        raise ValueError("Extensions replay intent contains unsupported fields")
    canonical = json.dumps(
        {
            "tenant_id": tenant_id,
            "subject_id": subject_id,
            "run_id": run_id,
            "tool_name": "extensions_dead_letter_replay",
            "capability": EXTENSIONS_DEAD_LETTER_REPLAY.capability,
            "action": EXTENSIONS_DEAD_LETTER_REPLAY.action,
            "resource": EXTENSIONS_DEAD_LETTER_REPLAY.resource_pattern,
            "arguments": arguments,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


class ExtensionsAPIHandler:
    """Route registered Extensions operations through the Platform tool gateway."""

    def __init__(
        self,
        *,
        delegate: APIHandler,
        gateway: MCPToolGateway,
        environment: str,
        approval_verifier: ApprovalVerifier | None = None,
    ) -> None:
        if not environment or environment != environment.strip():
            raise ValueError("Platform environment must be normalized")
        self._delegate = delegate
        self._gateway = gateway
        self._environment = environment
        self._approval_verifier = approval_verifier

    def handle(self, request: APIRequest) -> APIResponse:
        tool_name = _OPERATION_TO_TOOL.get(request.operation)
        if tool_name is None:
            return self._delegate.handle(request)
        principal = self._principal(request)

        trace_id = request.trace_id
        if trace_id is not None and "-" in trace_id:
            parts = trace_id.split("-")
            if len(parts) == 5 and len(parts[1]) == 32 and len(parts[2]) == 16:
                trace_id = parts[1]
        if trace_id is not None and not _TRACE_ID.fullmatch(trace_id):
            raise PermissionError("Platform trace ID is invalid")
        trace_id = trace_id or uuid4().hex
        span_id = uuid4().hex[:16]
        traceparent = f"00-{trace_id}-{span_id}-01"
        trace_context = TraceLineageContext(
            trace_id=trace_id,
            span_id=span_id,
            correlation_id=request.request_id,
            request_id=request.request_id,
            tenant_id=request.tenant_id,
            operation=request.operation,
            started_at=datetime.now(UTC).isoformat(),
        )
        context = RequestContext(
            request_id=request.request_id,
            tenant_id=request.tenant_id,
            principal=principal,
            environment=self._environment,
            trace_id=trace_id,
            trace_context=trace_context,
        )

        approval_arguments: dict[str, object] = {}
        approval_id: UUID | None = None
        intent_fingerprint: str | None = None
        approval_verifier: ApprovalVerifier | None = None

        if tool_name == "extensions_job_cancel":
            if set(request.payload) != {"job_id"}:
                raise ValueError("Extensions cancellation requires only job_id")
            job_id = request.payload.get("job_id")
            if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id):
                raise ValueError("Extensions job ID must be a canonical UUID")
            if str(UUID(job_id)) != job_id.lower():
                raise ValueError("Extensions job ID must be normalized")
            capability = "extensions.jobs.cancel"
            resource = "extensions://jobs/{job_id}"
            action = "cancel"
            risk = RiskTier.LOW
            reversibility = Reversibility.REVERSIBLE
            data_class = DataClass.CONFIDENTIAL
            arguments: dict[str, object] = {"job_id": job_id}
            run_id = uuid5(
                NAMESPACE_URL,
                f"extensions:{request.tenant_id}:{request.subject_id}:{request.request_id}:{tool_name}",
            )
        else:
            required_fields = {"event_id", "run_id", "approval_id", "intent_fingerprint"}
            payload_fields = set(request.payload)
            if payload_fields != required_fields and payload_fields != required_fields | {
                "idempotency_key"
            }:
                raise ValueError("Extensions replay requires exact approval-bound fields")
            event_id = request.payload.get("event_id")
            if not isinstance(event_id, str) or not _JOB_ID.fullmatch(event_id):
                raise ValueError("Extensions event ID must be a canonical UUID")
            if str(UUID(event_id)) != event_id.lower():
                raise ValueError("Extensions event ID must be normalized")
            idempotency_key = request.idempotency_key
            payload_idempotency_key = request.payload.get("idempotency_key")
            if (
                not isinstance(idempotency_key, str)
                or not _IDEMPOTENCY_KEY.fullmatch(idempotency_key)
                or (
                    payload_idempotency_key is not None
                    and payload_idempotency_key != idempotency_key
                )
            ):
                raise ValueError("Extensions replay idempotency key is invalid or unbound")
            supplied_run_id = request.payload.get("run_id")
            if not isinstance(supplied_run_id, str) or not _JOB_ID.fullmatch(supplied_run_id):
                raise ValueError("Extensions replay run ID must be a canonical UUID")
            run_id = extensions_dead_letter_replay_run_id(
                tenant_id=request.tenant_id,
                subject_id=request.subject_id,
                request_id=request.request_id,
            )
            if str(run_id) != supplied_run_id.lower():
                raise PermissionError("Extensions replay run ID does not match request context")
            approval_value = request.payload.get("approval_id")
            if not isinstance(approval_value, str) or not _JOB_ID.fullmatch(approval_value):
                raise ValueError("Extensions replay approval ID must be a canonical UUID")
            approval_id = UUID(approval_value)
            if str(approval_id) != approval_value.lower():
                raise ValueError("Extensions replay approval ID must be normalized")
            approval_arguments = {
                "event_id": event_id,
                "idempotency_key": idempotency_key,
            }
            expected_fingerprint = compute_extensions_dead_letter_replay_intent_fingerprint(
                tenant_id=request.tenant_id,
                subject_id=request.subject_id,
                run_id=str(run_id),
                arguments=approval_arguments,
            )
            supplied_fingerprint = request.payload.get("intent_fingerprint")
            if supplied_fingerprint != expected_fingerprint:
                raise PermissionError("Extensions replay approval intent does not match request")
            intent_fingerprint = expected_fingerprint
            approval_verifier = self._approval_verifier
            capability = EXTENSIONS_DEAD_LETTER_REPLAY.capability
            resource = EXTENSIONS_DEAD_LETTER_REPLAY.resource_pattern
            action = EXTENSIONS_DEAD_LETTER_REPLAY.action
            risk = RiskTier.HIGH
            reversibility = Reversibility.PARTIALLY_REVERSIBLE
            data_class = DataClass.CONFIDENTIAL
            arguments = {
                **request.payload,
                "idempotency_key": idempotency_key,
            }

        scope = ToolScope(
            tenant_id=request.tenant_id,
            capability=capability,
            resource=resource,
            subject_id=request.subject_id,
            request_id=request.request_id,
            traceparent=traceparent,
            principal_type=principal.principal_type,
        )
        capability_request = CapabilityRequest(
            action=action,
            resource=resource,
            capabilities=frozenset({capability}),
            risk=risk,
            reversibility=reversibility,
            data_class=data_class,
            blast_radius="single",
        )
        try:
            result = self._gateway.call(
                context,
                scope,
                tool_name,
                arguments,
                capability_request,
                run_id,
                approval_id=approval_id,
                approval_verifier=approval_verifier,
                intent_fingerprint=intent_fingerprint,
            )
        except PermissionError:
            raise
        except ValueError:
            raise
        except ExtensionsTransportError as exc:
            if exc.status_code in {401, 403}:
                return APIResponse(
                    "denied", {"error": "extensions_downstream_authentication_failed"}
                )
            if exc.status_code == 404:
                return APIResponse("not_found", {"error": "extensions_resource_not_found"})
            return APIResponse(
                "failed",
                {"error": "extensions_unavailable", "retryable": exc.retryable},
            )
        return APIResponse("success", result)

    @staticmethod
    def _principal(request: APIRequest) -> Principal:
        value = request.authenticated_principal
        if value is None:
            raise PermissionError("authenticated Platform principal is required")
        tenant_id = getattr(value, "tenant_id", None)
        subject_id = getattr(value, "subject_id", None)
        if tenant_id != request.tenant_id or subject_id != request.subject_id:
            raise PermissionError("Platform principal does not match request identity")
        if isinstance(value, Principal):
            return value

        def string_set(attribute: str) -> frozenset[str]:
            raw = getattr(value, attribute, ())
            if not isinstance(raw, (set, frozenset, list, tuple)):
                return frozenset()
            return frozenset(item for item in raw if isinstance(item, str) and item.strip())

        principal_type = getattr(value, "principal_type", "user")
        if not isinstance(principal_type, str) or not principal_type.strip():
            principal_type = "user"
        return Principal(
            subject_id=subject_id,
            principal_type=principal_type,
            tenant_id=tenant_id,
            roles=string_set("roles"),
            scopes=string_set("scopes"),
        )


@dataclass(frozen=True, slots=True)
class PlatformExtensionsApplication:
    api: AgentPlatformAPI
    signer: KMSRS256Signer
    token_issuer: PlatformServiceTokenIssuer
    gateway: MCPToolGateway

    @property
    def jwks_provider(self) -> KMSRS256Signer:
        return self.signer


def create_extensions_platform_application(
    *,
    delegate: APIHandler,
    environment: str,
    kms_client: KMSClient,
    kms_key_id: str,
    issuer: str,
    client_id: str,
    extensions_base_url: str,
    verification_key_ids: tuple[str, ...] = (),
    http_client: ExtensionsHTTPClient | None = None,
    approval_verifier: ApprovalVerifier | None = None,
    timeout_seconds: float = 5.0,
) -> PlatformExtensionsApplication:
    """Compose the Platform-authorized Extensions action boundary."""
    signer = KMSRS256Signer(
        kms_client=kms_client,
        key_id=kms_key_id,
        verification_key_ids=verification_key_ids,
    )
    token_issuer = PlatformServiceTokenIssuer(
        issuer=issuer,
        client_id=client_id,
        allowed_audiences=frozenset({EXTENSIONS_AUDIENCE}),
        signer=signer,
    )
    transport = ExtensionsHTTPTransport(
        base_url=extensions_base_url,
        token_issuer=token_issuer,
        http_client=http_client,
        timeout_seconds=timeout_seconds,
    )
    gateway = MCPToolGateway(transport)
    register_extensions_tools(gateway)
    handler = ExtensionsAPIHandler(
        delegate=delegate,
        gateway=gateway,
        environment=environment,
        approval_verifier=approval_verifier,
    )
    return PlatformExtensionsApplication(
        api=AgentPlatformAPI(handler),
        signer=signer,
        token_issuer=token_issuer,
        gateway=gateway,
    )
