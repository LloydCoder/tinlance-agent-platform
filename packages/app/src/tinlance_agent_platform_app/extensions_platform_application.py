"""Platform composition for governed Tinlance Extensions operations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
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
    ExtensionsHTTPClient,
    ExtensionsHTTPTransport,
    ExtensionsTransportError,
    register_extensions_tools,
)
from tinlance_agent_platform_mcp.gateway import MCPToolGateway, ToolScope

_OPERATION_TO_TOOL = {"extensions.jobs.cancel": "extensions_job_cancel"}
_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_JOB_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)


class ExtensionsAPIHandler:
    """Route only registered Extensions operations through the Platform tool gateway."""

    def __init__(
        self,
        *,
        delegate: APIHandler,
        gateway: MCPToolGateway,
        environment: str,
    ) -> None:
        if not environment or environment != environment.strip():
            raise ValueError("Platform environment must be normalized")
        self._delegate = delegate
        self._gateway = gateway
        self._environment = environment

    def handle(self, request: APIRequest) -> APIResponse:
        tool_name = _OPERATION_TO_TOOL.get(request.operation)
        if tool_name is None:
            return self._delegate.handle(request)
        principal = self._principal(request)
        if set(request.payload) != {"job_id"}:
            raise ValueError("Extensions cancellation requires only job_id")
        job_id = request.payload.get("job_id")
        if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id):
            raise ValueError("Extensions job ID must be a canonical UUID")
        if str(UUID(job_id)) != job_id.lower():
            raise ValueError("Extensions job ID must be normalized")

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
        capability = "extensions.jobs.cancel"
        resource = "extensions://jobs/{job_id}"
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
            action="cancel",
            resource=resource,
            capabilities=frozenset({capability}),
            risk=RiskTier.LOW,
            reversibility=Reversibility.REVERSIBLE,
            data_class=DataClass.CONFIDENTIAL,
            blast_radius="single",
        )
        run_id = uuid5(
            NAMESPACE_URL,
            f"extensions:{request.tenant_id}:{request.subject_id}:{request.request_id}:{tool_name}",
        )
        try:
            result = self._gateway.call(
                context,
                scope,
                tool_name,
                {"job_id": job_id},
                capability_request,
                run_id,
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
                return APIResponse("not_found", {"error": "extensions_job_not_found"})
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
    timeout_seconds: float = 5.0,
) -> PlatformExtensionsApplication:
    """Compose the Platform-authorized Extensions job-cancellation boundary.

    The caller must supply the authenticated Platform API principal resolver and
    serve the returned JWKS provider over HTTPS. This factory does not infer
    identity-provider, KMS, tenant-claim, or deployment configuration.
    """
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
    )
    return PlatformExtensionsApplication(
        api=AgentPlatformAPI(handler),
        signer=signer,
        token_issuer=token_issuer,
        gateway=gateway,
    )
