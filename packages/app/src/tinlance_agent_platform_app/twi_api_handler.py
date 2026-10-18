"""Platform API operation adapter for governed TWI tools.

This handler is intended to wrap the normal Platform API handler. It routes only registered
TWI operations through MCPToolGateway, which enforces the Platform policy and approval boundary.
All other Platform operations are delegated unchanged.
"""

from __future__ import annotations

import hmac
import re
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from tinlance_agent_platform_api.service import APIHandler, APIRequest, APIResponse
from tinlance_agent_platform_contracts import (
    CapabilityRequest,
    DataClass,
    Principal,
    RequestContext,
    Reversibility,
    TraceLineageContext,
)
from tinlance_agent_platform_mcp.gateway import ApprovalVerifier, MCPToolGateway, ToolScope
from tinlance_agent_platform_mcp.twi import (
    TWI_OPERATION_TO_TOOL,
    TWITransportError,
    compute_twi_intent_fingerprint,
    twi_tool_spec,
)

_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_INTENT_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")


class TWIAPIHandler:
    """Route TWI API operations through Platform policy before calling the HTTP adapter."""

    def __init__(
        self,
        *,
        delegate: APIHandler,
        gateway: MCPToolGateway,
        approval_verifier: ApprovalVerifier,
        environment: str,
    ) -> None:
        if not environment or environment != environment.strip():
            raise ValueError("Platform environment must be normalized")
        self._delegate = delegate
        self._gateway = gateway
        self._approval_verifier = approval_verifier
        self._environment = environment

    def handle(self, request: APIRequest) -> APIResponse:
        tool_name = TWI_OPERATION_TO_TOOL.get(request.operation)
        if tool_name is None:
            return self._delegate.handle(request)

        principal = self._principal(request)
        trace_id = request.trace_id
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
        spec = twi_tool_spec(tool_name)
        arguments = dict(request.payload)
        if request.idempotency_key is not None:
            supplied_key = arguments.get("idempotency_key")
            if supplied_key is not None and supplied_key != request.idempotency_key:
                raise PermissionError("conflicting Platform idempotency keys")
            arguments["idempotency_key"] = request.idempotency_key

        run_id = uuid5(
            NAMESPACE_URL,
            f"twi:{request.tenant_id}:{request.subject_id}:{request.request_id}:{tool_name}",
        )
        approval_id: UUID | None = None
        intent_fingerprint: str | None = None
        if tool_name == "twi_world_intelligence_export":
            try:
                run_id = UUID(str(arguments.pop("run_id")))
                approval_id = UUID(str(arguments.pop("approval_id")))
            except (ValueError, TypeError, AttributeError) as exc:
                raise PermissionError("a valid Platform run and approval are required") from exc
            declared_fingerprint = arguments.pop("intent_fingerprint", None)
            if not isinstance(declared_fingerprint, str) or not _INTENT_FINGERPRINT.fullmatch(
                declared_fingerprint
            ):
                raise PermissionError("a valid approval intent fingerprint is required")
            intent_fingerprint = compute_twi_intent_fingerprint(
                tenant_id=request.tenant_id,
                subject_id=request.subject_id,
                run_id=str(run_id),
                tool_name=tool_name,
                arguments=arguments,
            )
            if not hmac.compare_digest(declared_fingerprint, intent_fingerprint):
                raise PermissionError(
                    "approval intent fingerprint does not match the requested export"
                )

        scope = ToolScope(
            tenant_id=request.tenant_id,
            capability=spec.capability,
            resource=spec.resource_pattern,
            subject_id=request.subject_id,
            request_id=request.request_id,
            traceparent=traceparent,
        )
        capability_request = CapabilityRequest(
            action=spec.action,
            resource=spec.resource_pattern,
            capabilities=frozenset({spec.capability}),
            risk=spec.risk,
            reversibility=(
                Reversibility.PARTIALLY_REVERSIBLE
                if spec.requires_approval
                else Reversibility.REVERSIBLE
            ),
            data_class=DataClass.PUBLIC,
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
                approval_verifier=self._approval_verifier,
                intent_fingerprint=intent_fingerprint,
            )
        except PermissionError:
            raise
        except ValueError:
            raise
        except TWITransportError as exc:
            # Never return downstream response bodies, headers, or token material.
            if exc.status_code in {401, 403}:
                return APIResponse("denied", {"error": "twi_downstream_authentication_failed"})
            if exc.status_code == 409:
                return APIResponse("conflict", {"error": "twi_idempotency_conflict"})
            return APIResponse(
                "failed",
                {"error": "twi_unavailable", "retryable": exc.retryable},
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
