"""Platform API handler for purpose-bound, read-only World Intelligence queries."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid4, uuid5

from tinlance_agent_platform_api.service import APIHandler, APIRequest, APIResponse
from tinlance_agent_platform_contracts import (
    CapabilityRequest,
    DataClass,
    Principal,
    RequestContext,
    Reversibility,
    RiskTier,
    TraceLineageContext,
)
from tinlance_agent_platform_mcp.gateway import MCPToolGateway, ToolScope
from tinlance_agent_platform_mcp.world_intelligence import (
    WORLD_INTELLIGENCE_OPERATION_TO_TOOL,
    WORLD_INTELLIGENCE_TOOL_REGISTRATIONS,
    WorldIntelligenceTransportError,
)

_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_PURPOSE = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")


class WorldIntelligenceAPIHandler:
    """Route registered read operations through Platform policy before downstream HTTP."""

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
        tool_name = WORLD_INTELLIGENCE_OPERATION_TO_TOOL.get(request.operation)
        if tool_name is None:
            return self._delegate.handle(request)
        principal = self._principal(request)
        purpose = request.payload.get("purpose")
        if not isinstance(purpose, str) or not _PURPOSE.fullmatch(purpose):
            raise ValueError("a normalized World Intelligence purpose is required")
        if f"world-intelligence:purpose:{purpose}" not in principal.scopes:
            raise PermissionError("Platform principal is not authorized for the requested purpose")

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
        spec = next(item for item in WORLD_INTELLIGENCE_TOOL_REGISTRATIONS if item.name == tool_name)
        arguments = dict(request.payload)
        scope = ToolScope(
            tenant_id=request.tenant_id,
            capability=spec.capability,
            resource=spec.resource_pattern,
            subject_id=request.subject_id,
            request_id=request.request_id,
            traceparent=traceparent,
        )
        capability_request = CapabilityRequest(
            action="read",
            resource=spec.resource_pattern,
            capabilities=frozenset({spec.capability}),
            risk=RiskTier.LOW,
            reversibility=Reversibility.REVERSIBLE,
            data_class=DataClass.CONFIDENTIAL,
            blast_radius="single",
            parameters={"purpose": purpose},
        )
        run_id = uuid5(
            NAMESPACE_URL,
            f"world-intelligence:{request.tenant_id}:{request.subject_id}:{request.request_id}:{tool_name}",
        )
        try:
            result = self._gateway.call(
                context,
                scope,
                tool_name,
                arguments,
                capability_request,
                run_id,
            )
        except (PermissionError, ValueError):
            raise
        except WorldIntelligenceTransportError as exc:
            if exc.status_code in {401, 403}:
                return APIResponse("denied", {"error": "world_intelligence_downstream_auth_failed"})
            if exc.status_code == 400:
                return APIResponse("invalid", {"error": "world_intelligence_query_rejected"})
            return APIResponse(
                "failed",
                {"error": "world_intelligence_unavailable", "retryable": exc.retryable},
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
