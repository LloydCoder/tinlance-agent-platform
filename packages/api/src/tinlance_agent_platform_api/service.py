from dataclasses import dataclass
from typing import Protocol

API_VERSION = "1.1"


class AuthenticatedPrincipal(Protocol):
    tenant_id: str
    subject_id: str


@dataclass(frozen=True, slots=True)
class APIRequest:
    tenant_id: str
    subject_id: str
    operation: str
    payload: dict[str, object]
    request_id: str = "in-process"
    trace_id: str | None = None


@dataclass(frozen=True, slots=True)
class APIResponse:
    status: str
    payload: dict[str, object]


class APIHandler(Protocol):
    def handle(self, request: APIRequest) -> APIResponse: ...


class AuthenticationError(PermissionError):
    """Raised when bearer authentication cannot establish a principal."""


class PrincipalResolver(Protocol):
    """Resolve an already-authenticated bearer credential to a platform principal."""

    def resolve(self, bearer_token: str) -> AuthenticatedPrincipal: ...


class AgentPlatformAPI:
    def __init__(self, handler: APIHandler) -> None:
        self._handler = handler

    def dispatch(self, request: APIRequest) -> APIResponse:
        if (
            not request.tenant_id
            or not request.subject_id
            or not request.operation
            or not request.request_id
            or request.tenant_id != request.tenant_id.strip()
            or request.subject_id != request.subject_id.strip()
            or request.operation != request.operation.strip()
            or request.request_id != request.request_id.strip()
        ):
            raise PermissionError("authenticated request context is required")
        return self._handler.handle(request)

    def dispatch_authenticated(
        self,
        request: APIRequest,
        bearer_token: str,
        resolver: PrincipalResolver,
    ) -> APIResponse:
        """Dispatch only after binding request identity to the authenticated principal."""
        principal = resolver.resolve(bearer_token)
        if principal.tenant_id != request.tenant_id or principal.subject_id != request.subject_id:
            raise PermissionError("request identity does not match authenticated principal")
        authenticated_request = APIRequest(
            principal.tenant_id,
            principal.subject_id,
            request.operation,
            request.payload,
            request.request_id,
            request.trace_id,
        )
        return self.dispatch(authenticated_request)
