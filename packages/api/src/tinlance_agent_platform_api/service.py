import json
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from threading import RLock
from typing import Protocol

API_VERSION = "1.1"
_IDEMPOTENT_GUARDED_OPERATIONS = frozenset(
    {"runs.create", "runs.cancel", "approvals.request", "approvals.decide"}
)
_MAX_IDEMPOTENCY_ENTRIES = 1024


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
    idempotency_key: str | None = None
    authenticated_principal: object | None = None


@dataclass(frozen=True, slots=True)
class APIResponse:
    status: str
    payload: dict[str, object]


class APIHandler(Protocol):
    def handle(self, request: APIRequest) -> APIResponse: ...


class AuthenticationError(PermissionError):
    """Raised when bearer authentication cannot establish a principal."""


class IdempotencyConflictError(ValueError):
    """Raised when one request ID is reused for a different consequential request."""


class PrincipalResolver(Protocol):
    """Resolve an already-authenticated bearer credential to a platform principal."""

    def resolve(self, bearer_token: str) -> AuthenticatedPrincipal: ...


class AgentPlatformAPI:
    def __init__(self, handler: APIHandler) -> None:
        self._handler = handler
        self._idempotency: dict[str, tuple[str, APIResponse]] = {}
        self._idempotency_order: list[str] = []
        self._idempotency_lock = RLock()

    @staticmethod
    def _fingerprint(request: APIRequest) -> str:
        canonical = json.dumps(
            {
                "tenant_id": request.tenant_id,
                "subject_id": request.subject_id,
                "operation": request.operation,
                "payload": request.payload,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return sha256(canonical.encode("utf-8")).hexdigest()

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

        if request.operation not in _IDEMPOTENT_GUARDED_OPERATIONS:
            return self._handler.handle(request)

        fingerprint = self._fingerprint(request)
        with self._idempotency_lock:
            key = request.idempotency_key or request.request_id
            existing = self._idempotency.get(key)
            if existing is not None:
                if existing[0] != fingerprint:
                    raise IdempotencyConflictError("request ID was reused for a different request")
                return deepcopy(existing[1])

            # The reference boundary serializes guarded side effects so two
            # concurrent deliveries with the same request ID cannot both execute.
            response = self._handler.handle(request)
            self._idempotency[key] = (fingerprint, deepcopy(response))
            self._idempotency_order.append(key)
            while len(self._idempotency_order) > _MAX_IDEMPOTENCY_ENTRIES:
                evicted = self._idempotency_order.pop(0)
                self._idempotency.pop(evicted, None)
            return response

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
            request.idempotency_key,
            principal,
        )
        return self.dispatch(authenticated_request)


class ExecutionAPIError(PermissionError):
    """Structured failure emitted by the governed execution contract."""

    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable
