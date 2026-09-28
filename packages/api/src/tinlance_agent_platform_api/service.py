from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class APIRequest:
    tenant_id: str
    subject_id: str
    operation: str
    payload: dict[str, object]


@dataclass(frozen=True, slots=True)
class APIResponse:
    status: str
    payload: dict[str, object]


class APIHandler(Protocol):
    def handle(self, request: APIRequest) -> APIResponse: ...


class AgentPlatformAPI:
    def __init__(self, handler: APIHandler) -> None:
        self._handler = handler

    def dispatch(self, request: APIRequest) -> APIResponse:
        if not request.tenant_id or not request.subject_id or not request.operation:
            raise PermissionError("tenant, subject and operation are required")
        return self._handler.handle(request)
