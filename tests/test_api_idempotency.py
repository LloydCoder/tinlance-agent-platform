import pytest

from tinlance_agent_platform_api.service import (
    AgentPlatformAPI,
    APIRequest,
    APIResponse,
    IdempotencyConflictError,
)


class Handler:
    def __init__(self) -> None:
        self.requests: list[APIRequest] = []

    def handle(self, request: APIRequest) -> APIResponse:
        self.requests.append(request)
        return APIResponse("accepted", {"tenant_id": request.tenant_id, "payload": request.payload})


def request(tenant_id: str, subject_id: str, payload: dict[str, object]) -> APIRequest:
    return APIRequest(
        tenant_id,
        subject_id,
        "runs.create",
        payload,
        request_id="request-001",
        idempotency_key="shared-idempotency-key-001",
    )


def test_idempotency_keys_are_scoped_to_authenticated_tenant_and_principal() -> None:
    handler = Handler()
    api = AgentPlatformAPI(handler)
    tenant_a = api.dispatch(request("tenant-a", "subject-a", {"intent": "one"}))
    tenant_b = api.dispatch(request("tenant-b", "subject-b", {"intent": "two"}))
    assert tenant_a.payload["tenant_id"] == "tenant-a"
    assert tenant_b.payload["tenant_id"] == "tenant-b"
    assert len(handler.requests) == 2


def test_idempotency_replays_within_scope_and_rejects_payload_conflicts() -> None:
    handler = Handler()
    api = AgentPlatformAPI(handler)
    first = api.dispatch(request("tenant-a", "subject-a", {"intent": "one"}))
    replay = api.dispatch(request("tenant-a", "subject-a", {"intent": "one"}))
    assert replay == first
    assert len(handler.requests) == 1
    with pytest.raises(IdempotencyConflictError):
        api.dispatch(request("tenant-a", "subject-a", {"intent": "different"}))
