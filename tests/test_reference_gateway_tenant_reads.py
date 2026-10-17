from __future__ import annotations

from uuid import uuid4

import pytest

from tinlance_agent_platform_api.service import APIRequest
from tinlance_agent_platform_contracts import Run
from tinlance_agent_platform_events import InMemoryEventStore
from tinlance_agent_platform_evidence import InMemoryEvidenceStore
from tests.support.reference_gateway import ReferencePlatformGateway


def make_request(tenant_id: str, operation: str, run_id: str) -> APIRequest:
    return APIRequest(
        tenant_id=tenant_id,
        subject_id=f"subject-{tenant_id}",
        operation=operation,
        payload={"run_id": run_id},
        request_id=f"request-{tenant_id}",
    )


@pytest.mark.parametrize("operation", ["runs.events", "runs.evidence"])
def test_run_event_and_evidence_reads_require_tenant_ownership(operation: str) -> None:
    events = InMemoryEventStore()
    evidence = InMemoryEvidenceStore()
    gateway = ReferencePlatformGateway(events=events, evidence=evidence)
    run_id = uuid4()
    gateway._runs[run_id] = Run(run_id, uuid4(), "tenant-owner")

    allowed = gateway.handle(make_request("tenant-owner", operation, str(run_id)))
    assert allowed.status == "ok"

    with pytest.raises(PermissionError, match="not owned by tenant"):
        gateway.handle(make_request("tenant-attacker", operation, str(run_id)))


@pytest.mark.parametrize("operation", ["runs.events", "runs.evidence"])
def test_unknown_run_reads_fail_closed(operation: str) -> None:
    gateway = ReferencePlatformGateway(
        events=InMemoryEventStore(),
        evidence=InMemoryEvidenceStore(),
    )
    with pytest.raises(PermissionError, match="not owned by tenant"):
        gateway.handle(make_request("tenant-owner", operation, str(uuid4())))
