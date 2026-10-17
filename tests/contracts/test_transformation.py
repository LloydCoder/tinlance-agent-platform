from uuid import uuid4

import pytest

from tinlance_agent_platform_contracts import (
    Transformation,
    TransformationCapability,
    TransformationExecutionState,
    TransformationOutcome,
    TransformationOutcomeStatus,
    TransformationReference,
)


def test_transformation_payload_preserves_contract_and_authority_boundary() -> None:
    item = Transformation(
        transformation_id=uuid4(),
        tenant_ref="tenant:example",
        version=1,
        principal_ref="principal:human",
        agent_ref="agent:finance",
        agent_version="1.0.0",
        workspace_ref="workspace:finance",
        task_ref="task:001",
        objective="Reconcile transactions",
        success_criteria=("Produce a reconciled report",),
        requested_capabilities=(
            TransformationCapability("capability:finance.reconcile", "reconcile transactions"),
        ),
        policy_refs=("policy:finance",),
        risk_class="high",
        execution_state=TransformationExecutionState.SUCCEEDED,
        approval_refs=("approval:001",),
        output_refs=(TransformationReference("artifact:report", "report"),),
        evidence_refs=(TransformationReference("evidence:run", "execution"),),
        outcome=TransformationOutcome(
            TransformationOutcomeStatus.ACHIEVED,
            True,
            business_effect_refs=("effect:close-time",),
        ),
    )
    payload = item.as_payload()
    assert payload["schema_version"] == "transformation/v1"
    assert payload["requested_capabilities"][0]["capability_ref"] == "capability:finance.reconcile"
    assert payload["governance"]["approval_refs"] == ["approval:001"]
    assert payload["outputs"][0]["ref"] == "artifact:report"
    assert payload["evidence"][0]["ref"] == "evidence:run"
    assert payload["provenance"]["declared_by"] == "agent-platform"
    assert "authorization_decision" not in payload
    assert "capability_grant" not in payload
    assert item.content_digest() == item.content_digest()


def test_achieved_outcome_must_be_consistent() -> None:
    with pytest.raises(ValueError):
        TransformationOutcome(TransformationOutcomeStatus.ACHIEVED, False)
    with pytest.raises(ValueError):
        TransformationOutcome(TransformationOutcomeStatus.PARTIALLY_ACHIEVED, True)
