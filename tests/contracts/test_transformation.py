from uuid import uuid4

import pytest

from tinlance_agent_platform_contracts import (
    Transformation,
    TransformationExecutionState,
    TransformationOutcome,
    TransformationOutcomeStatus,
)


def test_transformation_contract_preserves_authority_boundary() -> None:
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
        requested_capability_refs=("capability:finance.reconcile",),
        policy_refs=("policy:finance",),
        risk_class="high",
        execution_state=TransformationExecutionState.SUCCEEDED,
        outcome=TransformationOutcome(
            TransformationOutcomeStatus.ACHIEVED,
            True,
            business_effect_refs=("effect:close-time",),
        ),
    )
    assert item.tenant_ref == "tenant:example"
    assert item.outcome is not None
    assert not hasattr(item, "authorization_decision")


def test_achieved_outcome_must_be_true() -> None:
    with pytest.raises(ValueError):
        TransformationOutcome(TransformationOutcomeStatus.ACHIEVED, False)
