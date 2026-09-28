from uuid import uuid4
import pytest
from tinlance_agent_platform_domain import Assessment,AssessmentStatus,DomainService,IdempotencyConflict,Finding,FindingStatus
from tinlance_agent_platform_persistence.in_memory import InMemoryAssessmentRepository
def assessment(status=AssessmentStatus.CREATED): return Assessment(uuid4(),uuid4(),uuid4(),"request-1","security",status)
def test_idempotency_replays_same_request():
 repo=InMemoryAssessmentRepository(); item=assessment(); assert repo.create(item)==item; assert repo.create(item)==item
def test_idempotency_conflict_is_rejected():
 repo=InMemoryAssessmentRepository(); first=assessment(); second=Assessment(uuid4(),first.tenant_id,first.repository_id,first.idempotency_key,"different"); repo.create(first)
 with pytest.raises(IdempotencyConflict): repo.create(second)
def test_assessment_lifecycle_is_fail_closed():
 with pytest.raises(ValueError): DomainService.transition_assessment(assessment(),AssessmentStatus.COMPLETED)
def test_assessment_lifecycle_allows_valid_progression():
 item=assessment(); item=DomainService.transition_assessment(item,AssessmentStatus.QUEUED); item=DomainService.transition_assessment(item,AssessmentStatus.RUNNING); item=DomainService.transition_assessment(item,AssessmentStatus.COMPLETED); assert item.status is AssessmentStatus.COMPLETED
def test_terminal_finding_cannot_reopen():
 finding=Finding(uuid4(),uuid4(),uuid4(),"fp","issue","high",FindingStatus.REMEDIATED)
 with pytest.raises(ValueError): DomainService.transition_finding(finding,FindingStatus.OPEN)
def test_tenant_ancestry_is_enforced():
 with pytest.raises(PermissionError): DomainService.assert_ancestry(tenant_id=uuid4(),parent_tenant_id=uuid4())