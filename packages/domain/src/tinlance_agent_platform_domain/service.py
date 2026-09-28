"""Pure lifecycle and ancestry rules; persistence lives behind adapters."""
from dataclasses import replace
from .models import Assessment, AssessmentStatus, Finding, FindingStatus
class InvalidTransition(ValueError): pass
class IdempotencyConflict(ValueError): pass
_TRANSITIONS={AssessmentStatus.CREATED:{AssessmentStatus.QUEUED,AssessmentStatus.CANCELLED},AssessmentStatus.QUEUED:{AssessmentStatus.RUNNING,AssessmentStatus.CANCELLED},AssessmentStatus.RUNNING:{AssessmentStatus.COMPLETED,AssessmentStatus.FAILED,AssessmentStatus.CANCELLED},AssessmentStatus.COMPLETED:set(),AssessmentStatus.FAILED:{AssessmentStatus.QUEUED},AssessmentStatus.CANCELLED:set()}
class DomainService:
    @staticmethod
    def transition_assessment(assessment: Assessment,target: AssessmentStatus)->Assessment:
        if target not in _TRANSITIONS[assessment.status]: raise InvalidTransition(f"{assessment.status} -> {target} is not permitted")
        return replace(assessment,status=target)
    @staticmethod
    def transition_finding(finding: Finding,target: FindingStatus)->Finding:
        if finding.status in {FindingStatus.REMEDIATED,FindingStatus.FALSE_POSITIVE}: raise InvalidTransition(f"terminal finding cannot transition from {finding.status}")
        return replace(finding,status=target)
    @staticmethod
    def assert_ancestry(*,tenant_id,parent_tenant_id)->None:
        if tenant_id != parent_tenant_id: raise PermissionError("cross-tenant ancestry is forbidden")
    @staticmethod
    def assert_idempotency_key(key:str)->None:
        if not key or len(key)>255: raise ValueError("idempotency key must contain 1..255 characters")