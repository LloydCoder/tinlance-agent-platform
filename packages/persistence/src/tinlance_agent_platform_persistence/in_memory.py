from uuid import UUID
from tinlance_agent_platform_domain import Assessment,DomainService,IdempotencyConflict
from .ports import AssessmentRepository
class InMemoryAssessmentRepository(AssessmentRepository):
    def __init__(self)->None: self._items={}; self._keys={}
    def get_by_idempotency(self,tenant_id:UUID,key:str)->Assessment|None:
        item=self._keys.get((tenant_id,key)); return self._items.get(item) if item else None
    def create(self,assessment:Assessment)->Assessment:
        DomainService.assert_idempotency_key(assessment.idempotency_key)
        existing=self.get_by_idempotency(assessment.tenant_id,assessment.idempotency_key)
        if existing and existing != assessment: raise IdempotencyConflict("idempotency key already belongs to another request")
        if existing: return existing
        self._items[assessment.assessment_id]=assessment; self._keys[(assessment.tenant_id,assessment.idempotency_key)]=assessment.assessment_id; return assessment
    def get(self,tenant_id:UUID,assessment_id:UUID)->Assessment|None:
        item=self._items.get(assessment_id); return item if item and item.tenant_id==tenant_id else None
    def update(self,assessment:Assessment)->Assessment:
        if self.get(assessment.tenant_id,assessment.assessment_id) is None: raise KeyError("assessment not found")
        self._items[assessment.assessment_id]=assessment; return assessment