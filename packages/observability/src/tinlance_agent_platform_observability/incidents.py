from dataclasses import dataclass, field
from threading import RLock
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class IncidentCorrelation:
    incident_id: UUID
    tenant_id: str
    run_id: UUID | None = None
    execution_id: UUID | None = None
    trace_ids: tuple[str, ...] = ()
    security_event_ids: tuple[UUID, ...] = ()
    audit_ids: tuple[UUID, ...] = ()
    evidence_ids: tuple[UUID, ...] = ()


class IncidentCorrelator:
    def __init__(self) -> None:
        self._incidents: dict[UUID, IncidentCorrelation] = {}
        self._lock = RLock()

    def start(
        self,
        tenant_id: str,
        *,
        run_id: UUID | None = None,
        execution_id: UUID | None = None,
        trace_id: str | None = None,
    ) -> IncidentCorrelation:
        if not tenant_id or tenant_id != tenant_id.strip():
            raise ValueError("incident tenant is required")
        if trace_id is not None and not trace_id.strip():
            raise ValueError("trace_id cannot be empty")
        incident = IncidentCorrelation(
            uuid4(),
            tenant_id,
            run_id,
            execution_id,
            (trace_id,) if trace_id else (),
        )
        with self._lock:
            self._incidents[incident.incident_id] = incident
        return incident

    def add_security_event(self, incident_id: UUID, event_id: UUID) -> None:
        with self._lock:
            incident = self._require(incident_id)
            self._incidents[incident_id] = IncidentCorrelation(
                incident.incident_id,
                incident.tenant_id,
                incident.run_id,
                incident.execution_id,
                incident.trace_ids,
                incident.security_event_ids + (event_id,),
                incident.audit_ids,
                incident.evidence_ids,
            )

    def add_audit(self, incident_id: UUID, audit_id: UUID) -> None:
        with self._lock:
            incident = self._require(incident_id)
            self._incidents[incident_id] = IncidentCorrelation(
                incident.incident_id,
                incident.tenant_id,
                incident.run_id,
                incident.execution_id,
                incident.trace_ids,
                incident.security_event_ids,
                incident.audit_ids + (audit_id,),
                incident.evidence_ids,
            )

    def get(self, incident_id: UUID) -> IncidentCorrelation:
        with self._lock:
            return self._require(incident_id)

    def _require(self, incident_id: UUID) -> IncidentCorrelation:
        try:
            return self._incidents[incident_id]
        except KeyError as exc:
            raise LookupError("incident does not exist") from exc
