"""Authority-side canonical trace lineage contract.

Trace data is audit/observability metadata, never an authorization grant.
Sensitive payloads and credentials are not accepted as attributes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID = re.compile(r"^[0-9a-f]{16}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CLASSIFICATIONS = {"public", "internal", "confidential", "restricted"}
_SAFE_ATTRIBUTE_KEYS = {"service", "component", "outcome", "route_id", "attempt"}
_OUTCOMES = {"started", "succeeded", "failed", "cancelled", "denied", "pending"}


def _required(value: str, label: str, limit: int = 256) -> None:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > limit:
        raise ValueError(f"{label} must be normalized, non-empty, and at most {limit} characters")


def _timestamp(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        raise ValueError("started_at must be an ISO-8601 date-time") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("started_at must include a timezone")


@dataclass(frozen=True, slots=True)
class TraceEvidenceRef:
    evidence_id: str
    kind: str
    sha256: str
    source: str | None = None
    observed_at: str | None = None

    def __post_init__(self) -> None:
        _required(self.evidence_id, "evidence_id", 512)
        _required(self.kind, "evidence kind", 128)
        if not _SHA256.fullmatch(self.sha256):
            raise ValueError("evidence sha256 must be lowercase SHA-256 hex")
        if self.source is not None:
            _required(self.source, "evidence source", 512)
        if self.observed_at is not None:
            _timestamp(self.observed_at)

    def as_payload(self) -> dict[str, str]:
        value = {"evidence_id": self.evidence_id, "kind": self.kind, "sha256": self.sha256}
        if self.source is not None:
            value["source"] = self.source
        if self.observed_at is not None:
            value["observed_at"] = self.observed_at
        return value


@dataclass(frozen=True, slots=True)
class TraceLineageContext:
    trace_id: str
    span_id: str
    correlation_id: str
    request_id: str
    tenant_id: str
    operation: str
    started_at: str
    data_classification: Literal["public", "internal", "confidential", "restricted"] = "internal"
    parent_span_id: str | None = None
    workspace_id: str | None = None
    execution_id: str | None = None
    event_id: str | None = None
    decision_id: str | None = None
    approval_id: str | None = None
    tool_call_id: str | None = None
    policy_decision_id: str | None = None
    evidence_refs: tuple[TraceEvidenceRef, ...] = ()
    safe_attributes: tuple[tuple[str, str | int], ...] = ()

    def __post_init__(self) -> None:
        if not _TRACE_ID.fullmatch(self.trace_id) or set(self.trace_id) == {"0"}:
            raise ValueError("trace_id must be a non-zero W3C 16-byte lowercase hex identifier")
        if not _SPAN_ID.fullmatch(self.span_id) or set(self.span_id) == {"0"}:
            raise ValueError("span_id must be a non-zero W3C 8-byte lowercase hex identifier")
        if self.parent_span_id is not None and (
            not _SPAN_ID.fullmatch(self.parent_span_id) or set(self.parent_span_id) == {"0"}
        ):
            raise ValueError("parent_span_id must be a non-zero W3C span identifier")
        for value, label in (
            (self.correlation_id, "correlation_id"),
            (self.request_id, "request_id"),
            (self.tenant_id, "tenant_id"),
            (self.operation, "operation"),
        ):
            _required(value, label)
        for optional_value, label in (
            (self.workspace_id, "workspace_id"),
            (self.execution_id, "execution_id"),
            (self.event_id, "event_id"),
            (self.decision_id, "decision_id"),
            (self.approval_id, "approval_id"),
            (self.tool_call_id, "tool_call_id"),
            (self.policy_decision_id, "policy_decision_id"),
        ):
            if optional_value is not None:
                _required(optional_value, label)
        _timestamp(self.started_at)
        if self.data_classification not in _CLASSIFICATIONS:
            raise ValueError("unsupported data classification")
        if len(self.evidence_refs) > 1000:
            raise ValueError("evidence_refs exceeds 1000 entries")
        seen: set[str] = set()
        for key, attribute_value in self.safe_attributes:
            if key not in _SAFE_ATTRIBUTE_KEYS:
                raise ValueError(f"unsafe or unsupported trace attribute: {key}")
            if key in seen:
                raise ValueError(f"duplicate trace attribute: {key}")
            seen.add(key)
            if key == "outcome" and attribute_value not in _OUTCOMES:
                raise ValueError("unsupported trace outcome")
            if key == "attempt" and (
                not isinstance(attribute_value, int)
                or isinstance(attribute_value, bool)
                or attribute_value < 0
                or attribute_value > 1000
            ):
                raise ValueError("trace attempt must be an integer between 0 and 1000")
            if isinstance(attribute_value, str):
                _required(attribute_value, f"trace attribute {key}", 256)
            elif not isinstance(attribute_value, int) or isinstance(attribute_value, bool):
                raise ValueError(f"trace attribute {key} must be a string or integer")

    @property
    def traceparent(self) -> str:
        """Return the W3C traceparent header for the current span."""
        return f"00-{self.trace_id}-{self.span_id}-00"

    def as_headers(self) -> dict[str, str]:
        """Propagate W3C trace context plus stable request correlation identifiers."""
        return {
            "traceparent": self.traceparent,
            "x-correlation-id": self.correlation_id,
            "x-request-id": self.request_id,
        }

    def as_payload(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": "trace-context/v1",
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "correlation_id": self.correlation_id,
            "request_id": self.request_id,
            "tenant_id": self.tenant_id,
            "operation": self.operation,
            "started_at": self.started_at,
            "data_classification": self.data_classification,
        }
        for key in (
            "parent_span_id",
            "workspace_id",
            "execution_id",
            "event_id",
            "decision_id",
            "approval_id",
            "tool_call_id",
            "policy_decision_id",
        ):
            current = getattr(self, key)
            if current is not None:
                value[key] = current
        if self.evidence_refs:
            value["evidence_refs"] = [ref.as_payload() for ref in self.evidence_refs]
        if self.safe_attributes:
            value["safe_attributes"] = {key: val for key, val in self.safe_attributes}
        return value

    def child(self, *, span_id: str, operation: str, started_at: str) -> TraceLineageContext:
        return TraceLineageContext(
            trace_id=self.trace_id,
            span_id=span_id,
            parent_span_id=self.span_id,
            correlation_id=self.correlation_id,
            request_id=self.request_id,
            tenant_id=self.tenant_id,
            workspace_id=self.workspace_id,
            execution_id=self.execution_id,
            operation=operation,
            started_at=started_at,
            data_classification=self.data_classification,
        )
