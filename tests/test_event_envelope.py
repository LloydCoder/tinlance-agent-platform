from __future__ import annotations

import json

import pytest

from tinlance_agent_platform_events.envelope import EventEnvelope


def envelope(**overrides: object) -> EventEnvelope:
    values: dict[str, object] = {
        "specversion": "1.0",
        "id": "evt-0001",
        "source": "urn:tinlance:agent-platform:execution",
        "type": "com.tinlance.agent.run.created.v1",
        "time": "2026-10-17T22:00:00Z",
        "subject": "run:0001",
        "datacontenttype": "application/json",
        "tenantid": "tenant:finance",
        "executionid": "execution:0001",
        "traceid": "1" * 32,
        "correlationid": "request:0001",
        "idempotencykey": "run-create-0001",
        "data": {"run_id": "0001", "details": {"state": "accepted"}},
    }
    values.update(overrides)
    return EventEnvelope(**values)  # type: ignore[arg-type]


def test_envelope_round_trips_and_digest_is_canonical() -> None:
    item = envelope()
    decoded = EventEnvelope.from_json(item.to_json())
    assert decoded.to_payload() == item.to_payload()
    assert decoded.payload_digest == item.payload_digest
    assert decoded.to_payload()["datacontenttype"] == "application/json"
    assert "data_content_type" not in decoded.to_payload()


def test_envelope_deep_freezes_payload() -> None:
    item = envelope()
    with pytest.raises(TypeError):
        item.data["new"] = "value"  # type: ignore[index]
    nested = item.data["details"]
    assert isinstance(nested, dict) is False
    with pytest.raises(TypeError):
        nested["state"] = "changed"  # type: ignore[index]


@pytest.mark.parametrize(
    "changes",
    [
        {"traceid": "0" * 32},
        {"traceid": "not-a-trace"},
        {"type": "run.created"},
        {"time": "2026-10-17T22:00:00"},
        {"tenantid": " tenant:finance"},
        {"datacontenttype": "text/plain"},
        {"data": {"api_key": "must-not-be-stored"}},
    ],
)
def test_envelope_rejects_invalid_or_sensitive_attributes(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        envelope(**changes)


def test_envelope_rejects_undeclared_attributes_on_decode() -> None:
    payload = json.loads(envelope().to_json())
    payload["auth_token"] = "never accept"
    with pytest.raises(ValueError, match="undeclared"):
        EventEnvelope.from_payload(payload)
