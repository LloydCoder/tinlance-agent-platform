import json

import pytest

from tinlance_agent_platform_events.envelope import CloudEventEnvelope


def make_event(**overrides):
    value = {
        "id": "event-001",
        "source": "https://tinlance.com/platform/runs",
        "type": "com.tinlance.execution.completed.v1",
        "time": "2026-10-18T04:00:00Z",
        "tenantid": "tenant-a",
        "executionid": "run-001",
        "traceid": "4bf92f3577b34da6a3ce929d0e0e4736",
        "correlationid": "workflow-001",
        "data": {"state": "succeeded"},
    }
    value.update(overrides)
    return CloudEventEnvelope(**value)


def test_platform_envelope_serializes_canonical_cloud_events_names() -> None:
    payload = make_event(subject="run-001", spanid="00f067aa0ba902b7").as_payload()
    assert payload["specversion"] == "1.0"
    assert payload["datacontenttype"] == "application/json"
    assert payload["tenantid"] == "tenant-a"
    assert "tenant_id" not in payload
    assert "data_content_type" not in payload
    assert json.loads(make_event().to_json())["data"]["state"] == "succeeded"


@pytest.mark.parametrize(
    "overrides",
    [
        {"traceid": "0" * 32},
        {"traceid": "not-a-trace"},
        {"spanid": "0" * 16},
        {"time": "2026-10-18T04:00:00"},
        {"source": "not a URI"},
        {"tenantid": " tenant-a"},
        {"datacontenttype": "text/plain"},
        {"specversion": "2.0"},
        {"data": {"nan": float("nan")}},
        {"dataschema": "/relative/schema.json"},
    ],
)
def test_platform_envelope_rejects_invalid_values(overrides) -> None:
    with pytest.raises(ValueError):
        make_event(**overrides)
