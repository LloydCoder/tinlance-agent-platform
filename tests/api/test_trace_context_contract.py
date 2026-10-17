from tinlance_agent_platform_api.http import _traceparent


def test_traceparent_extracts_distinct_ids() -> None:
    trace_id = "1" * 32
    span_id = "2" * 16
    header = f"00-{trace_id}-{span_id}-01"
    assert _traceparent(header) == (trace_id, span_id, header)
