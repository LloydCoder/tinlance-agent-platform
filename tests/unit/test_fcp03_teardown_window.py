from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from scripts.validate_fcp03_teardown_at import validate_teardown_at


NOW = datetime(2026, 11, 9, 9, 0, 0, tzinfo=timezone.utc)


def test_accepts_a_teardown_deadline_inside_the_bounded_window() -> None:
    result = validate_teardown_at("2026-11-09T10:30:00", now=NOW)

    assert result == NOW + timedelta(minutes=90)


@pytest.mark.parametrize(
    "value",
    [
        "2026-11-09T09:14:59",
        "2026-11-09T11:00:01",
        "2026-11-09T10:30:00Z",
        "2026-11-09T10:30:00+01:00",
        "not-a-time",
    ],
)
def test_rejects_deadlines_outside_the_bounded_utc_window(value: str) -> None:
    with pytest.raises(ValueError):
        validate_teardown_at(value, now=NOW)


def test_rejects_a_naive_or_non_utc_reference_clock() -> None:
    with pytest.raises(ValueError):
        validate_teardown_at(
            "2026-11-09T10:30:00",
            now=datetime(2026, 11, 9, 9, 0, 0),
        )
