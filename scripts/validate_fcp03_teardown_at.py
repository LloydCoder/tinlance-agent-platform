"""Validate the required disposable FCP-03 stack auto-teardown deadline."""

from __future__ import annotations

from argparse import ArgumentParser
from datetime import UTC, datetime, timedelta


MINIMUM_WINDOW = timedelta(minutes=15)
MAXIMUM_WINDOW = timedelta(hours=2)
UTC_FORMAT = "%Y-%m-%dT%H:%M:%S"


def validate_teardown_at(
    value: str, *, now: datetime | None = None
) -> datetime:
    """Require a naive-formatted UTC timestamp 15 minutes to 2 hours ahead."""
    try:
        deadline = datetime.strptime(value, UTC_FORMAT).replace(tzinfo=UTC)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"teardown time must use {UTC_FORMAT} in UTC, without a timezone suffix"
        ) from exc

    reference = now if now is not None else datetime.now(UTC)
    if reference.tzinfo is None or reference.utcoffset() != timedelta(0):
        raise ValueError("reference clock must be timezone-aware UTC")

    remaining = deadline - reference
    if remaining < MINIMUM_WINDOW:
        raise ValueError("teardown deadline must be at least 15 minutes in the future")
    if remaining > MAXIMUM_WINDOW:
        raise ValueError("teardown deadline must be no more than 2 hours in the future")
    return deadline


def main(argv: list[str] | None = None) -> int:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument(
        "--teardown-at",
        required=True,
        help="UTC timestamp YYYY-MM-DDTHH:MM:SS (no Z or offset)",
    )
    args = parser.parse_args(argv)
    try:
        deadline = validate_teardown_at(args.teardown_at)
    except ValueError as exc:
        parser.error(str(exc))
    print(f"valid auto-teardown deadline: {deadline.strftime(UTC_FORMAT)} UTC")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
