"""Fail-closed wall-clock execution helpers for governed agent work."""

from __future__ import annotations

import signal
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from time import monotonic
from typing import TypeVar

T = TypeVar("T")


class ExecutionTimeout(TimeoutError):
    """Raised when a governed operation exceeds its wall-clock deadline."""


@contextmanager
def wall_clock_timeout(seconds: float) -> Iterator[None]:
    """Enforce a real wall-clock deadline on Linux/Unix main-thread execution.

    Agent Platform's reference execution path is intentionally fail-closed: a
    governed call must not silently downgrade to a post-hoc elapsed-time check.
    Production async/process workers should enforce the same deadline at their
    supervisor boundary as well.
    """
    if seconds <= 0:
        raise ValueError("timeout must be positive")
    if signal.getsignal(signal.SIGALRM) is signal.SIG_IGN:
        raise RuntimeError("SIGALRM is ignored; refusing to run without a deadline")

    def _alarm(_signum: int, _frame: object) -> None:
        raise ExecutionTimeout("governed operation exceeded its wall-clock deadline")

    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL, previous_timer[0], previous_timer[1])


def call_with_timeout[T](fn: Callable[[], T], seconds: float) -> tuple[T, float]:
    """Call *fn* with a hard wall-clock deadline and return result + duration."""
    started = monotonic()
    with wall_clock_timeout(seconds):
        result = fn()
    return result, monotonic() - started
