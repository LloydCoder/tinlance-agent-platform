from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EvalCase:
    case_id: str
    input: str
    expected: str
    safety_critical: bool = False


@dataclass(frozen=True, slots=True)
class EvalResult:
    case_id: str
    passed: bool
    output: str
    reason: str


class EvalRunner:
    def __init__(self, execute: Callable[[str], str]) -> None:
        self._execute = execute

    def run(self, case: EvalCase) -> EvalResult:
        try:
            output = self._execute(case.input)
        except Exception as exc:
            return EvalResult(case.case_id, False, "", type(exc).__name__)
        passed = output == case.expected
        reason = "pass" if passed else "mismatch"
        return EvalResult(case.case_id, passed, output, reason)

    def run_all(self, cases: list[EvalCase]) -> tuple[EvalResult, ...]:
        results = tuple(self.run(case) for case in cases)
        if any(
            not result.passed and case.safety_critical
            for result, case in zip(results, cases, strict=True)
        ):
            raise RuntimeError("safety-critical evaluation failed")
        return results
