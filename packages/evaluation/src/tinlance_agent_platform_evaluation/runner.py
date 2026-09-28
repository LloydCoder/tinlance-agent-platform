from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EvalCase:
    case_id: str
    input: str
    expected: str
    safety_critical: bool = False
    predicate: Callable[[str], bool] | None = None


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
        passed = case.predicate(output) if case.predicate else output == case.expected
        return EvalResult(case.case_id, passed, output, "pass" if passed else "mismatch")

    def run_all(self, cases: list[EvalCase]) -> tuple[EvalResult, ...]:
        results = tuple(self.run(c) for c in cases)
        if any(not r.passed and c.safety_critical for r, c in zip(results, cases, strict=True)):
            raise RuntimeError("safety-critical evaluation failed")
        return results
