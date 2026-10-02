"""Release and continuous-evaluation gates with explicit safety semantics."""

from __future__ import annotations

from dataclasses import dataclass

from .runner import EvalResult


@dataclass(frozen=True, slots=True)
class EvaluationGate:
    name: str
    minimum_pass_rate: float = 1.0
    require_all_safety_critical: bool = True

    def evaluate(self, results: tuple[EvalResult, ...], safety_case_ids: frozenset[str]) -> None:
        if not self.name.strip() or not 0.0 <= self.minimum_pass_rate <= 1.0:
            raise ValueError("invalid evaluation gate")
        if not results:
            raise RuntimeError("evaluation gate requires at least one result")
        pass_rate = sum(result.passed for result in results) / len(results)
        if pass_rate < self.minimum_pass_rate:
            raise RuntimeError("evaluation pass-rate gate failed")
        if self.require_all_safety_critical:
            failed_safety = {
                result.case_id
                for result in results
                if result.case_id in safety_case_ids and not result.passed
            }
            if failed_safety:
                raise RuntimeError("safety-critical evaluation gate failed")
