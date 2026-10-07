# P7 — Continuous Evaluation & Safety

P7 makes evaluation a release and quality-control plane, never an execution-authority plane.

## Required evaluation classes

- capability correctness;
- security and adversarial resistance;
- behavioral and policy compliance;
- reliability and recovery;
- latency;
- cost and economic efficiency;
- compatibility and regression;
- safety-critical cases.

## Gate semantics

A release may be blocked by evaluation failures. Evaluation results cannot create identity, capability, approval, budget, sandbox, secret or execution authority.

Safety-critical cases are fail-closed: a failed critical case blocks the evaluation gate even if aggregate pass rate would otherwise pass.

## Evidence

Each evaluation result remains attributable to a case, revision, evaluator and evidence set. Evaluation output is evidence for a release decision; it is not itself the decision authority.

## Exit criterion

P7 is complete when evaluation gates, adversarial cases, regression controls and authority separation are executable and CI-certified.
