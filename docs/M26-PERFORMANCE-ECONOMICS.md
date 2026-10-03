# M26 — Performance & Economic Governance

M26 adds measurable capacity envelopes and tenant economic quotas.

Capacity gates cover minimum throughput, p95/p99 latency and maximum concurrency. Tenant quotas cover concurrent executions, tool calls, token units and cost units.

These controls provide admission and release evidence; they do not promise a fixed capacity independent of infrastructure, provider latency or workload.

M26 is complete only when capacity/quota contracts, tests, documentation and every CI/security workflow are green.
