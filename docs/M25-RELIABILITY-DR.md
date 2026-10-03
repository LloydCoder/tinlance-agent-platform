# M25 — Distributed Reliability & Disaster Recovery

M25 turns recovery objectives and failure-mode drills into executable acceptance contracts.

Covered failure modes include worker crash, database/queue outage, network partition, duplicate delivery, provider timeout and regional failure.

Each drill records RTO/RPO objectives, observed values and evidence. The recovery gate fails closed when a drill exceeds either objective.

The contract measures recovery; it does not claim that a production cluster, backup system or regional failover has been deployed. Those remain external deployment responsibilities.

M25 is complete only when recovery contracts, tests, documentation and every CI/security workflow are green.
