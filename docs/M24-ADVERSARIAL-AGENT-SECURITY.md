# M24 — Adversarial Agent Security

M24 makes agent-specific attack classes executable as a release security gate.

Covered classes include goal hijacking, tool misuse, identity/privilege abuse, memory poisoning, inter-agent attacks, cascading failures, trust exploitation, data exfiltration, sandbox escape and resource exhaustion.

Each regression case declares an expected blocking outcome and evidence reference. A release gate fails closed when a declared blocking case is observed to succeed.

The gate does not replace authorization, sandboxing or policy enforcement. It verifies that those authoritative controls resist known adversarial behaviors.

M24 is complete only when the adversarial corpus, tests, documentation and every CI/security workflow are green.
