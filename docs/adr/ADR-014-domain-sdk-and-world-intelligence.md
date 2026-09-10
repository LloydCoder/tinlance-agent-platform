# ADR-014 — Domain SDK and World Intelligence

**Status:** Accepted

The Domain SDK exposes versioned registration primitives for agents, skills, tools, policies, workflows, events and evidence. World Intelligence uses those contracts as a domain capability and does not modify kernel authority rules.

**Decision:** domain registration is declarative and governed; registering a domain capability never grants additional authority by itself.
