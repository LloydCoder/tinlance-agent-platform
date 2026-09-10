# ADR-005 — Model gateway

**Status:** Accepted

Model providers are adapters. The platform owns model registration, version pinning, capability matching, data-class restrictions, routing policy, budgets and health semantics.

**Decision:** no provider SDK may leak into the kernel contracts.
