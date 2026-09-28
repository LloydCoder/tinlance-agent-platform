# M2 Authorization Threat Model

## Abuse cases

- Request claims a different tenant than its principal.
- Capability parameters are mutated after authorization.
- Action/resource differs between authorization and execution.
- Child agent attempts to widen parent capabilities.
- A prohibited or secret-data capability is smuggled through an allowed scope.
- Tool registration is mistaken for authorization.

## Controls

Authorization is deny-by-default; principal and tenant are normalized; capability requests are immutable/defensively frozen; exact capability/action/resource binding is checked at the side-effect boundary; child authority is narrowed; prohibited and secret capabilities are hard denied.

## Test obligations

Cross-tenant requests, scope mismatch, action mismatch, resource mismatch, mutable-parameter attempts, child widening and prohibited-capability cases must fail closed.
