# M2 Authorization Threat Model

## Assets
Tenant isolation, principal scopes, capability boundaries, policy decisions and execution authority.

## Threats
- capability substitution;
- scope widening;
- cross-tenant context injection;
- confused-deputy execution;
- stale authorization;
- policy bypass through alternate entry points.

## Required controls
Authorization is deny-by-default. Every side-effect gateway validates tenant, capability, action and resource. The final executor cannot rely on model-selected permissions.

## Acceptance tests
Cross-tenant requests, missing scopes, prohibited capabilities, mismatched action/resource and alternate tool names must all fail closed.
