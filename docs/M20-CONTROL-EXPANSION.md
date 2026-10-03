# M20 — Enterprise Control Expansion

## Objective

Add the missing provider-neutral control contracts required for advanced enterprise operation without creating a second authority system.

## Modules

### Risk
Classifies consequential actions by severity and contributing factors. Risk may require explicit approval but never grants authorization.

### Control
Defines portable runtime interception hooks. A control hook may allow, deny or require review; only the existing authoritative execution boundary can grant permission.

### Registry
Provides tenant-bound lifecycle metadata for governed resources such as agents, tools, MCP servers, models, policies, runtimes and remote agents. Registration is inventory, not authorization.

### Attestation
Represents time-bounded agent/workload/artifact/runtime trust claims. Attestation is a verification input and cannot widen tenant, capability or policy authority.

### Crypto
Defines key references, versions, algorithms and signature envelopes. Private key material is never stored in the Platform contract layer; production cryptography is supplied by KMS/HSM or an equivalent trusted adapter.

### Compliance
Maps a control to implementation, test, evidence, owner and optional framework references. The mapping is an evidence index, not a compliance certification.

## Security invariants

1. Risk never grants authority.
2. Control hooks cannot bypass identity, tenancy, authorization, policy or approval.
3. Registry state cannot authorize a resource.
4. Attestation cannot widen authority or change tenant scope.
5. Cryptographic key material remains outside provider-neutral contracts.
6. Compliance mappings cannot claim evidence that is absent.
7. Every consequential action still re-enters the R10 governed execution boundary.
8. The new packages remain independent from Agent OS and all domain products.

## Completion evidence

M20 is complete only when package exports, wheel configuration, tests, boundary checks and documentation are green across the complete CI/security workflow set.
