# Enterprise Conformance

The platform's enterprise claim is based on executable controls, not milestone prose alone.

## Canonical path

Identity -> Authorization -> Approval -> Runtime -> Model Gateway -> Tool/MCP Gateway -> Sandbox -> Orchestration -> Memory -> Evidence/Event -> Observability -> Evaluation -> Domain SDK -> Enterprise

The reference end-to-end path is implemented by GovernedExecutionService and tested by tests/conformance/test_governed_execution.py.

## Security invariants

- Tenant identity is immutable across the request.
- Authorization is deny-by-default and evaluated outside model reasoning.
- Tool execution performs complete mediation immediately before the side effect.
- MCP execution uses the same capability/action/resource authority model and cannot silently drop tenant scope.
- Approval, when required, binds to tenant, run, action and resource.
- Model providers are explicitly registered and can be tenant/agent allowlisted.
- Model responses cannot exceed the requested output-token budget or silently change model identity.
- Evidence is content-hashed and sequence-verified.
- Trajectory is hash-chained and independently verifiable.
- Events reject secret-bearing fields and expose immutable payload mappings.
- Security telemetry is tenant/actor/trace attributable without requiring sensitive prompt content.
- Evaluation results never grant runtime authority.
- Production infrastructure remains behind explicit provider/repository contracts.

## Production/reference boundary

The repository's reference implementations are executable and tested, but deployment still requires real infrastructure: durable PostgreSQL repositories, secret management, approved provider accounts, isolated execution hosts, telemetry backends, backups/restore, incident response and operational SLOs.

Enterprise conformance therefore means the governed core is complete and testable; it does not mean external infrastructure has been provisioned by this repository.
