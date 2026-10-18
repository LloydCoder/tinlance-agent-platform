import pytest

from tinlance_agent_platform_registry.ecosystem import (
    AgentRegistration,
    AuthorityMode,
    CompatibilityRule,
    ContractRegistration,
    EcosystemRegistrySnapshot,
    ServiceRegistration,
)

SHAS = {
    "developer": "a" * 40,
    "os": "b" * 40,
    "platform": "c" * 40,
    "platform_sdk": "d" * 40,
    "tsic": "e" * 40,
}

CONTRACTS = (
    ContractRegistration("governed-execution.v1", "1.0", "platform"),
    ContractRegistration("event-envelope.v1", "1.0", "tsic"),
    ContractRegistration("trace-context.v1", "1.0", "tsic"),
    ContractRegistration("transformation.v1", "1.0", "developer"),
    ContractRegistration("replication.v1", "1.0", "developer"),
    ContractRegistration("registry-manifest.v1", "1.0", "tsic"),
)

SERVICES = (
    ServiceRegistration(
        "agent-platform.api",
        "platform",
        SHAS["platform"],
        "1.1",
        ("governed-execution.v1", "event-envelope.v1", "trace-context.v1"),
        ("agent.execute", "tool.invoke"),
        AuthorityMode.SOLE_CONSEQUENTIAL_EXECUTION,
    ),
    ServiceRegistration(
        "agent-os.runtime",
        "os",
        SHAS["os"],
        "1.1",
        ("event-envelope.v1", "trace-context.v1"),
        ("event.publish", "trace.propagate"),
        AuthorityMode.AUTHORITY_FREE,
    ),
    ServiceRegistration(
        "platform-sdk.client",
        "platform_sdk",
        SHAS["platform_sdk"],
        "1.1",
        ("governed-execution.v1", "event-envelope.v1", "trace-context.v1"),
        ("request.submit", "trace.propagate"),
        AuthorityMode.AUTHORITY_FREE,
    ),
    ServiceRegistration(
        "tadl.validator",
        "developer",
        SHAS["developer"],
        "1.1",
        ("transformation.v1", "replication.v1", "trace-context.v1", "registry-manifest.v1"),
        ("artifact.validate", "registry.validate"),
        AuthorityMode.AUTHORITY_FREE,
    ),
    ServiceRegistration(
        "tsic.conformance",
        "tsic",
        SHAS["tsic"],
        "1.1",
        ("event-envelope.v1", "trace-context.v1", "registry-manifest.v1"),
        ("contract.validate", "compatibility.validate"),
        AuthorityMode.CONFORMANCE_ONLY,
    ),
)

AGENTS = (
    AgentRegistration(
        "reference.enterprise-a",
        "platform",
        SHAS["platform"],
        ("agent.execute", "tool.invoke"),
        (
            ("governed-execution.v1", "1.0"),
            ("event-envelope.v1", "1.0"),
            ("trace-context.v1", "1.0"),
        ),
    ),
    AgentRegistration(
        "reference.enterprise-b",
        "platform",
        SHAS["platform"],
        ("agent.execute", "tool.invoke"),
        (
            ("governed-execution.v1", "1.0"),
            ("event-envelope.v1", "1.0"),
            ("trace-context.v1", "1.0"),
        ),
    ),
)


def valid_snapshot(**overrides):
    services = overrides.pop("services", SERVICES)
    agents = overrides.pop("agents", AGENTS)
    contracts = overrides.pop("contracts", CONTRACTS)
    pairs = {
        (service.service_id, contract_id)
        for service in services
        for contract_id in service.contract_ids
    } | {
        (agent.agent_id, contract_id)
        for agent in agents
        for contract_id, _ in agent.required_contracts
    }
    rules = overrides.pop(
        "compatibility_rules",
        tuple(
            CompatibilityRule(consumer, contract_id, ("1.0",))
            for consumer, contract_id in sorted(pairs)
        ),
    )
    return EcosystemRegistrySnapshot(
        repository_revisions=overrides.pop("repository_revisions", SHAS),
        services=services,
        agents=agents,
        contracts=contracts,
        compatibility_rules=rules,
        required_service_ids=frozenset(s.service_id for s in SERVICES),
        required_agent_ids=frozenset(a.agent_id for a in AGENTS),
        **overrides,
    )


def test_canonical_registry_accepts_exact_revisions_and_compatible_contracts():
    valid_snapshot().validate()


def test_registry_rejects_missing_service_and_stale_reviewed_revision():
    with pytest.raises(ValueError, match="missing required services"):
        valid_snapshot(services=SERVICES[1:]).validate()
    with pytest.raises(ValueError, match="full immutable commit SHA"):
        ServiceRegistration(
            SERVICES[0].service_id,
            "platform",
            "main",
            "1.1",
            SERVICES[0].contract_ids,
            SERVICES[0].capabilities,
            SERVICES[0].authority_mode,
        )
    stale = (
        ServiceRegistration(
            SERVICES[0].service_id,
            "platform",
            "f" * 40,
            "1.1",
            SERVICES[0].contract_ids,
            SERVICES[0].capabilities,
            SERVICES[0].authority_mode,
        ),
        *SERVICES[1:],
    )
    with pytest.raises(ValueError, match="stale reviewed revision"):
        valid_snapshot(services=stale).validate()


def test_registry_rejects_missing_contracts_and_incompatible_versions():
    with pytest.raises(ValueError, match="missing contract registrations"):
        valid_snapshot(contracts=CONTRACTS[1:]).validate()
    incompatible = tuple(
        CompatibilityRule(rule.consumer_id, rule.contract_id, ("99.0",))
        if rule.consumer_id == "platform-sdk.client" and rule.contract_id == "trace-context.v1"
        else rule
        for rule in valid_snapshot().compatibility_rules
    )
    with pytest.raises(ValueError, match="incompatible"):
        valid_snapshot(compatibility_rules=incompatible).validate()


def test_registry_rejects_authority_drift_and_duplicate_ids():
    drift = (
        SERVICES[0],
        ServiceRegistration(
            "agent-os.runtime",
            "os",
            SHAS["os"],
            "1.1",
            ("event-envelope.v1", "trace-context.v1"),
            ("event.publish",),
            AuthorityMode.SOLE_CONSEQUENTIAL_EXECUTION,
        ),
        *SERVICES[2:],
    )
    with pytest.raises(ValueError, match="sole consequential execution authority"):
        valid_snapshot(services=drift).validate()
    with pytest.raises(ValueError, match="duplicate service"):
        valid_snapshot(services=(*SERVICES, SERVICES[0])).validate()


def test_registry_requires_complete_fail_closed_compatibility_coverage():
    snapshot = valid_snapshot()
    with pytest.raises(ValueError, match="missing compatibility rules"):
        valid_snapshot(compatibility_rules=snapshot.compatibility_rules[:-1]).validate()
