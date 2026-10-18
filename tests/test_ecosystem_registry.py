from dataclasses import replace

import pytest

from tinlance_agent_platform_registry.ecosystem import (
    AgentRegistration,
    AuthorityMode,
    CompatibilityRule,
    ContractRegistration,
    EcosystemRegistrySnapshot,
    IdentityStatus,
    LifecycleMetadata,
    LifecycleState,
    PublisherIdentity,
    RepositoryMetadata,
    ServiceRegistration,
    SupplyChainReferences,
    SupplyChainStatus,
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
    ContractRegistration(
        "registry-manifest.v1",
        "1.0",
        "tsic",
        lifecycle=LifecycleMetadata(
            LifecycleState.DEPRECATED,
            "2026-10-18T06:50:45Z",
            reason="superseded by registry-manifest.v2",
            replacement_id="registry-manifest.v2",
        ),
    ),
    ContractRegistration(
        "registry-manifest.v2",
        "2.0",
        "tsic",
        lifecycle=LifecycleMetadata(LifecycleState.ACTIVE, "2026-10-18T06:50:45Z"),
    ),
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
        ("transformation.v1", "replication.v1", "trace-context.v1", "registry-manifest.v2"),
        ("artifact.validate", "registry.validate"),
        AuthorityMode.AUTHORITY_FREE,
    ),
    ServiceRegistration(
        "tsic.conformance",
        "tsic",
        SHAS["tsic"],
        "1.1",
        ("event-envelope.v1", "trace-context.v1", "registry-manifest.v2"),
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
    schema_version = overrides.pop("schema_version", "registry-manifest/v1")
    services = overrides.pop("services", SERVICES)
    agents = overrides.pop("agents", AGENTS)
    contracts = overrides.pop("contracts", CONTRACTS)
    if schema_version == "registry-manifest/v2":
        active_lifecycle = LifecycleMetadata(LifecycleState.ACTIVE, "2026-10-18T00:00:00Z")
        services = tuple(
            replace(item, lifecycle=item.lifecycle or active_lifecycle)
            for item in services
        )
        agents = tuple(
            replace(item, lifecycle=item.lifecycle or active_lifecycle)
            for item in agents
        )
        contracts = tuple(
            replace(item, lifecycle=item.lifecycle or active_lifecycle)
            for item in contracts
        )
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
        schema_version=schema_version,
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


def test_registry_rejects_compatibility_that_does_not_fail_closed_and_agent_authority():
    with pytest.raises(ValueError, match="must reject unknown"):
        CompatibilityRule(
            "agent-os.runtime",
            "trace-context.v1",
            ("1.0",),
            reject_unknown=True,
            reject_stale=False,
            reject_missing=True,
        )
    with pytest.raises(ValueError, match="agents cannot be registered"):
        AgentRegistration(
            "malicious.agent",
            "platform",
            SHAS["platform"],
            ("agent.execute",),
            (("governed-execution.v1", "1.0"),),
            AuthorityMode.SOLE_CONSEQUENTIAL_EXECUTION,
        )


def v2_repository_metadata():
    result = {}
    repository_names = {
        "developer": "tinlance-agent-developer",
        "os": "tinlance-agent-os",
        "platform": "tinlance-agent-platform",
        "platform_sdk": "tinlance-agent-platform-sdk",
        "tsic": "tinlance-system-integration",
    }
    for repository_id, sha in SHAS.items():
        result[repository_id] = RepositoryMetadata(
            publisher=PublisherIdentity(
                "LloydCoder",
                "https://github.com/LloydCoder",
                IdentityStatus.UNVERIFIED,
            ),
            lifecycle=LifecycleMetadata(
                LifecycleState.ACTIVE,
                "2026-10-18T00:00:00Z",
            ),
            supply_chain=SupplyChainReferences(
                reviewed_sha=sha,
                provenance_uri=f"https://github.com/LloydCoder/{repository_names[repository_id]}/commit/{sha}",
                sbom_uri=f"https://github.com/LloydCoder/{repository_names[repository_id]}/attestations",
                signature_uri=f"https://github.com/LloydCoder/{repository_names[repository_id]}/attestations",
                verification_status=SupplyChainStatus.PENDING,
            ),
        )
    return result


def test_v2_registry_requires_exact_publisher_lifecycle_and_supply_chain_metadata():
    valid_snapshot(
        schema_version="registry-manifest/v2",
        repository_metadata=v2_repository_metadata(),
    ).validate()

    with pytest.raises(ValueError, match="requires publisher, lifecycle and supply-chain metadata"):
        valid_snapshot(schema_version="registry-manifest/v2").validate()


def test_v2_registry_rejects_supply_chain_revision_drift_and_revoked_publisher():
    metadata = v2_repository_metadata()
    platform = metadata["platform"]
    metadata["platform"] = RepositoryMetadata(
        platform.publisher,
        platform.lifecycle,
        SupplyChainReferences(
            reviewed_sha="f" * 40,
            provenance_uri=platform.supply_chain.provenance_uri,
            sbom_uri=platform.supply_chain.sbom_uri,
            signature_uri=platform.supply_chain.signature_uri,
            verification_status=SupplyChainStatus.PENDING,
        ),
    )
    with pytest.raises(ValueError, match="supply-chain revision differs"):
        valid_snapshot(schema_version="registry-manifest/v2", repository_metadata=metadata).validate()

    metadata = v2_repository_metadata()
    platform = metadata["platform"]
    metadata["platform"] = RepositoryMetadata(
        PublisherIdentity(
            platform.publisher.publisher_id,
            platform.publisher.identity_uri,
            IdentityStatus.REVOKED,
        ),
        platform.lifecycle,
        platform.supply_chain,
    )
    with pytest.raises(ValueError, match="revoked publisher identity"):
        valid_snapshot(schema_version="registry-manifest/v2", repository_metadata=metadata).validate()


def test_lifecycle_quarantine_requires_reason_and_cannot_remain_enabled():
    with pytest.raises(ValueError, match="require a reason"):
        LifecycleMetadata(LifecycleState.QUARANTINED, "2026-10-18T00:00:00Z")

    quarantined = ServiceRegistration(
        SERVICES[0].service_id,
        SERVICES[0].owner_repository_id,
        SERVICES[0].reviewed_sha,
        SERVICES[0].api_version,
        SERVICES[0].contract_ids,
        SERVICES[0].capabilities,
        SERVICES[0].authority_mode,
        True,
        LifecycleMetadata(
            LifecycleState.QUARANTINED,
            "2026-10-18T00:00:00Z",
            reason="security review pending",
        ),
    )
    with pytest.raises(ValueError, match="non-active lifecycle state must fail closed"):
        valid_snapshot(services=(quarantined, *SERVICES[1:])).validate()


def test_deprecated_contract_requires_replacement_and_non_https_supply_chain_refs_are_rejected():
    with pytest.raises(ValueError, match="require a replacement ID"):
        LifecycleMetadata(
            LifecycleState.DEPRECATED,
            "2026-10-18T00:00:00Z",
            reason="superseded",
        )
    with pytest.raises(ValueError, match="SBOM reference must be credential-free HTTPS"):
        SupplyChainReferences(
            reviewed_sha=SHAS["platform"],
            provenance_uri="https://github.com/LloydCoder/tinlance-agent-platform/commit/" + SHAS["platform"],
            sbom_uri="http://example.test/sbom.json",
            signature_uri="https://github.com/LloydCoder/tinlance-agent-platform/attestations",
            verification_status=SupplyChainStatus.PENDING,
        )
