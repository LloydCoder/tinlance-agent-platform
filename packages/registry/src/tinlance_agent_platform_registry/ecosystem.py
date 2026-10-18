"""Fail-closed canonical service/agent/contract registry validation.

This is separate from the tenant-scoped resource inventory: it validates the
system's reviewed component registrations and contract compatibility before
those registrations are used by runtime components.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


class AuthorityMode(StrEnum):
    SOLE_CONSEQUENTIAL_EXECUTION = "sole_consequential_execution"
    AUTHORITY_FREE = "authority_free"
    CONFORMANCE_ONLY = "conformance_only"
    DELEGATED_ONLY = "delegated_only"


@dataclass(frozen=True, slots=True)
class ContractRegistration:
    contract_id: str
    version: str
    owner_repository_id: str
    immutable: bool = True

    def __post_init__(self) -> None:
        if any(
            not value.strip()
            for value in (self.contract_id, self.version, self.owner_repository_id)
        ):
            raise ValueError("contract ID, version and owner are required")


@dataclass(frozen=True, slots=True)
class ServiceRegistration:
    service_id: str
    owner_repository_id: str
    reviewed_sha: str
    api_version: str
    contract_ids: tuple[str, ...]
    capabilities: tuple[str, ...]
    authority_mode: AuthorityMode
    enabled: bool = True

    def __post_init__(self) -> None:
        if any(
            not value.strip()
            for value in (
                self.service_id,
                self.owner_repository_id,
                self.api_version,
                self.reviewed_sha,
            )
        ):
            raise ValueError("service registration identity and version fields are required")
        if not _FULL_SHA.fullmatch(self.reviewed_sha):
            raise ValueError("service reviewed revision must be a full immutable commit SHA")
        if not self.contract_ids or len(set(self.contract_ids)) != len(self.contract_ids):
            raise ValueError("service contracts must be non-empty and unique")
        if not self.capabilities or len(set(self.capabilities)) != len(self.capabilities):
            raise ValueError("service capabilities must be non-empty and unique")


@dataclass(frozen=True, slots=True)
class AgentRegistration:
    agent_id: str
    owner_repository_id: str
    reviewed_sha: str
    capabilities: tuple[str, ...]
    required_contracts: tuple[tuple[str, str], ...]
    authority_mode: AuthorityMode = AuthorityMode.DELEGATED_ONLY

    def __post_init__(self) -> None:
        if any(
            not value.strip()
            for value in (self.agent_id, self.owner_repository_id, self.reviewed_sha)
        ):
            raise ValueError("agent registration identity and revision are required")
        if not _FULL_SHA.fullmatch(self.reviewed_sha):
            raise ValueError("agent reviewed revision must be a full immutable commit SHA")
        if not self.capabilities or len(set(self.capabilities)) != len(self.capabilities):
            raise ValueError("agent capabilities must be non-empty and unique")
        if not self.required_contracts or len(set(self.required_contracts)) != len(
            self.required_contracts
        ):
            raise ValueError("agent required contracts must be non-empty and unique")
        if self.authority_mode not in {AuthorityMode.DELEGATED_ONLY, AuthorityMode.AUTHORITY_FREE}:
            raise ValueError("agents cannot be registered as execution authorities")


@dataclass(frozen=True, slots=True)
class CompatibilityRule:
    consumer_id: str
    contract_id: str
    supported_versions: tuple[str, ...]
    reject_unknown: bool = True
    reject_stale: bool = True
    reject_missing: bool = True

    def __post_init__(self) -> None:
        if not self.consumer_id.strip() or not self.contract_id.strip():
            raise ValueError("compatibility consumer and contract are required")
        if not self.supported_versions or len(set(self.supported_versions)) != len(
            self.supported_versions
        ):
            raise ValueError("supported contract versions must be non-empty and unique")
        if not (self.reject_unknown and self.reject_stale and self.reject_missing):
            raise ValueError(
                "registry compatibility must reject unknown, stale and missing registrations"
            )


@dataclass(frozen=True, slots=True)
class EcosystemRegistrySnapshot:
    repository_revisions: Mapping[str, str]
    services: tuple[ServiceRegistration, ...]
    agents: tuple[AgentRegistration, ...]
    contracts: tuple[ContractRegistration, ...]
    compatibility_rules: tuple[CompatibilityRule, ...]
    required_service_ids: frozenset[str]
    required_agent_ids: frozenset[str]

    def validate(self) -> None:
        """Raise ValueError on any missing, stale, ambiguous or incompatible registration."""
        _assert_unique((item.service_id for item in self.services), "service")
        _assert_unique((item.agent_id for item in self.agents), "agent")
        _assert_unique((item.contract_id for item in self.contracts), "contract")
        _assert_unique(self.repository_revisions.keys(), "repository")
        _assert_unique(
            ((rule.consumer_id, rule.contract_id) for rule in self.compatibility_rules),
            "compatibility rule",
        )

        services = {item.service_id: item for item in self.services}
        agents = {item.agent_id: item for item in self.agents}
        contracts = {item.contract_id: item for item in self.contracts}
        if not self.required_service_ids.issubset(services):
            raise ValueError("registry is missing required services")
        if not self.required_agent_ids.issubset(agents):
            raise ValueError("registry is missing required agents")
        if not self.contracts:
            raise ValueError("registry has no contracts")

        for repository_id, sha in self.repository_revisions.items():
            if not _FULL_SHA.fullmatch(sha):
                raise ValueError(f"{repository_id}: repository revision is not a full SHA")

        platform_services = [
            service
            for service in self.services
            if service.authority_mode is AuthorityMode.SOLE_CONSEQUENTIAL_EXECUTION
        ]
        if len(platform_services) != 1 or platform_services[0].owner_repository_id != "platform":
            raise ValueError("Platform must be the sole consequential execution authority")

        for service in self.services:
            self._validate_owner_revision(
                service.owner_repository_id, service.reviewed_sha, service.service_id
            )
            if not service.enabled:
                raise ValueError(f"{service.service_id}: required service registration is disabled")
            if service.owner_repository_id != "platform" and service.authority_mode not in {
                AuthorityMode.AUTHORITY_FREE, AuthorityMode.CONFORMANCE_ONLY
            }:
                raise ValueError(
                    f"{service.service_id}: non-Platform service cannot grant authority"
                )
            self._validate_contract_set(service.service_id, service.contract_ids, contracts)

        for agent in self.agents:
            self._validate_owner_revision(
                agent.owner_repository_id, agent.reviewed_sha, agent.agent_id
            )
            if agent.authority_mode not in {
                AuthorityMode.DELEGATED_ONLY,
                AuthorityMode.AUTHORITY_FREE,
            }:
                raise ValueError(f"{agent.agent_id}: agents cannot grant execution authority")
            required_ids = tuple(contract_id for contract_id, _ in agent.required_contracts)
            self._validate_contract_set(agent.agent_id, required_ids, contracts)
            for contract_id, version in agent.required_contracts:
                if contracts[contract_id].version != version:
                    raise ValueError(
                        f"{agent.agent_id}: incompatible {contract_id} version {version}"
                    )

        rule_map = {(rule.consumer_id, rule.contract_id): rule for rule in self.compatibility_rules}
        required_pairs = {
            (service.service_id, contract_id)
            for service in self.services
            for contract_id in service.contract_ids
        } | {
            (agent.agent_id, contract_id)
            for agent in self.agents
            for contract_id, _ in agent.required_contracts
        }
        if not required_pairs.issubset(rule_map):
            missing = sorted(required_pairs - set(rule_map))
            raise ValueError(f"registry is missing compatibility rules: {missing}")
        for (consumer_id, contract_id), rule in rule_map.items():
            contract = contracts.get(contract_id)
            if contract is None:
                raise ValueError(f"{consumer_id}: unknown contract {contract_id}")
            if contract.version not in rule.supported_versions:
                raise ValueError(
                    f"{consumer_id}: incompatible {contract_id} version {contract.version}"
                )
            if not (rule.reject_unknown and rule.reject_stale and rule.reject_missing):
                raise ValueError(f"{consumer_id}: compatibility must fail closed")

    def _validate_owner_revision(self, owner: str, sha: str, registration_id: str) -> None:
        reviewed = self.repository_revisions.get(owner)
        if reviewed is None:
            raise ValueError(f"{registration_id}: owner repository is not registered")
        if sha != reviewed:
            raise ValueError(f"{registration_id}: stale reviewed revision for {owner}")

    @staticmethod
    def _validate_contract_set(
        consumer_id: str,
        contract_ids: tuple[str, ...],
        contracts: Mapping[str, ContractRegistration],
    ) -> None:
        missing = set(contract_ids) - set(contracts)
        if missing:
            raise ValueError(f"{consumer_id}: missing contract registrations {sorted(missing)}")
        for contract_id in contract_ids:
            if not contracts[contract_id].immutable:
                raise ValueError(f"{consumer_id}: contract {contract_id} is not immutable")


def _assert_unique(values, label: str) -> None:
    values = list(values)
    if len(values) != len(set(values)):
        raise ValueError(f"duplicate {label} registration")
