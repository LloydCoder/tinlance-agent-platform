from uuid import UUID

from tinlance_agent_platform_contracts import AgentDefinition


class AgentRegistry:
    def __init__(self) -> None:
        self._agents: dict[tuple[str, UUID, str], AgentDefinition] = {}

    def register(self, agent: AgentDefinition) -> AgentDefinition:
        key = (agent.tenant_id, agent.agent_id, agent.version)
        existing = self._agents.get(key)
        if existing is not None and existing != agent:
            raise ValueError("agent version is immutable")
        self._agents[key] = agent
        return agent

    def get(self, tenant_id: str, agent_id: UUID, version: str) -> AgentDefinition:
        agent = self._agents.get((tenant_id, agent_id, version))
        if agent is None:
            raise KeyError("agent version is not registered")
        return agent

    def list_for_tenant(self, tenant_id: str) -> tuple[AgentDefinition, ...]:
        if not tenant_id or tenant_id != tenant_id.strip():
            raise ValueError("tenant identifier must be normalized")
        return tuple(
            agent
            for (agent_tenant, _agent_id, _version), agent in self._agents.items()
            if agent_tenant == tenant_id
        )

    def latest_version(self, tenant_id: str, agent_id: UUID) -> str:
        candidates = [
            agent.version
            for (agent_tenant, registered_id, _version), agent in self._agents.items()
            if agent_tenant == tenant_id and registered_id == agent_id
        ]
        if not candidates:
            raise KeyError("agent version is not registered")
        return sorted(candidates)[-1]
