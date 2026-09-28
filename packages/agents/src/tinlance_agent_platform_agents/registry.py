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
