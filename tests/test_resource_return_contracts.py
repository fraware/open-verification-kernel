from __future__ import annotations

from ovk.compilers.authorization.material_loader import materials_from_pair
from ovk.compilers.authorization.resource_return_contracts import (
    infer_resource_return_contracts,
)


def _materials(service_source: str):
    return materials_from_pair(
        path="services/agent_service.py",
        base_source=service_source,
        head_source=service_source,
        repo="example/platform",
        base_revision="base",
        head_revision="head",
    )


def test_infers_rejecting_scope_guard_contract() -> None:
    source = """
class AgentService:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await self._session.get(Agent, agent_id)
        if agent is None:
            return None
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent
""".strip()

    contracts = infer_resource_return_contracts(_materials(source))

    assert len(contracts) == 1
    contract = contracts[0]
    assert contract.qualified_name == "AgentService.get"
    assert contract.return_scope_parameter == "workspace_id"
    assert contract.return_scope_attribute == "workspace_id"
    assert contract.requires_non_null_argument is True
    assert contract.origin.path == "services/agent_service.py"


def test_infers_unconditional_scope_rejection_contract() -> None:
    source = """
class AgentService:
    async def get(self, agent_id: str, workspace_id: str):
        agent = await self._session.get(Agent, agent_id)
        if agent.workspace_id != workspace_id:
            return None
        return agent
""".strip()

    contracts = infer_resource_return_contracts(_materials(source))

    assert len(contracts) == 1
    assert contracts[0].requires_non_null_argument is False


def test_does_not_infer_contract_without_rejecting_mismatch() -> None:
    source = """
class AgentService:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await self._session.get(Agent, agent_id)
        return agent
""".strip()

    assert infer_resource_return_contracts(_materials(source)) == []


def test_does_not_infer_contract_with_alternative_non_none_return() -> None:
    source = """
class AgentService:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await self._session.get(Agent, agent_id)
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return fallback_agent
        return agent
""".strip()

    assert infer_resource_return_contracts(_materials(source)) == []


def test_does_not_infer_contract_across_unsupported_loop_control_flow() -> None:
    source = """
class AgentService:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await self._session.get(Agent, agent_id)
        for item in audit_records:
            audit(item)
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent
""".strip()

    assert infer_resource_return_contracts(_materials(source)) == []
