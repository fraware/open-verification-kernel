from __future__ import annotations

from ovk.compilers.authorization.material_loader import materials_from_pair
from ovk.compilers.authorization.resource_return_contracts import (
    infer_function_contracts,
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



def test_typed_contract_records_pre_and_post_conditions() -> None:
    source = """
class AgentService:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await self._session.get(Agent, agent_id)
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent
""".strip()

    contracts = infer_function_contracts(_materials(source))

    assert len(contracts) == 1
    contract = contracts[0]
    assert contract.qualified_name == "AgentService.get"
    assert contract.positional_parameters == ["agent_id"]
    assert len(contract.preconditions) == 1
    assert contract.preconditions[0].relation == "non_null"
    assert contract.preconditions[0].left.kind == "parameter"
    assert contract.preconditions[0].left.name == "workspace_id"
    assert len(contract.postconditions) == 1
    post = contract.postconditions[0]
    assert post.relation == "eq"
    assert post.left.kind == "return_attribute"
    assert post.left.name == "workspace_id"
    assert post.right is not None
    assert post.right.kind == "parameter"
    assert post.right.name == "workspace_id"


def test_typed_contract_infers_identity_and_scope_postconditions() -> None:
    source = """
class AgentService:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await self._session.get(Agent, agent_id)
        if agent.id != agent_id:
            return None
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent
""".strip()

    contracts = infer_function_contracts(_materials(source))

    assert len(contracts) == 1
    contract = contracts[0]
    pairs = {
        (post.left.name, post.right.name)
        for post in contract.postconditions
        if post.right is not None
    }
    assert pairs == {
        ("id", "agent_id"),
        ("workspace_id", "workspace_id"),
    }
    assert len(contract.preconditions) == 1
    assert contract.preconditions[0].left.name == "workspace_id"


def test_multi_postcondition_contract_does_not_project_to_legacy_scope_contract() -> None:
    source = """
class AgentService:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await self._session.get(Agent, agent_id)
        if agent.id != agent_id:
            return None
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent
""".strip()

    assert infer_resource_return_contracts(_materials(source)) == []



def test_composes_contract_through_self_member_repository() -> None:
    source = """
class AgentRepository:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await load_agent(agent_id)
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent

class AgentService:
    def __init__(self):
        self._repo = AgentRepository()

    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        return await self._repo.get(agent_id, workspace_id=workspace_id)
""".strip()

    contracts = infer_function_contracts(_materials(source))
    by_name = {contract.qualified_name: contract for contract in contracts}

    assert set(by_name) == {"AgentRepository.get", "AgentService.get"}
    service = by_name["AgentService.get"]
    assert service.positional_parameters == ["agent_id"]
    assert len(service.preconditions) == 1
    assert service.preconditions[0].left.name == "workspace_id"
    post = service.postconditions[0]
    assert post.left.name == "workspace_id"
    assert post.right is not None
    assert post.right.name == "workspace_id"


def test_composes_contract_to_fixed_point_across_two_wrappers() -> None:
    source = """
class AgentRepository:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await load_agent(agent_id)
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent

class AgentService:
    def __init__(self):
        self._repo = AgentRepository()

    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        result = await self._repo.get(agent_id, workspace_id=workspace_id)
        return result

class AgentFacade:
    def __init__(self):
        self._service = AgentService()

    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        return await self._service.get(agent_id, workspace_id=workspace_id)
""".strip()

    contracts = infer_function_contracts(_materials(source))
    by_name = {contract.qualified_name: contract for contract in contracts}

    assert set(by_name) == {
        "AgentRepository.get",
        "AgentService.get",
        "AgentFacade.get",
    }
    facade = by_name["AgentFacade.get"]
    assert facade.preconditions[0].left.name == "workspace_id"
    assert facade.postconditions[0].left.name == "workspace_id"
    assert facade.postconditions[0].right is not None
    assert facade.postconditions[0].right.name == "workspace_id"


def test_composed_contract_substitutes_wrapper_parameter_name() -> None:
    source = """
class DocumentRepository:
    async def get(self, document_id: str, *, project_id: str):
        document = await load_document(document_id)
        if document.project_id != project_id:
            return None
        return document

class DocumentService:
    def __init__(self):
        self._repo = DocumentRepository()

    async def get(self, document_id: str, *, parent_project_id: str):
        return await self._repo.get(document_id, project_id=parent_project_id)
""".strip()

    contracts = infer_function_contracts(_materials(source))
    by_name = {contract.qualified_name: contract for contract in contracts}
    service = by_name["DocumentService.get"]

    assert service.preconditions == []
    post = service.postconditions[0]
    assert post.left.name == "project_id"
    assert post.right is not None
    assert post.right.kind == "parameter"
    assert post.right.name == "parent_project_id"


def test_composed_contract_can_discharge_non_null_precondition_with_literal() -> None:
    source = """
class AgentRepository:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await load_agent(agent_id)
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent

class SystemAgentService:
    def __init__(self):
        self._repo = AgentRepository()

    async def get(self, agent_id: str):
        return await self._repo.get(agent_id, workspace_id="system")
""".strip()

    contracts = infer_function_contracts(_materials(source))
    by_name = {contract.qualified_name: contract for contract in contracts}
    service = by_name["SystemAgentService.get"]

    assert service.preconditions == []
    post = service.postconditions[0]
    assert post.right is not None
    assert post.right.kind == "literal"
    assert post.right.value == "system"


def test_wrapper_omitting_required_callee_parameter_does_not_gain_contract() -> None:
    source = """
class DocumentRepository:
    async def get(self, document_id: str, *, project_id: str):
        document = await load_document(document_id)
        if document.project_id != project_id:
            return None
        return document

class DocumentService:
    def __init__(self):
        self._repo = DocumentRepository()

    async def get(self, document_id: str):
        return await self._repo.get(document_id)
""".strip()

    contracts = infer_function_contracts(_materials(source))
    names = {contract.qualified_name for contract in contracts}

    assert "DocumentRepository.get" in names
    assert "DocumentService.get" not in names
