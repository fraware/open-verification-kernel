from __future__ import annotations

from ovk.compilers.authorization.material_loader import materials_from_pair
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.python_ast_index import (
    parse_head_python_materials,
)
from ovk.compilers.authorization.resource_return_contracts import (
    build_contract_summary_index,
    compose_function_contracts,
    contract_summary_index_matches_materials,
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



def test_contract_summary_index_reuses_unchanged_files() -> None:
    source_a = """
class AgentRepository:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await load_agent(agent_id)
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent
""".strip()
    source_b = """
class AgentService:
    def __init__(self):
        self._repo = AgentRepository()

    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        return await self._repo.get(agent_id, workspace_id=workspace_id)
""".strip()
    source_c = "VALUE = 1"

    base = AuthMaterials(
        head_files={
            "repository.py": source_a,
            "service.py": source_b,
            "unrelated.py": source_c,
        }
    )
    base_parsed = parse_head_python_materials(base)
    base_summaries = build_contract_summary_index(
        base,
        parsed_trees=base_parsed.trees,
        source_digests=base_parsed.source_digests,
    )

    head = AuthMaterials(
        base_files=dict(base.head_files),
        head_files={
            "repository.py": source_a,
            "service.py": source_b,
            "unrelated.py": "VALUE = 2",
        },
    )
    head_parsed = parse_head_python_materials(
        head,
        reuse_from=base_parsed,
    )
    head_summaries = build_contract_summary_index(
        head,
        parsed_trees=head_parsed.trees,
        source_digests=head_parsed.source_digests,
        reuse_from=base_summaries,
    )

    assert base_summaries.fresh_summary_count == 3
    assert base_summaries.reused_summary_count == 0
    assert head_summaries.fresh_summary_count == 1
    assert head_summaries.reused_summary_count == 2
    assert contract_summary_index_matches_materials(head_summaries, head)
    assert (
        head_summaries.summaries["repository.py"]
        is base_summaries.summaries["repository.py"]
    )
    assert (
        head_summaries.summaries["service.py"]
        is base_summaries.summaries["service.py"]
    )


def test_reused_wrapper_summary_recomposes_against_changed_callee() -> None:
    secure_repository = """
class AgentRepository:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await load_agent(agent_id)
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent
""".strip()
    changed_repository = secure_repository.replace(
        "agent.workspace_id != workspace_id",
        "agent.tenant_id != workspace_id",
    )
    service = """
class AgentService:
    def __init__(self):
        self._repo = AgentRepository()

    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        return await self._repo.get(agent_id, workspace_id=workspace_id)
""".strip()

    base = AuthMaterials(
        head_files={
            "repository.py": secure_repository,
            "service.py": service,
        }
    )
    base_parsed = parse_head_python_materials(base)
    base_summaries = build_contract_summary_index(
        base,
        parsed_trees=base_parsed.trees,
        source_digests=base_parsed.source_digests,
    )
    base_contracts = {
        item.qualified_name: item
        for item in compose_function_contracts(base_summaries)
    }

    head = AuthMaterials(
        base_files=dict(base.head_files),
        head_files={
            "repository.py": changed_repository,
            "service.py": service,
        },
    )
    head_parsed = parse_head_python_materials(
        head,
        reuse_from=base_parsed,
    )
    head_summaries = build_contract_summary_index(
        head,
        parsed_trees=head_parsed.trees,
        source_digests=head_parsed.source_digests,
        reuse_from=base_summaries,
    )
    head_contracts = {
        item.qualified_name: item
        for item in compose_function_contracts(head_summaries)
    }

    assert head_summaries.fresh_summary_count == 1
    assert head_summaries.reused_summary_count == 1
    assert (
        head_summaries.summaries["service.py"]
        is base_summaries.summaries["service.py"]
    )

    assert (
        base_contracts["AgentRepository.get"].contract_id
        != head_contracts["AgentRepository.get"].contract_id
    )
    assert (
        base_contracts["AgentService.get"].contract_id
        != head_contracts["AgentService.get"].contract_id
    )
    assert head_contracts["AgentService.get"].depends_on == ["AgentRepository.get"]

    post = head_contracts["AgentService.get"].postconditions[0]
    assert post.left.name == "tenant_id"
    assert post.right is not None
    assert post.right.name == "workspace_id"


def test_summary_composition_matches_inference_api() -> None:
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
    materials = _materials(source)
    parsed = parse_head_python_materials(materials)
    summaries = build_contract_summary_index(
        materials,
        parsed_trees=parsed.trees,
        source_digests=parsed.source_digests,
    )

    from_summary = compose_function_contracts(summaries)
    from_api = infer_function_contracts(
        materials,
        summary_index=summaries,
    )

    assert [
        item.model_dump(mode="json")
        for item in from_summary
    ] == [
        item.model_dump(mode="json")
        for item in from_api
    ]


def test_infers_fail_closed_free_function_parameter_equality() -> None:
    source = """
from typing import Optional

def ensure_resource_in_workspace(
    resource_workspace_id: str | None,
    workspace_id: str,
    *,
    label: str = "Resource",
) -> None:
    """Reject cross-workspace access."""
    if resource_workspace_id != workspace_id:
        raise RuntimeError(label)
""".strip()

    contracts = infer_function_contracts(_materials(source))
    by_name = {contract.qualified_name: contract for contract in contracts}

    contract = by_name["ensure_resource_in_workspace"]
    assert contract.origin.path == "services/agent_service.py"
    assert contract.positional_parameters == [
        "resource_workspace_id",
        "workspace_id",
    ]
    assert contract.preconditions == []
    assert len(contract.postconditions) == 1
    post = contract.postconditions[0]
    assert post.relation == "eq"
    assert post.left.kind == "parameter"
    assert post.left.name == "resource_workspace_id"
    assert post.right is not None
    assert post.right.kind == "parameter"
    assert post.right.name == "workspace_id"


def test_fail_closed_equality_accepts_optional_string_annotation() -> None:
    source = """
from typing import Optional

def ensure_resource_in_workspace(
    resource_workspace_id: Optional[str],
    workspace_id: str,
) -> None:
    if resource_workspace_id != workspace_id:
        raise RuntimeError()
""".strip()

    contracts = infer_function_contracts(_materials(source))
    assert {
        contract.qualified_name for contract in contracts
    } == {"ensure_resource_in_workspace"}


def test_does_not_infer_parameter_equality_without_terminating_raise() -> None:
    source = """
def ensure_resource_in_workspace(
    resource_workspace_id: str | None,
    workspace_id: str,
) -> None:
    if resource_workspace_id != workspace_id:
        audit(resource_workspace_id, workspace_id)
""".strip()

    assert infer_function_contracts(_materials(source)) == []


def test_does_not_infer_parameter_equality_with_extra_executable_behavior() -> None:
    source = """
def ensure_resource_in_workspace(
    resource_workspace_id: str | None,
    workspace_id: str,
) -> None:
    audit(workspace_id)
    if resource_workspace_id != workspace_id:
        raise RuntimeError()
""".strip()

    assert infer_function_contracts(_materials(source)) == []


def test_does_not_infer_parameter_equality_for_arbitrary_object_types() -> None:
    source = """
def ensure_same_scope(left: Scope, right: Scope) -> None:
    if left != right:
        raise RuntimeError()
""".strip()

    assert infer_function_contracts(_materials(source)) == []

