from __future__ import annotations

import ast

import pytest

from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.compilers.authorization.python_ast_index import (
    parse_head_python_materials,
    parsed_index_matches_materials,
)
from ovk.compilers.authorization.resource_return_contracts import (
    infer_function_contracts,
)


def _materials() -> AuthMaterials:
    route = """
from fastapi import Depends, FastAPI
app = FastAPI()

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str,
    agent_id: str,
    user = Depends(require_workspace_member),
):
    svc = AgentService()
    return await svc.get(agent_id, workspace_id=workspace_id)
""".strip()
    service = """
class AgentService:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await load_agent(agent_id)
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent
""".strip()
    unrelated = """
def healthcheck():
    return {"ok": True}
""".strip()
    return AuthMaterials(
        base_files={
            "routes.py": route,
            "service.py": service,
            "health.py": unrelated,
        },
        head_files={
            "routes.py": route,
            "service.py": service,
            "health.py": unrelated,
        },
        repo="example/app",
        base_revision="base",
        head_revision="head",
    )


def _profile() -> FastApiDependencyEffectProfile:
    return FastApiDependencyEffectProfile(
        sink_effects={"svc.get": "workspace.agent.read"},
        sink_identity_args={"svc.get": 0},
        sink_contracts={"svc.get": "AgentService.get"},
        sink_contract_scope_attributes={"svc.get": "workspace_id"},
        dependency_guard_resources={"require_workspace_member": "workspace_id"},
        dependency_guard_effects={
            "require_workspace_member": ("workspace.agent.read",),
        },
        principal_parameter="user",
    )


def test_shared_index_parses_each_head_file_once(monkeypatch) -> None:
    materials = _materials()
    original = ast.parse
    calls: list[str] = []

    def counted(source, filename="<unknown>", mode="exec", **kwargs):
        calls.append(str(filename))
        return original(source, filename=filename, mode=mode, **kwargs)

    monkeypatch.setattr(
        "ovk.compilers.authorization.python_ast_index.ast.parse",
        counted,
    )

    ir = FastApiDependencyEffectExtractor().compile(materials, _profile())

    assert ir.coverage.status == "complete"
    assert sorted(calls) == sorted(materials.head_files)
    assert len(calls) == len(materials.head_files)


def test_parse_index_reports_syntax_errors_without_tree() -> None:
    materials = AuthMaterials(
        head_files={
            "good.py": "x = 1",
            "bad.py": "def broken(:\n    pass",
        }
    )

    parsed = parse_head_python_materials(materials)

    assert parsed.parse_count == 2
    assert set(parsed.trees) == {"good.py"}
    assert set(parsed.syntax_errors) == {"bad.py"}


def test_standalone_contract_inference_remains_backward_compatible() -> None:
    materials = _materials()

    contracts = infer_function_contracts(materials)

    assert any(
        contract.qualified_name == "AgentService.get"
        for contract in contracts
    )



def test_head_index_reuses_unchanged_files_and_parses_only_change() -> None:
    base = _materials()
    base_index = parse_head_python_materials(base)

    head_files = dict(base.head_files)
    head_files["health.py"] = """
def healthcheck():
    return {"ok": True, "revision": 2}
""".strip()
    head = AuthMaterials(
        base_files=dict(base.head_files),
        head_files=head_files,
        repo=base.repo,
        base_revision="base",
        head_revision="head-2",
    )

    head_index = parse_head_python_materials(
        head,
        reuse_from=base_index,
    )

    assert head_index.parse_count == 1
    assert head_index.reused_count == len(head.head_files) - 1
    assert parsed_index_matches_materials(head_index, head)
    assert head_index.trees["routes.py"] is base_index.trees["routes.py"]
    assert head_index.trees["service.py"] is base_index.trees["service.py"]
    assert head_index.trees["health.py"] is not base_index.trees["health.py"]


def test_compiler_accepts_matching_reused_index() -> None:
    materials = _materials()
    parsed = parse_head_python_materials(materials)

    ir = FastApiDependencyEffectExtractor().compile(
        materials,
        _profile(),
        parsed_index=parsed,
    )

    assert ir.coverage.status == "complete"
    assert len(ir.protected_effects) == 1


def test_compiler_rejects_stale_parsed_index() -> None:
    materials = _materials()
    parsed = parse_head_python_materials(materials)

    changed_files = dict(materials.head_files)
    changed_files["routes.py"] = changed_files["routes.py"].replace(
        "return await svc.get",
        "agent = await svc.get",
    )
    changed = AuthMaterials(
        base_files=dict(materials.base_files),
        head_files=changed_files,
        repo=materials.repo,
        base_revision=materials.base_revision,
        head_revision="different-head",
    )

    assert not parsed_index_matches_materials(parsed, changed)
    with pytest.raises(ValueError, match="parsed Python index does not match"):
        FastApiDependencyEffectExtractor().compile(
            changed,
            _profile(),
            parsed_index=parsed,
        )


def test_unchanged_syntax_error_is_reused_without_reparse() -> None:
    base = AuthMaterials(
        head_files={
            "good.py": "x = 1",
            "bad.py": "def broken(:\n    pass",
        }
    )
    base_index = parse_head_python_materials(base)

    head = AuthMaterials(
        base_files=dict(base.head_files),
        head_files={
            "good.py": "x = 2",
            "bad.py": base.head_files["bad.py"],
        },
    )
    head_index = parse_head_python_materials(head, reuse_from=base_index)

    assert head_index.parse_count == 1
    assert head_index.reused_count == 1
    assert "bad.py" in head_index.syntax_errors
