from __future__ import annotations

import json
from pathlib import Path

from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.compilers.authorization.semantic_summary_cache import (
    PersistentPythonSemanticSummaryCache,
    load_persistent_semantic_summaries,
)


def _route_source() -> str:
    return """
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


def _service_source(attribute: str = "workspace_id") -> str:
    return f"""
class AgentService:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await load_agent(agent_id)
        if workspace_id is not None and agent.{attribute} != workspace_id:
            return None
        return agent
""".strip()


def _materials(*, service_attribute: str = "workspace_id") -> AuthMaterials:
    files = {
        "routes.py": _route_source(),
        "service.py": _service_source(service_attribute),
        "unrelated.py": "VALUE = 1\n",
    }
    return AuthMaterials(
        base_files=dict(files),
        head_files=files,
        repo="example/app",
        base_revision="base",
        head_revision=f"head-{service_attribute}",
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


def _compile(materials: AuthMaterials, loaded):
    return FastApiDependencyEffectExtractor().compile(
        materials,
        _profile(),
        parsed_index=loaded.parsed_index,
        contract_summary_index=loaded.contract_summary_index,
        route_summary_index=loaded.route_summary_index,
    )


def test_fresh_worker_reuses_persistent_summaries_without_ast_parse(tmp_path: Path) -> None:
    materials = _materials()
    first_cache = PersistentPythonSemanticSummaryCache(tmp_path / "summaries")

    seeded = load_persistent_semantic_summaries(
        materials,
        cache=first_cache,
    )
    first_ir = _compile(materials, seeded)

    assert seeded.stats.misses == 3
    assert seeded.stats.hits == 0
    assert seeded.stats.parse_count == 3
    assert seeded.contract_summary_index.fresh_summary_count == 3
    assert seeded.route_summary_index.fresh_summary_count == 3
    assert first_ir.coverage.status == "complete"

    # Simulate a fresh worker: new cache object, no in-memory AST/index reuse.
    second_cache = PersistentPythonSemanticSummaryCache(tmp_path / "summaries")
    loaded = load_persistent_semantic_summaries(
        materials,
        cache=second_cache,
    )
    second_ir = _compile(materials, loaded)

    assert loaded.stats.hits == 3
    assert loaded.stats.misses == 0
    assert loaded.stats.parse_count == 0
    assert loaded.parsed_index.trees == {}
    assert loaded.contract_summary_index.fresh_summary_count == 0
    assert loaded.contract_summary_index.reused_summary_count == 3
    assert loaded.route_summary_index.fresh_summary_count == 0
    assert loaded.route_summary_index.reused_summary_count == 3
    assert second_ir.canonical_payload() == first_ir.canonical_payload()


def test_fresh_worker_parses_only_changed_file_and_rebinds_semantics(tmp_path: Path) -> None:
    base = _materials()
    cache_root = tmp_path / "summaries"

    seeded = load_persistent_semantic_summaries(
        base,
        cache=PersistentPythonSemanticSummaryCache(cache_root),
    )
    base_ir = _compile(base, seeded)
    assert base_ir.coverage.status == "complete"

    head = _materials(service_attribute="tenant_id")
    loaded = load_persistent_semantic_summaries(
        head,
        cache=PersistentPythonSemanticSummaryCache(cache_root),
    )
    head_ir = _compile(head, loaded)

    assert loaded.stats.hits == 2
    assert loaded.stats.misses == 1
    assert loaded.stats.parse_count == 1
    assert loaded.contract_summary_index.fresh_summary_count == 1
    assert loaded.contract_summary_index.reused_summary_count == 2
    assert loaded.route_summary_index.fresh_summary_count == 1
    assert loaded.route_summary_index.reused_summary_count == 2

    assert head_ir.coverage.status == "partial"
    assert any(
        "required_scope_postcondition_missing:AgentService.get:workspace_id"
        in item
        for item in head_ir.coverage.unsupported_constructs
    )


def test_corrupt_payload_digest_is_cache_miss_and_rebuilt(tmp_path: Path) -> None:
    materials = _materials()
    root = tmp_path / "summaries"
    cache = PersistentPythonSemanticSummaryCache(root)
    seeded = load_persistent_semantic_summaries(materials, cache=cache)
    assert seeded.stats.writes == 3

    records = sorted(root.glob("*.json"))
    assert len(records) == 3
    record = json.loads(records[0].read_text(encoding="utf-8"))
    record["payload"]["source_digest"] = "tampered"
    records[0].write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    reloaded = load_persistent_semantic_summaries(
        materials,
        cache=PersistentPythonSemanticSummaryCache(root),
    )

    assert reloaded.stats.hits == 2
    assert reloaded.stats.misses == 1
    assert reloaded.stats.parse_count == 1
    assert reloaded.stats.writes == 1
    assert _compile(materials, reloaded).coverage.status == "complete"


def test_cached_syntax_error_reuses_failure_without_reparse(tmp_path: Path) -> None:
    materials = AuthMaterials(
        head_files={
            "good.py": "VALUE = 1\n",
            "bad.py": "def broken(:\n    pass\n",
        },
        repo="example/app",
        head_revision="bad-head",
    )
    root = tmp_path / "summaries"

    first = load_persistent_semantic_summaries(
        materials,
        cache=PersistentPythonSemanticSummaryCache(root),
    )
    second = load_persistent_semantic_summaries(
        materials,
        cache=PersistentPythonSemanticSummaryCache(root),
    )

    assert first.stats.parse_count == 2
    assert second.stats.parse_count == 0
    assert second.stats.hits == 2
    assert second.parsed_index.syntax_errors == {
        "bad.py": "invalid syntax",
    }
