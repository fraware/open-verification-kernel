"""Fresh-worker scaling benchmark for persistent incremental FastAPI assurance."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.persistent_fastapi_state import (
    PersistentFastApiIncrementalStateCache,
    compile_persistent_incremental_fastapi_assurance,
)
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.compilers.authorization.semantic_summary_cache import (
    PersistentPythonSemanticSummaryCache,
)


CONFIG_PATH = Path(
    "benchmarks/formal_pr_bench/persistent_fastapi_incremental_v1/"
    "scaling_workloads.json"
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
    svc = AgentFacade()
    return await svc.get(agent_id, workspace_id=workspace_id)
""".strip()


def _repo_source(attribute: str = "workspace_id") -> str:
    return f"""
class AgentRepository:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await load_agent(agent_id)
        if workspace_id is not None and agent.{attribute} != workspace_id:
            return None
        return agent
""".strip()


def _service_source() -> str:
    return """
class AgentService:
    def __init__(self):
        self._repo = AgentRepository()

    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        return await self._repo.get(agent_id, workspace_id=workspace_id)
""".strip()


def _facade_source() -> str:
    return """
class AgentFacade:
    def __init__(self):
        self._service = AgentService()

    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        return await self._service.get(agent_id, workspace_id=workspace_id)
""".strip()


def _profile() -> FastApiDependencyEffectProfile:
    return FastApiDependencyEffectProfile(
        sink_effects={"svc.get": "workspace.agent.read"},
        sink_identity_args={"svc.get": 0},
        sink_contracts={"svc.get": "AgentFacade.get"},
        sink_contract_scope_attributes={"svc.get": "workspace_id"},
        dependency_guard_resources={"require_workspace_member": "workspace_id"},
        dependency_guard_effects={
            "require_workspace_member": ("workspace.agent.read",),
        },
        principal_parameter="user",
    )


def _files(
    size: int,
    *,
    repo_attribute: str = "workspace_id",
    changed_unrelated: bool = False,
) -> dict[str, str]:
    if size < 4:
        raise ValueError("persistent FastAPI benchmark requires at least four files")

    files = {
        "routes.py": _route_source(),
        "repo.py": _repo_source(repo_attribute),
        "service.py": _service_source(),
        "facade.py": _facade_source(),
    }
    for index in range(4, size):
        value = index
        if changed_unrelated and index == 4:
            value += 100000
        files[f"unrelated/module_{index}.py"] = (
            f"VALUE_{index} = {value}\n"
            f"def helper_{index}():\n"
            f"    return VALUE_{index}\n"
        )
    return files


def _materials(
    files: dict[str, str],
    *,
    revision: str,
    repo: str,
) -> AuthMaterials:
    return AuthMaterials(
        base_files=dict(files),
        head_files=dict(files),
        repo=repo,
        base_revision="base",
        head_revision=revision,
    )


def _full(materials: AuthMaterials):
    return FastApiDependencyEffectExtractor().compile(
        materials,
        _profile(),
    )


def _timed(call):
    started = time.perf_counter()
    result = call()
    return result, (time.perf_counter() - started) * 1000.0


def _compile(
    materials: AuthMaterials,
    *,
    summary_root: Path,
    state_root: Path,
):
    # Construct fresh cache objects on every call to model a new worker.
    return compile_persistent_incremental_fastapi_assurance(
        materials,
        _profile(),
        semantic_summary_cache=PersistentPythonSemanticSummaryCache(
            summary_root
        ),
        state_cache=PersistentFastApiIncrementalStateCache(state_root),
    )


def _assert_equivalent(result, materials: AuthMaterials) -> None:
    full = _full(materials)
    if result.compilation.ir.canonical_payload() != full.canonical_payload():
        raise AssertionError("persistent incremental compile diverged from full compile")


def _row(result, elapsed_ms: float) -> dict[str, int | float | bool]:
    stats = result.compilation.stats
    summary = result.semantic_summary_stats
    return {
        "fresh_parses": summary.parse_count,
        "summary_hits": summary.hits,
        "summary_misses": summary.misses,
        "recomposed_contracts": stats.recomposed_contract_count,
        "reused_composed_contracts": stats.reused_composed_contract_count,
        "invalidated_contract_names": stats.contract_invalidated_name_count,
        "rebound_fragments": stats.rebound_file_count,
        "reused_fragments": stats.reused_fragment_count,
        "previous_state_loaded": result.previous_state_loaded,
        "state_written": result.state_written,
        "compile_ms": elapsed_ms,
    }


def run_scaling_case(size: int) -> dict:
    repo = f"benchmark/persistent-fastapi-{size}"
    base_files = _files(size)

    with tempfile.TemporaryDirectory(
        prefix=f"ovk-persistent-fastapi-{size}-"
    ) as temp:
        root = Path(temp)
        summary_root = root / "summary-cache"
        state_root = root / "state-cache"

        base = _materials(
            base_files,
            revision="base-head",
            repo=repo,
        )
        base_result, base_ms = _timed(
            lambda: _compile(
                base,
                summary_root=summary_root,
                state_root=state_root,
            )
        )
        _assert_equivalent(base_result, base)

        unchanged = _materials(
            _files(size),
            revision="unchanged-head",
            repo=repo,
        )
        unchanged_result, unchanged_ms = _timed(
            lambda: _compile(
                unchanged,
                summary_root=summary_root,
                state_root=state_root,
            )
        )
        _assert_equivalent(unchanged_result, unchanged)

        unrelated = _materials(
            _files(size, changed_unrelated=True),
            revision="unrelated-change-head",
            repo=repo,
        )
        unrelated_result, unrelated_ms = _timed(
            lambda: _compile(
                unrelated,
                summary_root=summary_root,
                state_root=state_root,
            )
        )
        _assert_equivalent(unrelated_result, unrelated)

    # Contract-change scenario gets a fresh base cache so it is measured from
    # the same secure baseline rather than after the unrelated branch state.
    with tempfile.TemporaryDirectory(
        prefix=f"ovk-persistent-fastapi-contract-{size}-"
    ) as temp:
        root = Path(temp)
        summary_root = root / "summary-cache"
        state_root = root / "state-cache"

        baseline = _materials(
            base_files,
            revision="contract-base",
            repo=repo + "-contract",
        )
        _compile(
            baseline,
            summary_root=summary_root,
            state_root=state_root,
        )

        contract_changed = _materials(
            _files(size, repo_attribute="tenant_id"),
            revision="contract-change-head",
            repo=repo + "-contract",
        )
        contract_result, contract_ms = _timed(
            lambda: _compile(
                contract_changed,
                summary_root=summary_root,
                state_root=state_root,
            )
        )
        _assert_equivalent(contract_result, contract_changed)

    return {
        "source_files": size,
        "base": _row(base_result, base_ms),
        "unchanged": _row(unchanged_result, unchanged_ms),
        "unrelated_change": _row(unrelated_result, unrelated_ms),
        "contract_change": _row(contract_result, contract_ms),
    }


def load_config() -> dict:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def run_scaling_benchmark() -> dict:
    config = load_config()
    return {
        "schema_version": config["schema_version"],
        "benchmark_id": config["benchmark_id"],
        "claim_scope": config["claim_scope"],
        "results": [
            run_scaling_case(int(size))
            for size in config["sizes"]
        ],
    }


def main() -> None:
    print(json.dumps(run_scaling_benchmark(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
