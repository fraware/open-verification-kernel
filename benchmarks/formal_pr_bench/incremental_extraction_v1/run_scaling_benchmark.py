"""Deterministic work-count benchmark for incremental Python extraction."""

from __future__ import annotations

import json
import time
from pathlib import Path

from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.compilers.authorization.python_ast_index import (
    parse_head_python_materials,
)


CONFIG_PATH = Path(
    "benchmarks/formal_pr_bench/incremental_extraction_v1/"
    "scaling_workloads.json"
)


def _target_source() -> str:
    return """
from fastapi import Depends, FastAPI

app = FastAPI()

class AgentService:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await load_agent(agent_id)
        if workspace_id is not None and agent.workspace_id != workspace_id:
            return None
        return agent

@app.get("/workspaces/{workspace_id}/agents/{agent_id}")
async def get_agent(
    workspace_id: str,
    agent_id: str,
    user = Depends(require_workspace_member),
):
    svc = AgentService()
    return await svc.get(agent_id, workspace_id=workspace_id)
""".strip()


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


def build_materials(size: int) -> tuple[AuthMaterials, AuthMaterials]:
    if size < 1:
        raise ValueError("source file count must be positive")

    base_files = {"target.py": _target_source()}
    for index in range(1, size):
        base_files[f"unrelated/module_{index}.py"] = (
            f"VALUE_{index} = {index}\n"
            f"def helper_{index}():\n"
            f"    return VALUE_{index}\n"
        )

    head_files = dict(base_files)
    if size == 1:
        head_files["target.py"] = base_files["target.py"] + "\n# head revision\n"
        changed_path = "target.py"
    else:
        changed_path = f"unrelated/module_{size - 1}.py"
        head_files[changed_path] = (
            base_files[changed_path]
            + f"HEAD_ONLY_{size - 1} = True\n"
        )

    base = AuthMaterials(
        base_files=dict(base_files),
        head_files=dict(base_files),
        repo="benchmark/incremental-extraction",
        base_revision="base",
        head_revision="base",
    )
    head = AuthMaterials(
        base_files=dict(base_files),
        head_files=head_files,
        repo="benchmark/incremental-extraction",
        base_revision="base",
        head_revision="head",
    )
    return base, head


def _timed(call):
    started = time.perf_counter()
    value = call()
    return value, (time.perf_counter() - started) * 1000.0


def run_scaling_case(size: int) -> dict[str, float | int]:
    base, head = build_materials(size)

    base_index, base_index_ms = _timed(
        lambda: parse_head_python_materials(base)
    )
    cold_head, cold_head_ms = _timed(
        lambda: parse_head_python_materials(head)
    )
    warm_head, warm_head_ms = _timed(
        lambda: parse_head_python_materials(head, reuse_from=base_index)
    )

    extractor = FastApiDependencyEffectExtractor()
    ir, compile_ms = _timed(
        lambda: extractor.compile(
            head,
            _profile(),
            parsed_index=warm_head,
        )
    )

    if ir.coverage.status != "complete":
        raise AssertionError(
            f"expected complete extraction coverage, got {ir.coverage.status}"
        )
    if len(ir.protected_effects) != 1:
        raise AssertionError(
            "benchmark source must produce exactly one protected effect"
        )

    return {
        "source_files": size,
        "base_fresh_parses": base_index.parse_count,
        "cold_head_fresh_parses": cold_head.parse_count,
        "warm_head_fresh_parses": warm_head.parse_count,
        "warm_head_reused": warm_head.reused_count,
        "base_index_ms": base_index_ms,
        "cold_head_index_ms": cold_head_ms,
        "warm_head_index_ms": warm_head_ms,
        "compile_from_warm_index_ms": compile_ms,
        # Current semantic extraction still considers the complete supplied head
        # source set. This field is a model/architecture count, not a timing claim.
        "head_source_files_supplied_to_semantic_compile": len(head.head_files),
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
