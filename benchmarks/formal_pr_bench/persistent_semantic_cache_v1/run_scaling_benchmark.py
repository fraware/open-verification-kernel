"""Persistent semantic summary cache work-count benchmark."""

from __future__ import annotations

import json
import time
from pathlib import Path
from tempfile import TemporaryDirectory

from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.compilers.authorization.semantic_summary_cache import (
    PersistentPythonSemanticSummaryCache,
    load_persistent_semantic_summaries,
)


CONFIG_PATH = Path(
    "benchmarks/formal_pr_bench/persistent_semantic_cache_v1/"
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
    svc = AgentService()
    return await svc.get(agent_id, workspace_id=workspace_id)
""".strip()


def _service_source(attribute: str) -> str:
    return f"""
class AgentService:
    async def get(self, agent_id: str, *, workspace_id: str | None = None):
        agent = await load_agent(agent_id)
        if workspace_id is not None and agent.{attribute} != workspace_id:
            return None
        return agent
""".strip()


def _files(size: int, *, service_attribute: str) -> dict[str, str]:
    if size < 2:
        raise ValueError("persistent benchmark requires at least two source files")
    files = {
        "routes.py": _route_source(),
        "service.py": _service_source(service_attribute),
    }
    for index in range(2, size):
        files[f"unrelated/module_{index}.py"] = (
            f"VALUE_{index} = {index}\n"
            f"def helper_{index}():\n"
            f"    return VALUE_{index}\n"
        )
    return files


def _materials(
    size: int,
    *,
    service_attribute: str,
    head_sha: str,
) -> AuthMaterials:
    files = _files(size, service_attribute=service_attribute)
    return AuthMaterials(
        base_files=dict(files),
        head_files=files,
        repo="benchmark/persistent-semantic-cache",
        base_revision="base",
        head_revision=head_sha,
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


def _timed(call):
    started = time.perf_counter()
    value = call()
    return value, (time.perf_counter() - started) * 1000.0


def _compile(materials: AuthMaterials, loaded):
    return FastApiDependencyEffectExtractor().compile(
        materials,
        _profile(),
        parsed_index=loaded.parsed_index,
        contract_summary_index=loaded.contract_summary_index,
        route_summary_index=loaded.route_summary_index,
    )


def run_scaling_case(size: int) -> dict[str, float | int | str]:
    with TemporaryDirectory(prefix="ovk-persistent-summary-") as temp:
        root = Path(temp)

        base = _materials(
            size,
            service_attribute="workspace_id",
            head_sha="base",
        )
        seeded, seed_ms = _timed(
            lambda: load_persistent_semantic_summaries(
                base,
                cache=PersistentPythonSemanticSummaryCache(root),
            )
        )
        base_ir = _compile(base, seeded)
        if base_ir.coverage.status != "complete":
            raise AssertionError("base extraction must be complete")

        unchanged = _materials(
            size,
            service_attribute="workspace_id",
            head_sha="unchanged-head",
        )
        unchanged_loaded, unchanged_load_ms = _timed(
            lambda: load_persistent_semantic_summaries(
                unchanged,
                cache=PersistentPythonSemanticSummaryCache(root),
            )
        )
        unchanged_ir, unchanged_compile_ms = _timed(
            lambda: _compile(unchanged, unchanged_loaded)
        )
        if unchanged_ir.coverage.status != "complete":
            raise AssertionError("unchanged cached head must remain complete")

        changed = _materials(
            size,
            service_attribute="tenant_id",
            head_sha="changed-head",
        )
        changed_loaded, changed_load_ms = _timed(
            lambda: load_persistent_semantic_summaries(
                changed,
                cache=PersistentPythonSemanticSummaryCache(root),
            )
        )
        changed_ir, changed_compile_ms = _timed(
            lambda: _compile(changed, changed_loaded)
        )
        marker = (
            "required_scope_postcondition_missing:"
            "AgentService.get:workspace_id"
        )
        if changed_ir.coverage.status != "partial":
            raise AssertionError("changed service contract must lower coverage")
        if not any(
            marker in item
            for item in changed_ir.coverage.unsupported_constructs
        ):
            raise AssertionError(
                "persistent route summary failed to rebind changed contract"
            )

        return {
            "source_files": size,
            "seed_parses": seeded.stats.parse_count,
            "seed_writes": seeded.stats.writes,
            "unchanged_hits": unchanged_loaded.stats.hits,
            "unchanged_misses": unchanged_loaded.stats.misses,
            "unchanged_parses": unchanged_loaded.stats.parse_count,
            "unchanged_fresh_contract_summaries": (
                unchanged_loaded.contract_summary_index.fresh_summary_count
            ),
            "unchanged_fresh_route_summaries": (
                unchanged_loaded.route_summary_index.fresh_summary_count
            ),
            "changed_hits": changed_loaded.stats.hits,
            "changed_misses": changed_loaded.stats.misses,
            "changed_parses": changed_loaded.stats.parse_count,
            "changed_fresh_contract_summaries": (
                changed_loaded.contract_summary_index.fresh_summary_count
            ),
            "changed_fresh_route_summaries": (
                changed_loaded.route_summary_index.fresh_summary_count
            ),
            "changed_coverage_status": changed_ir.coverage.status,
            "seed_load_ms": seed_ms,
            "unchanged_load_ms": unchanged_load_ms,
            "unchanged_compile_ms": unchanged_compile_ms,
            "changed_load_ms": changed_load_ms,
            "changed_compile_ms": changed_compile_ms,
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
