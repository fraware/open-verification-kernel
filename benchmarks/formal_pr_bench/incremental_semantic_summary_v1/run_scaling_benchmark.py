"""Semantic-summary work-count benchmark for incremental FastAPI assurance."""

from __future__ import annotations

import json
import time
from pathlib import Path

from ovk.compilers.authorization.fastapi_route_summary import (
    build_route_summary_index,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.protected_effect_fastapi_dependency import (
    FastApiDependencyEffectExtractor,
    FastApiDependencyEffectProfile,
)
from ovk.compilers.authorization.python_ast_index import (
    parse_head_python_materials,
)
from ovk.compilers.authorization.resource_return_contracts import (
    build_contract_summary_index,
)


CONFIG_PATH = Path(
    "benchmarks/formal_pr_bench/incremental_semantic_summary_v1/"
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
    if size < 2:
        raise ValueError("semantic-summary benchmark requires at least two files")

    base_files = {
        "routes.py": _route_source(),
        "service.py": _service_source("workspace_id"),
    }
    for index in range(2, size):
        base_files[f"unrelated/module_{index}.py"] = (
            f"VALUE_{index} = {index}\n"
            f"def helper_{index}():\n"
            f"    return VALUE_{index}\n"
        )

    head_files = dict(base_files)
    head_files["service.py"] = _service_source("tenant_id")

    base = AuthMaterials(
        base_files=dict(base_files),
        head_files=dict(base_files),
        repo="benchmark/incremental-semantic-summary",
        base_revision="base",
        head_revision="base",
    )
    head = AuthMaterials(
        base_files=dict(base_files),
        head_files=head_files,
        repo="benchmark/incremental-semantic-summary",
        base_revision="base",
        head_revision="head",
    )
    return base, head


def _timed(call):
    started = time.perf_counter()
    value = call()
    return value, (time.perf_counter() - started) * 1000.0


def run_scaling_case(size: int) -> dict[str, float | int | str]:
    base, head = build_materials(size)

    base_parsed = parse_head_python_materials(base)
    base_contracts = build_contract_summary_index(
        base,
        parsed_trees=base_parsed.trees,
        source_digests=base_parsed.source_digests,
    )
    base_routes = build_route_summary_index(
        base,
        parsed_trees=base_parsed.trees,
        source_digests=base_parsed.source_digests,
    )

    cold_parsed, cold_parse_ms = _timed(
        lambda: parse_head_python_materials(head)
    )
    cold_contracts, cold_contract_ms = _timed(
        lambda: build_contract_summary_index(
            head,
            parsed_trees=cold_parsed.trees,
            source_digests=cold_parsed.source_digests,
        )
    )
    cold_routes, cold_route_ms = _timed(
        lambda: build_route_summary_index(
            head,
            parsed_trees=cold_parsed.trees,
            source_digests=cold_parsed.source_digests,
        )
    )

    warm_parsed, warm_parse_ms = _timed(
        lambda: parse_head_python_materials(
            head,
            reuse_from=base_parsed,
        )
    )
    warm_contracts, warm_contract_ms = _timed(
        lambda: build_contract_summary_index(
            head,
            parsed_trees=warm_parsed.trees,
            source_digests=warm_parsed.source_digests,
            reuse_from=base_contracts,
        )
    )
    warm_routes, warm_route_ms = _timed(
        lambda: build_route_summary_index(
            head,
            parsed_trees=warm_parsed.trees,
            source_digests=warm_parsed.source_digests,
            reuse_from=base_routes,
        )
    )

    extractor = FastApiDependencyEffectExtractor()
    ir, compile_ms = _timed(
        lambda: extractor.compile(
            head,
            _profile(),
            parsed_index=warm_parsed,
            contract_summary_index=warm_contracts,
            route_summary_index=warm_routes,
        )
    )

    expected_marker = (
        "required_scope_postcondition_missing:"
        "AgentService.get:workspace_id"
    )
    if ir.coverage.status != "partial":
        raise AssertionError(
            f"expected partial coverage after contract change, got {ir.coverage.status}"
        )
    if not any(
        expected_marker in item
        for item in ir.coverage.unsupported_constructs
    ):
        raise AssertionError(
            "cached route summary failed to rebind changed service contract"
        )
    if warm_routes.summaries["routes.py"] is not base_routes.summaries["routes.py"]:
        raise AssertionError("unchanged route summary was not reused")

    return {
        "source_files": size,
        "cold_fresh_parses": cold_parsed.parse_count,
        "cold_fresh_contract_summaries": cold_contracts.fresh_summary_count,
        "cold_fresh_route_summaries": cold_routes.fresh_summary_count,
        "warm_fresh_parses": warm_parsed.parse_count,
        "warm_reused_parses": warm_parsed.reused_count,
        "warm_fresh_contract_summaries": warm_contracts.fresh_summary_count,
        "warm_reused_contract_summaries": warm_contracts.reused_summary_count,
        "warm_fresh_route_summaries": warm_routes.fresh_summary_count,
        "warm_reused_route_summaries": warm_routes.reused_summary_count,
        "coverage_status": ir.coverage.status,
        "detected_changed_contract_semantics": 1,
        "cold_parse_ms": cold_parse_ms,
        "cold_contract_summary_ms": cold_contract_ms,
        "cold_route_summary_ms": cold_route_ms,
        "warm_parse_ms": warm_parse_ms,
        "warm_contract_summary_ms": warm_contract_ms,
        "warm_route_summary_ms": warm_route_ms,
        "compile_from_warm_summaries_ms": compile_ms,
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
