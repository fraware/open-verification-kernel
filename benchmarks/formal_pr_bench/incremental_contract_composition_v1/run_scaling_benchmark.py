"""Deterministic work-count benchmark for incremental contract composition."""

from __future__ import annotations

import json
import time
from pathlib import Path

from ovk.compilers.authorization.incremental_contract_composition import (
    compose_function_contracts_incremental,
)
from ovk.compilers.authorization.material_loader import AuthMaterials
from ovk.compilers.authorization.python_ast_index import parse_head_python_materials
from ovk.compilers.authorization.resource_return_contracts import (
    build_contract_summary_index,
    compose_function_contracts,
)


CONFIG_PATH = Path(
    "benchmarks/formal_pr_bench/incremental_contract_composition_v1/"
    "scaling_workloads.json"
)


def _direct_source(class_name: str, attribute: str = "scope_id") -> str:
    return f"""
class {class_name}:
    async def get(self, item_id: str, *, scope_id: str | None = None):
        item = await load_item(item_id)
        if scope_id is not None and item.{attribute} != scope_id:
            return None
        return item
""".strip()


def _wrapper_source(class_name: str, callee: str) -> str:
    return f"""
class {class_name}:
    def __init__(self):
        self._inner = {callee}()

    async def get(self, item_id: str, *, scope_id: str | None = None):
        return await self._inner.get(item_id, scope_id=scope_id)
""".strip()


def _materials(
    base_files: dict[str, str],
    head_files: dict[str, str],
    *,
    head_revision: str,
) -> tuple[AuthMaterials, AuthMaterials]:
    base = AuthMaterials(
        base_files=dict(base_files),
        head_files=dict(base_files),
        repo="benchmark/incremental-contract-composition",
        base_revision="base",
        head_revision="base",
    )
    head = AuthMaterials(
        base_files=dict(base_files),
        head_files=dict(head_files),
        repo="benchmark/incremental-contract-composition",
        base_revision="base",
        head_revision=head_revision,
    )
    return base, head


def _indexes(base: AuthMaterials, head: AuthMaterials):
    base_parsed = parse_head_python_materials(base)
    base_summary = build_contract_summary_index(
        base,
        parsed_trees=base_parsed.trees,
        source_digests=base_parsed.source_digests,
    )
    head_parsed = parse_head_python_materials(
        head,
        reuse_from=base_parsed,
    )
    head_summary = build_contract_summary_index(
        head,
        parsed_trees=head_parsed.trees,
        source_digests=head_parsed.source_digests,
        reuse_from=base_summary,
    )
    return base_summary, head_summary, head_parsed


def _timed(call):
    started = time.perf_counter()
    result = call()
    return result, (time.perf_counter() - started) * 1000.0


def _payload(contracts) -> list[dict]:
    return [item.model_dump(mode="json") for item in contracts]


def _width_files(width: int, *, changed: bool) -> dict[str, str]:
    if width < 1:
        raise ValueError("width must be positive")

    files = {
        "target_repo.py": _direct_source(
            "TargetRepo",
            "tenant_id" if changed else "scope_id",
        ),
        "target_service.py": _wrapper_source(
            "TargetService",
            "TargetRepo",
        ),
        "target_facade.py": _wrapper_source(
            "TargetFacade",
            "TargetService",
        ),
    }
    for index in range(1, width):
        repo_name = f"Repo{index}"
        service_name = f"Service{index}"
        files[f"unrelated/repo_{index}.py"] = _direct_source(repo_name)
        files[f"unrelated/service_{index}.py"] = _wrapper_source(
            service_name,
            repo_name,
        )
    return files


def run_width_case(width: int) -> dict[str, int | float | bool]:
    base_files = _width_files(width, changed=False)
    head_files = _width_files(width, changed=True)
    base, head = _materials(
        base_files,
        head_files,
        head_revision=f"width-{width}-head",
    )
    base_summary, head_summary, head_parsed = _indexes(base, head)
    base_result = compose_function_contracts_incremental(base_summary)

    incremental, incremental_ms = _timed(
        lambda: compose_function_contracts_incremental(
            head_summary,
            previous_state=base_result.state,
        )
    )
    full, full_ms = _timed(
        lambda: compose_function_contracts(head_summary)
    )
    equivalent = _payload(incremental.contracts) == _payload(full)
    if not equivalent:
        raise AssertionError("incremental width result diverged from full composer")

    return {
        "width": width,
        "source_files": len(head_files),
        "head_fresh_parses": head_parsed.parse_count,
        "reused_composed_contracts": (
            incremental.stats.reused_composed_contract_count
        ),
        "recomposed_contracts": incremental.stats.recomposed_contract_count,
        "invalidated_names": incremental.stats.invalidated_name_count,
        "changed_seeds": incremental.stats.changed_seed_count,
        "full_recompose_fallback": incremental.stats.full_recompose_fallback,
        "full_equivalent": equivalent,
        "incremental_compose_ms": incremental_ms,
        "full_compose_ms": full_ms,
    }


def _depth_files(
    depth: int,
    *,
    unrelated_chains: int,
    changed: bool,
) -> dict[str, str]:
    if depth < 1:
        raise ValueError("depth must be positive")

    files = {
        "target_repo.py": _direct_source(
            "TargetRepo",
            "tenant_id" if changed else "scope_id",
        )
    }
    callee = "TargetRepo"
    for level in range(1, depth + 1):
        wrapper = f"TargetLayer{level}"
        files[f"target/layer_{level}.py"] = _wrapper_source(
            wrapper,
            callee,
        )
        callee = wrapper

    for index in range(unrelated_chains):
        repo_name = f"SideRepo{index}"
        service_name = f"SideService{index}"
        files[f"side/repo_{index}.py"] = _direct_source(repo_name)
        files[f"side/service_{index}.py"] = _wrapper_source(
            service_name,
            repo_name,
        )
    return files


def run_depth_case(
    depth: int,
    *,
    unrelated_chains: int,
) -> dict[str, int | float | bool]:
    base_files = _depth_files(
        depth,
        unrelated_chains=unrelated_chains,
        changed=False,
    )
    head_files = _depth_files(
        depth,
        unrelated_chains=unrelated_chains,
        changed=True,
    )
    base, head = _materials(
        base_files,
        head_files,
        head_revision=f"depth-{depth}-head",
    )
    base_summary, head_summary, head_parsed = _indexes(base, head)
    base_result = compose_function_contracts_incremental(base_summary)

    incremental, incremental_ms = _timed(
        lambda: compose_function_contracts_incremental(
            head_summary,
            previous_state=base_result.state,
        )
    )
    full, full_ms = _timed(
        lambda: compose_function_contracts(head_summary)
    )
    equivalent = _payload(incremental.contracts) == _payload(full)
    if not equivalent:
        raise AssertionError("incremental depth result diverged from full composer")

    return {
        "depth": depth,
        "unrelated_chains": unrelated_chains,
        "source_files": len(head_files),
        "head_fresh_parses": head_parsed.parse_count,
        "reused_composed_contracts": (
            incremental.stats.reused_composed_contract_count
        ),
        "recomposed_contracts": incremental.stats.recomposed_contract_count,
        "invalidated_names": incremental.stats.invalidated_name_count,
        "changed_seeds": incremental.stats.changed_seed_count,
        "full_recompose_fallback": incremental.stats.full_recompose_fallback,
        "full_equivalent": equivalent,
        "incremental_compose_ms": incremental_ms,
        "full_compose_ms": full_ms,
    }


def load_config() -> dict:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def run_scaling_benchmark() -> dict:
    config = load_config()
    unrelated = int(config["depth_unrelated_chains"])
    return {
        "schema_version": config["schema_version"],
        "benchmark_id": config["benchmark_id"],
        "claim_scope": config["claim_scope"],
        "width_results": [
            run_width_case(int(width))
            for width in config["width_cases"]
        ],
        "depth_results": [
            run_depth_case(
                int(depth),
                unrelated_chains=unrelated,
            )
            for depth in config["depth_cases"]
        ],
    }


def main() -> None:
    print(json.dumps(run_scaling_benchmark(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
