"""Deployment IR/state-machine and CBMC guarantee honesty tests."""

from __future__ import annotations

from pathlib import Path

from ovk.compilers.cbmc import (
    CbmcProject,
    generate_harness,
    guarantee_implies_project_code,
    select_functions_from_source,
    validate_project_traceability,
)
from ovk.compilers.cbmc.project import CbmcFunctionTarget
from ovk.compilers.deployment import (
    compile_argo_rollouts,
    compile_explicit_schema,
    compile_github_environments,
    find_skipped_approval_paths,
)


def test_explicit_schema_detects_skipped_approval() -> None:
    ir = compile_explicit_schema(
        {
            "initial_state": "draft",
            "states": ["draft", "review", "approved", "deployed"],
            "required_states": ["review", "approved"],
            "production_states": ["deployed"],
            "transitions": [
                {"from": "draft", "to": "deployed"},
                {"from": "review", "to": "approved"},
                {"from": "approved", "to": "deployed"},
            ],
        }
    )
    findings = find_skipped_approval_paths(ir)
    assert findings
    assert findings[0]["failure_mode"] == "skipped_approval_state"


def test_github_environments_and_argo_compilers() -> None:
    gh = compile_github_environments(
        {
            "environments": [
                {"name": "staging", "required_reviewers": 1},
                {"name": "production", "required_reviewers": 2, "production": True},
            ]
        }
    )
    assert gh.source == "github_environments"
    assert "production" in gh.production_states
    argo = compile_argo_rollouts(
        {
            "spec": {
                "strategy": {
                    "canary": {
                        "steps": [{"setWeight": 20}, {"pause": {}}, {"setWeight": 100}],
                    }
                }
            }
        }
    )
    assert argo.source == "argo_rollouts"
    assert any(state.name.startswith("pause-") for state in argo.states)


def test_cbmc_guarantee_naming_honesty(tmp_path: Path) -> None:
    source = tmp_path / "buf.c"
    source.write_text("int copy_buf(char *dst, const char *src) { return 0; }\n", encoding="utf-8")
    functions = select_functions_from_source(source, name_substr="copy")
    assert functions
    stub = generate_harness(
        functions[0],
        obligation_id="obl-1",
        intent_id="cbmc-buffer-bounds",
        includes_project_code=False,
    )
    project = CbmcProject(functions=functions, harnesses=[stub])
    project.guarantee_type = project.declare_guarantee()
    assert project.guarantee_type == "bounded_harness_model_check"
    assert guarantee_implies_project_code(project.guarantee_type) is False

    linked = generate_harness(
        functions[0],
        obligation_id="obl-1",
        intent_id="cbmc-buffer-bounds",
        includes_project_code=True,
    )
    project2 = CbmcProject(functions=functions, harnesses=[linked])
    project2.guarantee_type = project2.declare_guarantee()
    assert project2.guarantee_type == "bounded_project_model_check"
    assert guarantee_implies_project_code(project2.guarantee_type) is True
    assert validate_project_traceability(project2) == []


def test_cbmc_rejects_project_guarantee_without_project_code() -> None:
    harness = generate_harness(
        CbmcFunctionTarget(name="f", file="f.c", selected_reason="test"),
        obligation_id="o",
        intent_id="i",
        includes_project_code=False,
    )
    project = CbmcProject(
        functions=[CbmcFunctionTarget(name="f", file="f.c", selected_reason="test")],
        harnesses=[harness],
        guarantee_type="bounded_project_model_check",
    )
    failures = validate_project_traceability(project)
    assert failures
