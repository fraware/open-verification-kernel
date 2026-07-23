import json
from pathlib import Path

from ovk.core.counterexample_translator import (
    generate_regression_artifacts,
    repair_hint_for_counterexample,
    write_generated_tests,
)
from ovk.core.repo_memory import backend_success_rates, record_run, router_historical_priors
from ovk.mcp_stdio import TOOL_HANDLERS, handle_request


def test_mcp_agent_loop_plan_run_explain() -> None:
    auth_input = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    run_response = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "ovk.run_verification",
                "arguments": {
                    "lane": "authorization",
                    "input_data": auth_input,
                },
            },
        }
    )
    evidence = json.loads(run_response["result"]["content"][0]["text"])["evidence"]
    bundle_response = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "ovk.create_evidence_bundle",
                "arguments": {"evidence_items": [evidence]},
            },
        }
    )
    bundle = json.loads(bundle_response["result"]["content"][0]["text"])["bundle"]
    explain_response = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "ovk.explain_result",
                "arguments": {"evidence_bundle": bundle},
            },
        }
    )
    explain_payload = json.loads(explain_response["result"]["content"][0]["text"])
    assert explain_payload["repair_plan"]["blocked"] is True
    assert explain_payload["repair_hints"]
    assert explain_payload["repair_hints"][0]["fix_class"]


def test_mcp_generate_regression_artifact_writes_pytest_source() -> None:
    from ovk.adapters.z3.validated_path import evaluate_validated_authorization_path
    from ovk.core.bundle import make_bundle

    auth_fixture = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    evidence = evaluate_validated_authorization_path(auth_fixture, repo="test/repo", head_sha="abc")
    bundle = make_bundle([evidence])
    artifacts = TOOL_HANDLERS["ovk.generate_regression_artifact"]({"evidence_bundle": bundle.model_dump(mode="json")})
    assert artifacts["artifacts"]
    assert any("pytest_source" in item for item in artifacts["artifacts"])


def test_generate_test_cli_writes_pytest_files(tmp_path: Path) -> None:
    from ovk.adapters.z3.validated_path import evaluate_validated_authorization_path
    from ovk.core.bundle import make_bundle

    auth_fixture = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    evidence = evaluate_validated_authorization_path(auth_fixture, repo="test/repo", head_sha="abc")
    bundle = make_bundle([evidence])
    output_dir = tmp_path / "generated_tests"
    written = write_generated_tests(bundle, output_dir)
    assert any(path.suffix == ".py" for path in written)
    assert any(path.suffix == ".json" for path in written)


def test_repair_hint_includes_fix_class_and_location() -> None:
    hint = repair_hint_for_counterexample(
        {
            "failure_mode": "required_check_removed",
            "summary": "Required check removed",
            "affected_file": ".github/workflows/ci.yml",
            "line_hunk": 42,
        }
    )
    assert hint["fix_class"] == "restore_ci_gate"
    assert hint["affected_file"] == ".github/workflows/ci.yml"
    assert hint["line_hunk"] == 42


def test_repo_memory_feeds_router_priors(tmp_path: Path) -> None:
    memory_dir = tmp_path / "memory"
    record_run(
        {
            "bundle_id": "b1",
            "decision": {"merge_recommendation": "block"},
            "evidence": [
                {
                    "intent": {"intent_id": "no-admin-route-bypass"},
                    "backend_claims": [{"backend": "z3", "status": "fail"}],
                }
            ],
        },
        memory_dir=memory_dir,
    )
    record_run(
        {
            "bundle_id": "b2",
            "decision": {"merge_recommendation": "allow"},
            "evidence": [
                {
                    "intent": {"intent_id": "no-admin-route-bypass"},
                    "backend_claims": [{"backend": "z3", "status": "pass"}],
                }
            ],
        },
        memory_dir=memory_dir,
    )
    rates = backend_success_rates(memory_dir=memory_dir)
    # pass and fail are both conclusive verifier outcomes for reliability priors
    assert rates["z3"] == 1.0
    priors = router_historical_priors(memory_dir=memory_dir, enabled=True)
    assert priors["z3"] == 1.0
    assert router_historical_priors(memory_dir=memory_dir, enabled=False) == {}


def test_mcp_select_backends_uses_surface_routing() -> None:
    response = handle_request(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "ovk.select_backends",
                "arguments": {
                    "intent_id": "infra-guard-1",
                    "changed_files": ["infra/iam_policy.tf"],
                },
            },
        }
    )
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["selected"][0]["backend"] == "cedar"


def test_generated_regression_artifacts_cover_known_failure_modes() -> None:
    from ovk.adapters.z3.validated_path import evaluate_validated_authorization_path
    from ovk.core.bundle import make_bundle

    auth_fixture = json.loads(Path("examples/auth_regression/input_admin_bypass.json").read_text(encoding="utf-8"))
    evidence = evaluate_validated_authorization_path(auth_fixture, repo="test/repo", head_sha="abc")
    bundle = make_bundle([evidence])
    artifacts = generate_regression_artifacts(bundle)
    assert artifacts[0]["failure_mode"] == "admin_route_reachable_by_non_admin"
    assert "pytest_source" in artifacts[0]
