from pathlib import Path

from ovk.adapters.deployment.diff_extract import deployment_inputs_from_diff
from ovk.adapters.z3.route_extract import authorization_inputs_from_diff
from ovk.core.diff_iac import infra_inputs_from_diff
from ovk.core.lane_compiler import build_plan_from_inputs, compile_lane_inputs_from_plan


ROOT = Path("examples/multi_surface")


def test_infra_compiler_extracts_public_resource_from_tf_diff() -> None:
    diff_text = (ROOT / "infra_public_s3.diff").read_text(encoding="utf-8")
    inputs = infra_inputs_from_diff(diff_text)
    assert inputs
    assert inputs[0]["input_format"] == "infra"
    assert inputs[0]["data"]["resources"][0]["public_exposure"] is True


def test_auth_compiler_extracts_routes_from_diff() -> None:
    diff_text = (ROOT / "auth_route_bypass.diff").read_text(encoding="utf-8")
    inputs = authorization_inputs_from_diff(diff_text)
    assert inputs
    paths = {route["path"] for route in inputs[0]["routes"]}
    assert "/admin/users" in paths


def test_deployment_compiler_extracts_states_from_diff() -> None:
    diff_text = (ROOT / "deployment_skip.diff").read_text(encoding="utf-8")
    inputs = deployment_inputs_from_diff(diff_text)
    assert inputs
    state_names = {state["name"] for state in inputs[0]["states"]}
    assert "staging" in state_names


def test_lane_compiler_selects_only_affected_lanes_from_infra_diff() -> None:
    diff_text = (ROOT / "infra_public_s3.diff").read_text(encoding="utf-8")
    plan = build_plan_from_inputs(diff_text=diff_text)
    jobs = compile_lane_inputs_from_plan(plan, diff_text=diff_text)
    lanes = {job["lane"] for job in jobs}
    assert "infrastructure" in lanes
    assert "ci_secrets" not in lanes
