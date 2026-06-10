from pathlib import Path

from ovk.adapters.deployment.diff_extract import deployment_inputs_from_diff
from ovk.adapters.workflow.diff_extract import workflow_inputs_from_diff
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
    assert "review" in inputs[0]["states"]
    assert "deployed" in inputs[0]["states"]
    assert inputs[0]["transitions"]
    assert isinstance(inputs[0]["transitions"][0], dict)


def test_deployment_partial_hunk_parses_transitions_from_context_lines() -> None:
    diff_text = """diff --git a/deploy/release.yml b/deploy/release.yml
--- a/deploy/release.yml
+++ b/deploy/release.yml
@@ -2,6 +2,7 @@ deployment_states:
   draft:
     transitions:
       - production
+  production:
     requires_approval: true
"""
    inputs = deployment_inputs_from_diff(diff_text)
    assert inputs
    payload = inputs[0]
    assert "production" in payload["states"]
    assert any(item.get("to") == "production" for item in payload["transitions"])


def test_infra_partial_hunk_infers_public_exposure_from_property_line() -> None:
    diff_text = """diff --git a/infra/db.tf b/infra/db.tf
--- a/infra/db.tf
+++ b/infra/db.tf
@@ -12,1 +12,2 @@
   instance_class = "db.t3.micro"
+  publicly_accessible = true
"""
    inputs = infra_inputs_from_diff(diff_text)
    assert inputs
    resource = inputs[0]["data"]["resources"][0]
    assert resource["public_exposure"] is True


def test_workflow_partial_hunk_detects_secret_reference() -> None:
    diff_text = (Path("benchmarks/real_diffs") / "workflow_secrets_partial_hunk.diff").read_text(encoding="utf-8")
    inputs = workflow_inputs_from_diff(diff_text)
    assert inputs
    assert inputs[0]["workflows"][0]["uses_secrets"] is True


def test_auth_partial_hunk_extracts_unguarded_admin_route() -> None:
    diff_text = (Path("benchmarks/real_diffs") / "auth_route_partial_hunk.diff").read_text(encoding="utf-8")
    inputs = authorization_inputs_from_diff(diff_text)
    assert inputs
    paths = {route["path"] for route in inputs[0]["routes"]}
    assert "/admin/export" in paths


def test_lane_compiler_selects_only_affected_lanes_from_infra_diff() -> None:
    diff_text = (ROOT / "infra_public_s3.diff").read_text(encoding="utf-8")
    plan = build_plan_from_inputs(diff_text=diff_text)
    jobs = compile_lane_inputs_from_plan(plan, diff_text=diff_text)
    lanes = {job["lane"] for job in jobs}
    assert "infrastructure" in lanes
    assert "ci_secrets" not in lanes
