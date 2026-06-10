from pathlib import Path

from ovk.core.lane_compiler import build_plan_from_inputs, compile_lane_inputs_from_plan


def test_lane_compiler_builds_ci_secrets_job_from_diff() -> None:
    diff_text = Path("examples/ci_secrets/workflow_secrets_on_pr.diff").read_text(encoding="utf-8")
    plan = build_plan_from_inputs(diff_text=diff_text)
    jobs = compile_lane_inputs_from_plan(plan, diff_text=diff_text)
    lanes = {job["lane"] for job in jobs}
    assert "ci_secrets" in lanes
