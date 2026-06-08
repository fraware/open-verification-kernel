from ovk.core.diff_parser import extract_changed_paths
from ovk.core.planner import plan_from_changed_files


def test_extract_changed_paths_from_unified_diff() -> None:
    diff_text = """diff --git a/.github/workflows/verify.yml b/.github/workflows/verify.yml
--- a/.github/workflows/verify.yml
+++ b/.github/workflows/verify.yml
@@ -1,2 +1,2 @@
 name: verify
"""
    assert extract_changed_paths(diff_text) == [".github/workflows/verify.yml"]


def test_planner_routes_ci_change_to_opa() -> None:
    plan = plan_from_changed_files([".github/workflows/verify.yml"])
    assert "agent-cannot-disable-own-ci-gate" in plan["candidate_intents"]
    routing = plan["intent_plans"][0]["routing"]
    selected = {item["backend"] for item in routing["selected"]}
    assert "opa" in selected


def test_planner_routes_auth_change_to_z3_or_opa() -> None:
    plan = plan_from_changed_files(["src/middleware/auth.py"])
    assert "no-admin-route-bypass" in plan["candidate_intents"]
    routing = plan["intent_plans"][0]["routing"]
    selected = {item["backend"] for item in routing["selected"]}
    assert selected.intersection({"z3", "opa"})
