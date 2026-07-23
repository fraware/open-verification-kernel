from pathlib import Path

from ovk.adapters.ci_secrets.evidence import evaluate_ci_secrets_exposure
from ovk.adapters.workflow.diff_extract import workflow_inputs_from_diff
from ovk.core.bundle import make_bundle
from ovk.core.diff_parser import extract_post_images, is_unified_diff, reconstruct_post_image
from ovk.core.multi_lane import plan_required_inputs_from_diff
from ovk.core.planner import plan_from_diff_text


DIFF_PATH = Path("examples/ci_secrets/workflow_secrets_on_pr.diff")


def test_is_unified_diff_detects_patch_files() -> None:
    text = DIFF_PATH.read_text(encoding="utf-8")
    assert is_unified_diff(text)


def test_extract_post_images_reconstructs_workflow_yaml() -> None:
    text = DIFF_PATH.read_text(encoding="utf-8")
    image = reconstruct_post_image(text, ".github/workflows/preview.yml")
    assert image is not None
    assert "pull_request" in image
    assert "secrets.DEPLOY_TOKEN" in image
    assert "Preview" in extract_post_images(text)[".github/workflows/preview.yml"]


def test_workflow_inputs_from_diff_blocks_secrets_on_pull_request() -> None:
    text = DIFF_PATH.read_text(encoding="utf-8")
    inputs = workflow_inputs_from_diff(text)
    assert len(inputs) == 1
    assert inputs[0]["workflows"][0]["triggers"] == ["pull_request"]
    bundle = make_bundle([evaluate_ci_secrets_exposure(inputs[0], repo="test/repo", head_sha="abc")])
    assert bundle.decision["merge_recommendation"] == "block"


def test_workflow_inputs_from_diff_skips_incomplete_yaml_fragments() -> None:
    """Partial hunks can reconstruct non-documents; do not crash the check path."""
    text = """diff --git a/.github/workflows/partial.yml b/.github/workflows/partial.yml
--- a/.github/workflows/partial.yml
+++ b/.github/workflows/partial.yml
@@ -1,4 +1,4 @@
 ]
 env:
-  OVK_PACKAGE_VERSION: "1.2.0"
+  OVK_PACKAGE_VERSION: "1.2.1"
"""
    assert workflow_inputs_from_diff(text) == []


def test_plan_from_diff_includes_workflow_lane_inputs() -> None:
    text = DIFF_PATH.read_text(encoding="utf-8")
    plan = plan_from_diff_text(text)
    assert plan["source"] == "unified_diff"
    assert ".github/workflows/preview.yml" in plan["changed_files"]
    assert "no-secrets-in-untrusted-context" in plan["candidate_intents"]
    assert len(plan["workflow_inputs"]) == 1


def test_plan_required_inputs_from_diff_surfaces_suggested_lane_inputs() -> None:
    text = DIFF_PATH.read_text(encoding="utf-8")
    payload = plan_required_inputs_from_diff(text)
    assert payload["source"] == "unified_diff"
    assert "ci_secrets" in payload["suggested_lane_inputs"]
    assert len(payload["suggested_lane_inputs"]["ci_secrets"]) == 1
