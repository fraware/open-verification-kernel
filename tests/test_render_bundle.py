import json
from pathlib import Path

from ovk.adapters.opa import evaluate_self_protection
from ovk.core.bundle import make_bundle
from ovk.core.render import render_bundle_markdown


def test_bundle_blocks_when_evidence_fails() -> None:
    data = json.loads(Path("examples/no_agent_self_approval/input_gate_removed.json").read_text(encoding="utf-8"))
    evidence = evaluate_self_protection(data, repo="example/repo", head_sha="abc")
    bundle = make_bundle([evidence])
    assert bundle.decision["merge_recommendation"] == "block"


def test_renderer_includes_guarantee_status_and_counterexample() -> None:
    data = json.loads(Path("examples/no_agent_self_approval/input_gate_removed.json").read_text(encoding="utf-8"))
    evidence = evaluate_self_protection(data, repo="example/repo", head_sha="abc")
    bundle = make_bundle([evidence])
    rendered = render_bundle_markdown(bundle)
    assert "Open Verification Kernel" in rendered
    assert "policy_evaluation" in rendered
    assert "required_check_removed" in rendered
    assert "block" in rendered
