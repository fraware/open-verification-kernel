"""Assert the composite Action and CI invoke the bounded source identity contract."""
from pathlib import Path
import yaml
ROOT = Path(__file__).resolve().parents[1]

def test_action_executes_identity_helper_and_uploads_receipt():
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    steps = action["runs"]["steps"]
    prepare = [s for s in steps if s.get("name") == "Prepare change input"]
    assert len(prepare) == 1
    script = prepare[0]["run"]
    assert "scripts/prepare_verified_change_input.py" in script
    assert "set -euo pipefail" in script
    assert "--github-sha" in script and "--pr-head-sha" in script
    assert "--base-sha" in script and "--mode" in script
    assert "|| true" not in script
    upload = next(s for s in steps if s.get("name") == "Upload OVK artifacts")
    assert "ovk-source-binding.json" in upload["with"]["path"]

def test_dogfood_uses_merge_preview_and_rejects_unbound_strict():
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    jobs = workflow["jobs"]
    for name in ("action_default_diff_dogfood", "action_strict_dogfood"):
        steps = jobs[name]["steps"]
        checkout = next(s for s in steps if "actions/checkout@" in s.get("uses", ""))
        assert checkout["with"]["ref"] == "${{ github.sha }}"
        assert checkout["with"]["fetch-depth"] == 2
        assert checkout["with"]["persist-credentials"] is False
    strict = jobs["action_strict_dogfood"]
    assert strict["permissions"] == {"contents": "read"}
    candidate = next(s for s in strict["steps"] if s.get("name", "").startswith("Strict Action"))
    assert candidate["with"]["mode"] == "strict"
    assert candidate["with"]["changed-files"]
    assert candidate["with"]["emit-check"] == "false"
    assert "test ! -f ovk-evidence.json" in strict["steps"][-1]["run"]

def test_docs_reject_unproved_signed_source_binding():
    docs = (ROOT / "docs/PR_SOURCE_BINDING_V1.md").read_text()
    assert "not yet incorporated" in docs
    assert "production_reliance_authorized=false" in docs

def test_unbound_caller_diff_never_emits_a_shareable_action_check_or_comment():
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    steps = action["runs"]["steps"]
    check = next(s for s in steps if s.get("name") == "Emit OVK GitHub check (check path)")
    comment = next(s for s in steps if s.get("name") == "Post OVK pull-request comment")
    warning = next(s for s in steps if s.get("name") == "Disclose unbound caller-selected inputs")
    assert "inputs.changed-files == ''" in check["if"]
    assert "inputs.changed-files == ''" in comment["if"]
    assert "caller-supplied" in warning["run"]
    assert "inputs.changed-files != ''" in warning["if"]
