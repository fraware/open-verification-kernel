from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
ALLOWED_DISPATCH_TYPES = {"boolean", "choice", "environment", "number", "string"}


def _load_workflow(path: Path) -> dict:
    """Load workflow YAML without YAML 1.1 coercion of the `on` key."""

    payload = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(payload, dict), f"workflow must be a mapping: {path}"
    return payload


def test_all_workflow_dispatch_inputs_have_explicit_supported_types() -> None:
    """GitHub rejects workflow_dispatch schemas whose inputs omit `type`."""

    checked = 0
    for path in sorted(WORKFLOW_DIR.glob("*.y*ml")):
        workflow = _load_workflow(path)
        triggers = workflow.get("on")
        if not isinstance(triggers, dict):
            continue
        dispatch = triggers.get("workflow_dispatch")
        if dispatch is None:
            continue
        checked += 1
        if dispatch == "":
            continue
        assert isinstance(dispatch, dict), f"workflow_dispatch must be a mapping or null: {path}"
        inputs = dispatch.get("inputs", {})
        if inputs == "":
            continue
        assert isinstance(inputs, dict), f"workflow_dispatch.inputs must be a mapping: {path}"
        for input_name, spec in inputs.items():
            assert isinstance(spec, dict), f"dispatch input {input_name!r} must be a mapping: {path}"
            input_type = spec.get("type")
            assert input_type in ALLOWED_DISPATCH_TYPES, (
                f"dispatch input {input_name!r} in {path} must declare a supported type; got {input_type!r}"
            )

    assert checked > 0, "expected at least one workflow_dispatch workflow"


def test_consumer_pin_verification_exposes_typed_release_inputs() -> None:
    """The release-authority consumer workflow must remain dispatchable by GitHub."""

    path = WORKFLOW_DIR / "consumer-pin-verification.yml"
    workflow = _load_workflow(path)
    dispatch = workflow["on"]["workflow_dispatch"]
    inputs = dispatch["inputs"]

    assert set(inputs) == {"ovk_candidate_sha", "fastapi_ref", "express_ref"}
    assert all(inputs[name]["type"] == "string" for name in inputs)
    assert inputs["ovk_candidate_sha"]["required"] == "true"
    assert inputs["fastapi_ref"]["default"] == "main"
    assert inputs["express_ref"]["default"] == "main"
