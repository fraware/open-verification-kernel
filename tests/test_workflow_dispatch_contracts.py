import re
from collections.abc import Iterator
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
ALLOWED_DISPATCH_TYPES = {"boolean", "choice", "environment", "number", "string"}
FULL_COMMIT_PIN = re.compile(r"^[^@\s]+@[0-9a-fA-F]{40}$")


def _load_workflow(path: Path) -> dict:
    """Load workflow YAML without YAML 1.1 coercion of the `on` key."""

    payload = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(payload, dict), f"workflow must be a mapping: {path}"
    return payload


def _iter_workflow_uses(workflow: dict) -> Iterator[str]:
    """Yield job- and step-level `uses` references from a parsed workflow."""

    jobs = workflow.get("jobs", {})
    if not isinstance(jobs, dict):
        return
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        job_uses = job.get("uses")
        if isinstance(job_uses, str):
            yield job_uses
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue
        for step in steps:
            if not isinstance(step, dict):
                continue
            step_uses = step.get("uses")
            if isinstance(step_uses, str):
                yield step_uses


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


def test_external_workflow_actions_use_full_commit_sha_pins() -> None:
    """External actions/reusable workflows must be pinned to exact 40-hex commits."""

    checked = 0
    for path in sorted(WORKFLOW_DIR.glob("*.y*ml")):
        workflow = _load_workflow(path)
        for uses in _iter_workflow_uses(workflow):
            if uses.startswith("./") or uses.startswith("docker://"):
                continue
            checked += 1
            assert FULL_COMMIT_PIN.fullmatch(uses), (
                f"external workflow reference must use an exact 40-hex commit SHA: {path}: {uses!r}"
            )

    assert checked > 0, "expected at least one external workflow reference"


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


def test_consumer_pin_verification_uploads_hidden_evidence() -> None:
    """Evidence written under `.verification` must not be silently omitted from artifacts."""

    path = WORKFLOW_DIR / "consumer-pin-verification.yml"
    workflow = _load_workflow(path)
    steps = workflow["jobs"]["verify-consumer-pins"]["steps"]
    upload_steps = [step for step in steps if step.get("name") == "Upload consumer pin evidence"]

    assert len(upload_steps) == 1
    upload = upload_steps[0]
    assert upload["with"]["path"].startswith(".verification/")
    assert upload["with"]["if-no-files-found"] == "error"
    assert upload["with"]["include-hidden-files"] == "true"
