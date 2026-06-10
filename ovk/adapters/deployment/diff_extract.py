"""Extract deployment state-machine inputs from deployment config diffs."""

from __future__ import annotations

from pathlib import PurePosixPath

from ovk.core.diff_parser import extract_post_images, is_unified_diff

DEPLOYMENT_MARKERS = ("deploy", "release", "deployment", "approval")


def _is_deployment_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    name = PurePosixPath(normalized).name
    return any(marker in normalized for marker in DEPLOYMENT_MARKERS) or name.endswith((".yml", ".yaml"))


def _states_from_content(content: str) -> list[dict]:
    states: list[dict] = []
    current: dict | None = None
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.endswith(":") and not stripped.startswith("-"):
            key = stripped[:-1].strip()
            if key in {"states", "approval_states", "deployment_states"}:
                continue
            if current:
                states.append(current)
            current = {"name": key, "requires_approval": False, "transitions": []}
        elif current and "approval" in stripped.lower():
            current["requires_approval"] = "required" in stripped.lower() or "true" in stripped.lower()
        elif current and stripped.startswith("- "):
            target = stripped[2:].strip().rstrip(":")
            if target:
                current["transitions"].append(target)
    if current:
        states.append(current)
    return states


def deployment_inputs_from_diff(diff_text: str) -> list[dict]:
    """Convert deployment file changes in a unified diff to deployment lane inputs."""
    if not is_unified_diff(diff_text):
        return []

    inputs: list[dict] = []
    for path, content in extract_post_images(diff_text).items():
        if not _is_deployment_path(path) or not content.strip():
            continue
        if "state" not in content.lower() and "approval" not in content.lower():
            continue
        states = _states_from_content(content)
        if not states:
            continue
        inputs.append({"states": states, "required_approval_states": [s["name"] for s in states if s.get("requires_approval")]})
    return inputs
