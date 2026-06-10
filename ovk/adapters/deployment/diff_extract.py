"""Extract deployment state-machine inputs from deployment config diffs."""

from __future__ import annotations

from pathlib import PurePosixPath

from ovk.core.diff_parser import extract_post_images, is_unified_diff

DEPLOYMENT_MARKERS = ("deploy", "release", "deployment", "approval")
SKIP_STATE_KEYS = frozenset(
    {
        "transitions",
        "requires_approval",
        "states",
        "approval_states",
        "deployment_states",
    }
)


def _is_deployment_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    name = PurePosixPath(normalized).name
    return any(marker in normalized for marker in DEPLOYMENT_MARKERS) or name.endswith((".yml", ".yaml"))


def _normalize_deployment_payload(states: list[dict]) -> dict:
    """Map YAML-style state blocks to deployment lane evaluator input."""
    state_names = [str(state["name"]) for state in states]
    transitions: list[dict[str, str]] = []
    for state in states:
        source = str(state["name"])
        for target in state.get("transitions", []):
            transitions.append({"from": source, "to": str(target)})
    required_states = [str(state["name"]) for state in states if state.get("requires_approval")]
    production_states = [state_names[-1]] if state_names else ["production"]
    state_metadata = {
        str(state["name"]): {"requires_approval": bool(state.get("requires_approval"))}
        for state in states
    }
    return {
        "initial_state": state_names[0] if state_names else "draft",
        "states": state_names,
        "transitions": transitions,
        "required_states": required_states,
        "production_states": production_states,
        "state_metadata": state_metadata,
    }


def _states_from_content(content: str) -> list[dict]:
    """Parse deployment state blocks; state names sit at two-space indent."""
    states: list[dict] = []
    current: dict | None = None
    for line in content.splitlines():
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if stripped.endswith(":") and not stripped.startswith("-"):
            key = stripped[:-1].strip()
            if indent == 2 and key not in SKIP_STATE_KEYS:
                if current:
                    states.append(current)
                current = {"name": key, "requires_approval": False, "transitions": []}
            continue
        if current is None:
            continue
        if indent >= 4 and "requires_approval" in stripped.lower():
            current["requires_approval"] = "false" not in stripped.lower()
        elif indent >= 4 and stripped.startswith("- "):
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
        inputs.append(_normalize_deployment_payload(states))
    return inputs
