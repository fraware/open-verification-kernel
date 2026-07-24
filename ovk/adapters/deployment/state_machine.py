"""Approval state machine reachability checker."""

from __future__ import annotations

from collections import deque
from typing import Any

FAILURE_MODE = "required_approval_state_skipped"


def _states(data: dict[str, Any]) -> list[str]:
    states = data.get("states", [])
    return [str(state) for state in states if isinstance(state, str)]


def _transitions(data: dict[str, Any]) -> list[tuple[str, str]]:
    transitions: list[tuple[str, str]] = []
    for item in data.get("transitions", []):
        if not isinstance(item, dict):
            continue
        from_state = item.get("from")
        to_state = item.get("to")
        if isinstance(from_state, str) and isinstance(to_state, str):
            transitions.append((from_state, to_state))
    return transitions


def find_skipped_approval_paths(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Find paths to production that skip required approval states."""
    states = set(_states(data))
    transitions = _transitions(data)
    required_states = {str(state) for state in data.get("required_states", []) if isinstance(state, str)}
    initial = str(data.get("initial_state", "draft"))
    production_states = {str(state) for state in data.get("production_states", ["deployed"]) if isinstance(state, str)}
    state_metadata = data.get("state_metadata", {})
    if isinstance(state_metadata, dict):
        approval_required = {
            str(name)
            for name, meta in state_metadata.items()
            if isinstance(meta, dict) and meta.get("requires_approval")
        }
    else:
        approval_required = set()

    if not states or not transitions:
        return []
    if not required_states and not approval_required:
        return []

    adjacency: dict[str, list[str]] = {state: [] for state in states}
    for from_state, to_state in transitions:
        if from_state in adjacency:
            adjacency[from_state].append(to_state)

    counterexamples: list[dict[str, Any]] = []
    queue: deque[tuple[str, list[str]]] = deque([(initial, [initial])])
    visited_paths: set[tuple[str, ...]] = set()

    while queue:
        state, path = queue.popleft()
        path_key = tuple(path)
        if path_key in visited_paths:
            continue
        visited_paths.add(path_key)

        if state in production_states:
            visited_required = {item for item in required_states if item in path}
            if required_states and visited_required != required_states:
                skipped = sorted(required_states - visited_required)
                counterexamples.append(
                    {
                        "summary": f"Production state {state} is reachable without required states: {', '.join(skipped)}.",
                        "failure_mode": FAILURE_MODE,
                        "path": path,
                        "skipped_required_states": skipped,
                        "production_state": state,
                    }
                )
            elif len(path) >= 2:
                previous = path[-2]
                previous_meta = state_metadata.get(previous, {}) if isinstance(state_metadata, dict) else {}
                if approval_required and not previous_meta.get("requires_approval"):
                    counterexamples.append(
                        {
                            "summary": (
                                f"Production state {state} is reachable from {previous} without a prior approval gate."
                            ),
                            "failure_mode": FAILURE_MODE,
                            "path": path,
                            "skipped_required_states": sorted(approval_required - set(path[:-1])),
                            "production_state": state,
                        }
                    )
            continue

        for next_state in adjacency.get(state, []):
            if next_state in path:
                continue
            queue.append((next_state, path + [next_state]))

    return counterexamples
