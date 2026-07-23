"""Deployment state-machine analysis over DeploymentIR."""

from __future__ import annotations

from collections import defaultdict, deque

from ovk.compilers.deployment.ir import DeploymentIR


def find_skipped_approval_paths(ir: DeploymentIR) -> list[dict[str, str]]:
    """Find production-reaching paths that skip required approval states."""
    if not ir.states or not ir.transitions:
        return [
            {
                "summary": "State machine abstraction is missing states or transitions.",
                "failure_mode": "missing_state_machine_abstraction",
            }
        ]
    graph: dict[str, list[str]] = defaultdict(list)
    for edge in ir.transitions:
        graph[edge.source].append(edge.target)
    production = set(ir.production_states) or {
        state.name for state in ir.states if state.production or state.kind == "deployed"
    }
    required = set(ir.required_states) or {state.name for state in ir.states if state.required}
    start = ir.initial_state or (ir.states[0].name if ir.states else None)
    if start is None:
        return [{"summary": "initial state missing", "failure_mode": "missing_initial_state"}]

    counterexamples: list[dict[str, str]] = []
    queue: deque[tuple[str, list[str]]] = deque([(start, [start])])
    seen: set[tuple[str, tuple[str, ...]]] = set()
    while queue:
        node, path = queue.popleft()
        key = (node, tuple(path))
        if key in seen:
            continue
        seen.add(key)
        if node in production:
            missing = sorted(required - set(path))
            if missing:
                counterexamples.append(
                    {
                        "summary": f"Path {' -> '.join(path)} reaches production without {', '.join(missing)}",
                        "failure_mode": "skipped_approval_state",
                        "path": " -> ".join(path),
                    }
                )
            continue
        for nxt in sorted(graph.get(node, [])):
            queue.append((nxt, path + [nxt]))
    return counterexamples
