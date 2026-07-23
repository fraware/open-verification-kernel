"""Composite action expansion into the trust graph."""

from __future__ import annotations

from pathlib import Path

from ovk.compilers.github_actions.expressions import secret_names
from ovk.compilers.github_actions.ir import SecretUse, TrustEdge, TrustNode
from ovk.compilers.github_actions.loader import load_workflow_file


def expand_composite_action(
    action_path: Path,
    *,
    step_node_id: str,
    job_id: str,
) -> tuple[list[TrustNode], list[TrustEdge], list[SecretUse], list[str]]:
    """Propagate shell/env/inputs from a local composite action into trust nodes."""
    if action_path.is_dir():
        candidate = action_path / "action.yml"
        if not candidate.exists():
            candidate = action_path / "action.yaml"
        action_path = candidate
    if not action_path.exists():
        return [], [], [], [f"missing_composite_action:{action_path.as_posix()}"]
    data = load_workflow_file(action_path)
    runs = data.get("runs") if isinstance(data.get("runs"), dict) else {}
    if runs.get("using") != "composite":
        return [], [], [], [f"not_composite:{action_path.as_posix()}"]

    nodes: list[TrustNode] = [
        TrustNode(node_id=f"action:{action_path.as_posix()}", kind="composite_action", trust="unknown")
    ]
    edges: list[TrustEdge] = [
        TrustEdge(source=step_node_id, target=nodes[0].node_id, kind="uses_composite")
    ]
    secrets: list[SecretUse] = []
    for index, step in enumerate(runs.get("steps") or []):
        if not isinstance(step, dict):
            continue
        node_id = f"{nodes[0].node_id}:step:{index}"
        shell = str(step.get("shell") or "")
        run = str(step.get("run") or "")
        env = step.get("env") if isinstance(step.get("env"), dict) else {}
        labels = [shell] if shell else []
        if run:
            labels.append("run")
        nodes.append(TrustNode(node_id=node_id, kind="composite_step", trust="unknown", labels=labels))
        edges.append(TrustEdge(source=nodes[0].node_id, target=node_id, kind="composite_step"))
        blob = run + "\n" + "\n".join(f"{k}={v}" for k, v in env.items())
        for name in secret_names(blob):
            secrets.append(
                SecretUse(
                    name=name,
                    job_id=job_id,
                    step_id=node_id,
                    expression=blob[:200],
                )
            )
        # inputs referenced in composite steps
        if "inputs." in blob:
            nodes[-1].labels.append("uses_inputs")
    return nodes, edges, secrets, []
