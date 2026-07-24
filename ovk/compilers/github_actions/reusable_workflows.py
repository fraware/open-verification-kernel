"""Reusable workflow resolution with cycle prevention and mutable-ref review."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ovk.compilers.github_actions.ir import TrustFinding, WorkflowRef
from ovk.compilers.github_actions.loader import load_workflow_file

_REMOTE = re.compile(r"^(?P<owner>[^/]+)/(?P<repo>[^/@]+)(?:/(?P<path>.+?))?@(?P<ref>.+)$")


def parse_uses(uses: str) -> WorkflowRef:
    if uses.startswith("./") or uses.startswith(".\\"):
        return WorkflowRef(path=uses, remote=False, ref=None, mutable_ref=False)
    match = _REMOTE.match(uses)
    if not match:
        return WorkflowRef(path=uses, remote=True, mutable_ref=True)
    ref = match.group("ref")
    digest = ref if re.fullmatch(r"[0-9a-f]{40}", ref) else None
    mutable = digest is None and not ref.startswith("v")  # tags still mutable unless digest
    # Pin/digest when resolvable: sha is immutable; branch/tag refs are mutable.
    if digest is None and re.fullmatch(r"v?\d+(\.\d+)*", ref or ""):
        mutable = True  # version tags remain mutable without digest
    return WorkflowRef(
        path=match.group("path") or "",
        remote=True,
        owner_repo=f"{match.group('owner')}/{match.group('repo')}",
        ref=ref,
        digest=digest,
        mutable_ref=mutable if digest is None else False,
    )


def _local_uses_path(repo_root: Path, uses: str) -> Path:
    rel = uses.replace("\\", "/")
    if rel.startswith("./"):
        rel = rel[2:]
    return (repo_root / rel).resolve()


def resolve_local_reusable(
    workflow: dict[str, Any],
    *,
    repo_root: Path,
    visiting: set[str] | None = None,
) -> tuple[list[dict[str, Any]], list[TrustFinding]]:
    """Recursively load local reusable workflows; detect cycles."""
    visiting = set(visiting or [])
    loaded: list[dict[str, Any]] = []
    findings: list[TrustFinding] = []
    path = str(Path(str(workflow.get("_ovk_path") or "")).resolve()) if workflow.get("_ovk_path") else ""
    if path and path in visiting:
        findings.append(
            TrustFinding(
                kind="cycle",
                summary=f"reusable workflow cycle involving {path}",
                node_ids=[path],
            )
        )
        return loaded, findings
    if path:
        visiting.add(path)
    jobs = workflow.get("jobs") if isinstance(workflow.get("jobs"), dict) else {}
    for job_id, job in sorted(jobs.items()):
        if not isinstance(job, dict):
            continue
        uses = job.get("uses")
        if not isinstance(uses, str):
            continue
        ref = parse_uses(uses)
        secrets = job.get("secrets")
        if secrets == "inherit":
            findings.append(
                TrustFinding(
                    kind="secrets_inherit",
                    summary=f"job {job_id} inherits secrets into reusable workflow",
                    node_ids=[str(job_id)],
                    evidence={"uses": uses},
                )
            )
        if ref.remote:
            if ref.mutable_ref:
                findings.append(
                    TrustFinding(
                        kind="mutable_remote_ref",
                        summary=f"job {job_id} uses mutable remote ref {uses}",
                        node_ids=[str(job_id)],
                        evidence={"uses": uses},
                    )
                )
            continue
        local_path = _local_uses_path(repo_root, uses)
        if not local_path.exists():
            findings.append(
                TrustFinding(
                    kind="review",
                    summary=f"local reusable workflow missing: {uses}",
                    node_ids=[str(job_id)],
                )
            )
            continue
        child = load_workflow_file(local_path)
        child["_ovk_path"] = str(local_path.resolve())
        loaded.append(child)
        nested, nested_findings = resolve_local_reusable(child, repo_root=repo_root, visiting=set(visiting))
        loaded.extend(nested)
        findings.extend(nested_findings)
    if path:
        visiting.discard(path)
    return loaded, findings
