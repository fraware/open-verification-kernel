"""Bridge into authentic v0 extract/materialize modules without editing them.

Imports the committed modules from ``rtk_eval`` and re-exports the repository
dispatch helpers used by CertifyEdge / pcs-core adapters.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Any

_RTK_EVAL = Path(__file__).resolve().parents[2]
if str(_RTK_EVAL) not in sys.path:
    sys.path.insert(0, str(_RTK_EVAL))

extract_historical_anchors = importlib.import_module("extract_historical_anchors")
materialize_source_evidence = importlib.import_module("materialize_source_evidence")
project_source_evidence_semantics = importlib.import_module(
    "project_source_evidence_semantics"
)
tier_source_evidence_v1 = importlib.import_module("tier_source_evidence_v1")


def extract_anchors_for_transition(
    repository: str,
    checkout: Path,
    transition: dict[str, Any],
) -> list[dict[str, Any]]:
    if repository == "fraware/CertifyEdge":
        return list(extract_historical_anchors._certifyedge_anchors(checkout, transition))
    if repository == "SentinelOps-CI/pcs-core":
        rows = list(extract_historical_anchors._pcs_workflow_anchors(checkout, transition))
        rows.extend(
            extract_historical_anchors._pcs_verifier_profile_anchors(checkout, transition)
        )
        return rows
    raise ValueError(f"v0_bridge does not dispatch repository {repository!r}")


def materialize_anchor(
    anchor: dict[str, Any],
    worktree: Path,
    *,
    timeout_sec: int,
    cache: dict[str, Any],
) -> dict[str, Any]:
    family = anchor["family"]
    mse = materialize_source_evidence
    if family == mse.FAMILY_CERTIFYEDGE:
        return mse._materialize_certifyedge(
            anchor, worktree, timeout_sec=timeout_sec, cache=cache
        )
    if family == mse.FAMILY_WORKFLOW:
        return mse._materialize_workflow(
            anchor, worktree, timeout_sec=timeout_sec, cache=cache
        )
    if family == mse.FAMILY_VERIFIER:
        return mse._materialize_verifier(
            anchor, worktree, timeout_sec=timeout_sec, cache=cache
        )
    return mse._base_record(
        anchor,
        mse.STATUS_UNSUPPORTED,
        notes=[f"unsupported anchor family {family}"],
    )


def project_record(row: dict[str, Any]) -> dict[str, Any]:
    return project_source_evidence_semantics.project(row)
