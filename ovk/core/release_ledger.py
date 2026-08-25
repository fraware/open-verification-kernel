"""Release ledger construction and offline verification (WP-17).

A ledger authorizes a release only when machine evidence passes. This module
never creates tags or publishes to PyPI.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ovk.core.project_status import build_project_status

LEDGER_SCHEMA_VERSION = "ovk.release_ledger.v1"
REQUIRED_WORKFLOWS = (
    "CI",
    "Native Tier 1",
    "Native Tier 1b",
    "FormalPR-Holdout predict",
    "FormalPR-Holdout eval",
    "Consumer Pin Verification",
)


def _sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_release_ledger(
    repo_root: Path,
    *,
    candidate_sha: str,
    repository: str = "fraware/open-verification-kernel",
    workflow_evidence: dict[str, Any] | None = None,
    preflight_report: dict[str, Any] | None = None,
    consumers: list[dict[str, Any]] | None = None,
    holdout: dict[str, Any] | None = None,
    artifacts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct a ledger from machine evidence only (no manual success fields)."""
    if len(candidate_sha) != 40 or any(c not in "0123456789abcdef" for c in candidate_sha.lower()):
        raise ValueError("candidate_sha must be lowercase/hex 40-char git SHA")
    candidate_sha = candidate_sha.lower()

    lock_path = repo_root / "toolchains" / "backend-tools.lock.json"
    lock_sha = _sha256_file(lock_path)
    if not lock_sha:
        raise FileNotFoundError(f"toolchain lock missing: {lock_path}")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))

    runs: list[dict[str, Any]] = []
    p0: list[str] = []
    if workflow_evidence:
        for run in workflow_evidence.get("runs") or []:
            if not isinstance(run, dict):
                continue
            head = str(run.get("headSha") or run.get("head_sha") or "")
            conclusion = str(run.get("conclusion") or "")
            runs.append(
                {
                    "workflow": str(run.get("workflowName") or run.get("workflow") or "unknown"),
                    "run_id": run.get("databaseId") or run.get("run_id"),
                    "head_sha": head.lower(),
                    "conclusion": conclusion,
                    "url": run.get("url"),
                    "artifact_digest": run.get("artifact_digest"),
                }
            )
        if workflow_evidence.get("ok") is False:
            p0.append(f"workflow_evidence:{workflow_evidence.get('blocker')}")

    # Preflight contributes evidence digests / blockers, never a hand-typed pass bit.
    if isinstance(preflight_report, dict):
        if preflight_report.get("ok") is False or preflight_report.get("passed") is False:
            p0.append("release_preflight_failed")
        for item in preflight_report.get("failures") or []:
            p0.append(f"preflight:{item}")

    qual_path = repo_root / ".verification" / "source-profile-qualification.json"
    status = build_project_status(repo_root, candidate_sha=candidate_sha)
    for profile_id, row in (status.get("profile_statuses") or {}).items():
        # Incomplete qualification is a P1 gap, not automatically a P0 blocker unless
        # release_state claims final without bounded profiles.
        if row.get("maturity") == "externally_calibrated_strict":
            p0.append(f"illegal_local_external_calibration:{profile_id}")

    holdout_payload = holdout or {
        "candidate_source_sha": candidate_sha,
        "predictions_sha256": None,
        "aggregate_sha256": None,
        "holdout_tag": None,
    }
    artifact_payload = artifacts or {
        "wheel_sha256": None,
        "sdist_sha256": None,
        "sbom_sha256": None,
        "sigstore_summary_sha256": None,
    }

    # Authorization is computed by the verifier; builder leaves authorized=false
    # until verify_release_ledger promotes it.
    ledger = {
        "schema_version": LEDGER_SCHEMA_VERSION,
        "source": {
            "candidate_sha": candidate_sha,
            "repository": repository,
            "ref": None,
        },
        "required_runs": runs,
        "toolchain": {
            "lock_path": "toolchains/backend-tools.lock.json",
            "lock_sha256": lock_sha,
            "isolation_profile": str(lock.get("isolation_profile") or "oci-sandbox.v1"),
            "worker_image_digest": (lock.get("worker_image") or {}).get("digest"),
        },
        "artifacts": artifact_payload,
        "evidence": {
            "verifier_version": "ovk.evidence_verifier.v3",
            "bundle_digests": [],
            "profile_qualifications_sha256": _sha256_file(qual_path),
            "p0_blockers": sorted(set(p0)),
        },
        "consumers": list(consumers or []),
        "holdout": holdout_payload,
        "release_state": {
            "authorized": False,
            "verified_source_sha": None,
            "tag": None,
            "published": False,
            "authorization_reason": "pending_offline_verification",
        },
    }
    return ledger


def verify_release_ledger(
    ledger: dict[str, Any],
    *,
    repo_root: Path | None = None,
    require_artifacts: bool = False,
    require_consumers: bool = False,
    require_holdout: bool = False,
) -> tuple[bool, list[str], dict[str, Any]]:
    """Offline ledger verifier. Returns (ok, failures, authorized_ledger)."""
    failures: list[str] = []
    if ledger.get("schema_version") != LEDGER_SCHEMA_VERSION:
        failures.append("schema_version must be ovk.release_ledger.v1")

    source = ledger.get("source") if isinstance(ledger.get("source"), dict) else {}
    candidate = str(source.get("candidate_sha") or "")
    if len(candidate) != 40:
        failures.append("source.candidate_sha must be 40-hex")

    for index, run in enumerate(ledger.get("required_runs") or []):
        if not isinstance(run, dict):
            failures.append(f"required_runs[{index}] not object")
            continue
        if str(run.get("head_sha") or "").lower() != candidate.lower():
            failures.append(f"required_runs[{index}] head_sha mismatch")
        if str(run.get("conclusion") or "").lower() != "success":
            failures.append(f"required_runs[{index}] conclusion not success")

    observed = {str(run.get("workflow")) for run in (ledger.get("required_runs") or []) if isinstance(run, dict)}
    for name in REQUIRED_WORKFLOWS:
        if name not in observed:
            failures.append(f"missing_required_workflow:{name}")

    toolchain = ledger.get("toolchain") if isinstance(ledger.get("toolchain"), dict) else {}
    if repo_root is not None:
        lock_path = repo_root / str(toolchain.get("lock_path") or "toolchains/backend-tools.lock.json")
        actual = _sha256_file(lock_path)
        if actual != toolchain.get("lock_sha256"):
            failures.append("toolchain.lock_sha256 mismatch vs on-disk lock")

    evidence = ledger.get("evidence") if isinstance(ledger.get("evidence"), dict) else {}
    p0 = list(evidence.get("p0_blockers") or [])
    if p0:
        failures.append("p0_blockers_non_empty:" + ",".join(p0))

    artifacts = ledger.get("artifacts") if isinstance(ledger.get("artifacts"), dict) else {}
    if require_artifacts:
        for key in ("wheel_sha256", "sdist_sha256"):
            digest = artifacts.get(key)
            if not isinstance(digest, str) or len(digest) != 64:
                failures.append(f"artifacts.{key} required")

    if require_consumers and not (ledger.get("consumers") or []):
        failures.append("consumers_required")

    holdout = ledger.get("holdout") if isinstance(ledger.get("holdout"), dict) else {}
    if require_holdout:
        if holdout.get("candidate_source_sha") != candidate:
            failures.append("holdout.candidate_source_sha mismatch")
        if not holdout.get("predictions_sha256") or not holdout.get("aggregate_sha256"):
            failures.append("holdout digests required")

    release_state = dict(ledger.get("release_state") or {})
    # Fail closed: published/tag must remain false/null until an external publish step
    # that this verifier does not perform.
    if release_state.get("published") is True:
        failures.append("ledger must not claim published=true inside offline verifier")
    if release_state.get("tag"):
        failures.append("ledger must not embed a created tag before authorization")

    authorized = not failures
    out = json.loads(json.dumps(ledger))
    out["release_state"] = {
        "authorized": authorized,
        "verified_source_sha": candidate if authorized else None,
        "tag": None,
        "published": False,
        "authorization_reason": "offline_verification_passed" if authorized else "offline_verification_failed",
    }
    if authorized:
        out["evidence"] = dict(out.get("evidence") or {})
        out["evidence"]["p0_blockers"] = []
    return authorized, failures, out


def write_release_ledger(repo_root: Path, ledger: dict[str, Any]) -> Path:
    path = repo_root / ".verification" / "release-ledger.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def ledger_from_collect_workflow_evidence(
    repo_root: Path,
    *,
    evidence: dict[str, Any],
    candidate_sha: str,
    preflight_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Bridge scripts/collect_workflow_evidence.py output into a ledger draft."""
    return build_release_ledger(
        repo_root,
        candidate_sha=candidate_sha,
        workflow_evidence=evidence,
        preflight_report=preflight_report,
    )
