"""Release-ledger construction and provenance-bound authorization (WP-17).

Ledger contents are untrusted declarations until required GitHub Actions runs
are independently resolved by a trusted workflow-run resolver. Structural
validation can run offline, but offline data alone can never mint
``verified_source_sha`` or authorize publication.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping

from ovk.core.project_status import build_project_status

LEDGER_SCHEMA_VERSION = "ovk.release_ledger.v2"

# Workflow names and paths are part of the release authorization contract.
# Keep this single source of truth shared by collectors and verifiers.
REQUIRED_WORKFLOW_PATHS: dict[str, str] = {
    "CI": ".github/workflows/ci.yml",
    "Repro baseline": ".github/workflows/repro-baseline.yml",
    "Native Backends Tier 1": ".github/workflows/native-backends-tier1.yml",
    "Native Backends Tier 1b": ".github/workflows/native-backends-tier1b.yml",
    "FormalPR-Holdout predict": ".github/workflows/holdout-predict.yml",
    "FormalPR-Holdout eval": ".github/workflows/holdout-eval.yml",
    "Consumer Pin Verification": ".github/workflows/consumer-pin-verification.yml",
}
REQUIRED_WORKFLOWS = tuple(REQUIRED_WORKFLOW_PATHS)

WorkflowRunResolver = Callable[[str, int], Mapping[str, Any]]


def _sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _valid_git_sha(value: str) -> bool:
    return len(value) == 40 and all(char in "0123456789abcdef" for char in value.lower())


def _normalize_workflow_run(run: Mapping[str, Any]) -> dict[str, Any]:
    repository = run.get("repository")
    if isinstance(repository, Mapping):
        repository_name = repository.get("full_name")
    else:
        repository_name = repository
    return {
        "workflow": str(run.get("workflowName") or run.get("workflow") or run.get("name") or "unknown"),
        "run_id": run.get("databaseId") or run.get("run_id") or run.get("id"),
        "head_sha": str(run.get("headSha") or run.get("head_sha") or "").lower(),
        "status": str(run.get("status") or ""),
        "conclusion": str(run.get("conclusion") or ""),
        "path": run.get("path"),
        "repository": repository_name,
        "url": run.get("url") or run.get("html_url"),
        "artifact_digest": run.get("artifact_digest"),
        "created_at": run.get("createdAt") or run.get("created_at"),
    }


def _run_sort_key(run: Mapping[str, Any]) -> tuple[str, int]:
    created = str(run.get("created_at") or "")
    run_id = run.get("run_id")
    return created, int(run_id) if isinstance(run_id, int) else -1


def _select_required_runs(
    workflow_evidence: Mapping[str, Any] | None,
    *,
    candidate_sha: str,
) -> list[dict[str, Any]]:
    """Select one attributable run per required workflow.

    Prefer the newest successful run on the candidate SHA. If no successful run
    exists, retain the newest candidate-bound record so verification reports the
    actual failure rather than silently dropping the workflow.
    """
    if not workflow_evidence:
        return []
    normalized = [
        _normalize_workflow_run(run)
        for run in workflow_evidence.get("runs") or []
        if isinstance(run, Mapping)
    ]
    selected: list[dict[str, Any]] = []
    for workflow in REQUIRED_WORKFLOWS:
        candidates = [
            run
            for run in normalized
            if run["workflow"] == workflow and run["head_sha"] == candidate_sha
        ]
        if not candidates:
            continue
        successful = [
            run
            for run in candidates
            if run["status"].lower() in {"", "completed"}
            and run["conclusion"].lower() == "success"
        ]
        chosen = max(successful or candidates, key=_run_sort_key)
        selected.append(chosen)
    return selected


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
    """Construct an unauthorized release-ledger draft from machine evidence."""
    if not _valid_git_sha(candidate_sha) or candidate_sha != candidate_sha.lower():
        raise ValueError("candidate_sha must be lowercase/hex 40-char git SHA")
    if not repository or "/" not in repository:
        raise ValueError("repository must be owner/name")

    lock_path = repo_root / "toolchains" / "backend-tools.lock.json"
    lock_sha = _sha256_file(lock_path)
    if not lock_sha:
        raise FileNotFoundError(f"toolchain lock missing: {lock_path}")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))

    p0: list[str] = []
    if workflow_evidence and workflow_evidence.get("ok") is False:
        p0.append(f"workflow_evidence:{workflow_evidence.get('blocker')}")

    if isinstance(preflight_report, dict):
        if preflight_report.get("ok") is False or preflight_report.get("passed") is False:
            p0.append("release_preflight_failed")
        for item in preflight_report.get("failures") or []:
            p0.append(f"preflight:{item}")

    qual_path = repo_root / ".verification" / "source-profile-qualification.json"
    status = build_project_status(repo_root, candidate_sha=candidate_sha)
    for profile_id, row in (status.get("profile_statuses") or {}).items():
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

    return {
        "schema_version": LEDGER_SCHEMA_VERSION,
        "source": {
            "candidate_sha": candidate_sha,
            "repository": repository,
            "ref": None,
        },
        "required_runs": _select_required_runs(
            workflow_evidence,
            candidate_sha=candidate_sha,
        ),
        "toolchain": {
            "lock_path": "toolchains/backend-tools.lock.json",
            "lock_sha256": lock_sha,
            "isolation_profile": str(lock.get("isolation_profile") or "oci-sandbox.v1"),
            "worker_image_digest": (lock.get("worker_image") or {}).get("digest"),
        },
        "artifacts": artifact_payload,
        "evidence": {
            "verifier_version": "ovk.release_ledger_verifier.v2",
            "bundle_digests": [],
            "profile_qualifications_sha256": _sha256_file(qual_path),
            "p0_blockers": sorted(set(p0)),
            "workflow_provenance": None,
        },
        "consumers": list(consumers or []),
        "holdout": holdout_payload,
        "release_state": {
            "authorized": False,
            "verified_source_sha": None,
            "tag": None,
            "published": False,
            "authorization_reason": "pending_provenance_verification",
        },
    }


def validate_release_ledger_structure(
    ledger: dict[str, Any],
    *,
    repo_root: Path | None = None,
    require_artifacts: bool = False,
    require_consumers: bool = False,
    require_holdout: bool = False,
) -> list[str]:
    """Validate ledger-internal invariants without granting authority."""
    failures: list[str] = []
    if ledger.get("schema_version") != LEDGER_SCHEMA_VERSION:
        failures.append(f"schema_version must be {LEDGER_SCHEMA_VERSION}")

    source = ledger.get("source") if isinstance(ledger.get("source"), dict) else {}
    candidate = str(source.get("candidate_sha") or "").lower()
    repository = str(source.get("repository") or "")
    if not _valid_git_sha(candidate):
        failures.append("source.candidate_sha must be 40-hex")
    if not repository or "/" not in repository:
        failures.append("source.repository must be owner/name")

    run_rows = ledger.get("required_runs") or []
    if not isinstance(run_rows, list):
        failures.append("required_runs must be a list")
        run_rows = []

    by_workflow: dict[str, list[dict[str, Any]]] = {}
    for index, run in enumerate(run_rows):
        if not isinstance(run, dict):
            failures.append(f"required_runs[{index}] not object")
            continue
        workflow = str(run.get("workflow") or "")
        by_workflow.setdefault(workflow, []).append(run)
        if workflow not in REQUIRED_WORKFLOW_PATHS:
            failures.append(f"unexpected_workflow_record:{workflow or '<empty>'}")
        run_id = run.get("run_id")
        if not isinstance(run_id, int) or run_id <= 0:
            failures.append(f"required_runs[{index}] run_id must be positive integer")
        if str(run.get("head_sha") or "").lower() != candidate:
            failures.append(f"required_runs[{index}] head_sha mismatch")
        if str(run.get("conclusion") or "").lower() != "success":
            failures.append(f"required_runs[{index}] conclusion not success")
        status = str(run.get("status") or "").lower()
        if status and status != "completed":
            failures.append(f"required_runs[{index}] status not completed")
        expected_path = REQUIRED_WORKFLOW_PATHS.get(workflow)
        recorded_path = run.get("path")
        if recorded_path is not None and expected_path and str(recorded_path) != expected_path:
            failures.append(f"required_runs[{index}] workflow path mismatch")

    for name in REQUIRED_WORKFLOWS:
        rows = by_workflow.get(name, [])
        if not rows:
            failures.append(f"missing_required_workflow:{name}")
        elif len(rows) != 1:
            failures.append(f"duplicate_required_workflow:{name}")

    toolchain = ledger.get("toolchain") if isinstance(ledger.get("toolchain"), dict) else {}
    if repo_root is not None:
        lock_path = repo_root / str(
            toolchain.get("lock_path") or "toolchains/backend-tools.lock.json"
        )
        actual = _sha256_file(lock_path)
        if actual != toolchain.get("lock_sha256"):
            failures.append("toolchain.lock_sha256 mismatch vs on-disk lock")

    evidence = ledger.get("evidence") if isinstance(ledger.get("evidence"), dict) else {}
    p0 = list(evidence.get("p0_blockers") or [])
    if p0:
        failures.append("p0_blockers_non_empty:" + ",".join(str(item) for item in p0))

    artifacts = ledger.get("artifacts") if isinstance(ledger.get("artifacts"), dict) else {}
    if require_artifacts:
        for key in ("wheel_sha256", "sdist_sha256"):
            digest = artifacts.get(key)
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(char not in "0123456789abcdefABCDEF" for char in digest)
            ):
                failures.append(f"artifacts.{key} required")

    if require_consumers and not (ledger.get("consumers") or []):
        failures.append("consumers_required")

    holdout = ledger.get("holdout") if isinstance(ledger.get("holdout"), dict) else {}
    if require_holdout:
        if str(holdout.get("candidate_source_sha") or "").lower() != candidate:
            failures.append("holdout.candidate_source_sha mismatch")
        for key in ("predictions_sha256", "aggregate_sha256"):
            digest = holdout.get(key)
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(char not in "0123456789abcdefABCDEF" for char in digest)
            ):
                failures.append(f"holdout.{key} required")

    release_state = ledger.get("release_state")
    if not isinstance(release_state, dict):
        failures.append("release_state must be object")
        release_state = {}
    if release_state.get("authorized") is not False:
        failures.append("input ledger must have release_state.authorized=false")
    if release_state.get("verified_source_sha") is not None:
        failures.append("input ledger must not self-assert verified_source_sha")
    if release_state.get("published") is not False:
        failures.append("input ledger must have published=false")
    if release_state.get("tag") is not None:
        failures.append("input ledger must have tag=null")

    # Serialized provenance is audit output only. It is never accepted as the
    # authority input for this verifier.
    if evidence.get("workflow_provenance") not in (None, {}):
        failures.append("input ledger must not self-assert workflow_provenance")

    return failures


def _resolved_run_field(run: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        value = run.get(name)
        if value is not None:
            return value
    return None


def _verify_workflow_provenance(
    ledger: dict[str, Any],
    *,
    workflow_run_resolver: WorkflowRunResolver | None,
) -> tuple[list[str], dict[str, Any] | None]:
    if workflow_run_resolver is None:
        return ["workflow_provenance_not_verified"], None

    source = ledger["source"]
    repository = str(source["repository"])
    candidate = str(source["candidate_sha"]).lower()
    rows = {
        str(run["workflow"]): run
        for run in ledger.get("required_runs") or []
        if isinstance(run, dict) and str(run.get("workflow") or "") in REQUIRED_WORKFLOW_PATHS
    }
    verified_ids: dict[str, int] = {}
    failures: list[str] = []

    for workflow in REQUIRED_WORKFLOWS:
        row = rows.get(workflow)
        if row is None:
            continue
        run_id = row.get("run_id")
        if not isinstance(run_id, int):
            continue
        try:
            resolved = workflow_run_resolver(repository, run_id)
        except Exception as exc:  # trusted resolver boundary; convert transport failure to fail-closed
            failures.append(
                f"workflow_provenance_lookup_failed:{workflow}:{run_id}:{type(exc).__name__}"
            )
            continue
        if not isinstance(resolved, Mapping):
            failures.append(f"workflow_provenance_invalid_response:{workflow}:{run_id}")
            continue

        before = len(failures)
        resolved_id = _resolved_run_field(resolved, "id", "run_id", "databaseId")
        resolved_name = str(
            _resolved_run_field(resolved, "name", "workflow", "workflowName") or ""
        )
        resolved_head = str(
            _resolved_run_field(resolved, "head_sha", "headSha") or ""
        ).lower()
        resolved_status = str(_resolved_run_field(resolved, "status") or "").lower()
        resolved_conclusion = str(
            _resolved_run_field(resolved, "conclusion") or ""
        ).lower()
        resolved_path = str(_resolved_run_field(resolved, "path") or "")

        repo_value = _resolved_run_field(resolved, "repository")
        if isinstance(repo_value, Mapping):
            resolved_repo = str(repo_value.get("full_name") or "")
        else:
            resolved_repo = str(repo_value or "")

        if resolved_id != run_id:
            failures.append(f"workflow_provenance_run_id_mismatch:{workflow}")
        if resolved_name != workflow:
            failures.append(f"workflow_provenance_name_mismatch:{workflow}")
        if resolved_head != candidate:
            failures.append(f"workflow_provenance_head_sha_mismatch:{workflow}")
        if resolved_status != "completed":
            failures.append(f"workflow_provenance_status_not_completed:{workflow}")
        if resolved_conclusion != "success":
            failures.append(f"workflow_provenance_conclusion_not_success:{workflow}")
        if resolved_repo != repository:
            failures.append(f"workflow_provenance_repository_mismatch:{workflow}")
        if resolved_path != REQUIRED_WORKFLOW_PATHS[workflow]:
            failures.append(f"workflow_provenance_path_mismatch:{workflow}")

        # The ledger is an audit record of the exact live run. Do not silently
        # authorize if a caller mutated its declared fields after collection.
        if str(row.get("head_sha") or "").lower() != resolved_head:
            failures.append(f"ledger_run_head_sha_mismatch_live:{workflow}")
        if str(row.get("conclusion") or "").lower() != resolved_conclusion:
            failures.append(f"ledger_run_conclusion_mismatch_live:{workflow}")
        if row.get("path") is not None and str(row.get("path")) != resolved_path:
            failures.append(f"ledger_run_path_mismatch_live:{workflow}")

        if len(failures) == before:
            verified_ids[workflow] = run_id

    if failures:
        return failures, None
    return (
        [],
        {
            "verifier": "github-actions-api.v1",
            "repository": repository,
            "candidate_sha": candidate,
            "verified_run_ids": verified_ids,
        },
    )


def verify_release_ledger(
    ledger: dict[str, Any],
    *,
    repo_root: Path | None = None,
    workflow_run_resolver: WorkflowRunResolver | None = None,
    require_artifacts: bool = False,
    require_consumers: bool = False,
    require_holdout: bool = False,
) -> tuple[bool, list[str], dict[str, Any]]:
    """Authorize only after structural and independently resolved workflow checks."""
    failures = validate_release_ledger_structure(
        ledger,
        repo_root=repo_root,
        require_artifacts=require_artifacts,
        require_consumers=require_consumers,
        require_holdout=require_holdout,
    )

    provenance: dict[str, Any] | None = None
    if not failures:
        provenance_failures, provenance = _verify_workflow_provenance(
            ledger,
            workflow_run_resolver=workflow_run_resolver,
        )
        failures.extend(provenance_failures)

    authorized = not failures
    out = json.loads(json.dumps(ledger))
    out["release_state"] = {
        "authorized": authorized,
        "verified_source_sha": (
            str(out["source"]["candidate_sha"]).lower() if authorized else None
        ),
        "tag": None,
        "published": False,
        "authorization_reason": (
            "github_workflow_provenance_verified"
            if authorized
            else "release_ledger_verification_failed"
        ),
    }
    out["evidence"] = dict(out.get("evidence") or {})
    out["evidence"]["workflow_provenance"] = provenance
    if authorized:
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
    """Bridge collector observations into an unauthorized release-ledger draft."""
    return build_release_ledger(
        repo_root,
        candidate_sha=candidate_sha,
        workflow_evidence=evidence,
        preflight_report=preflight_report,
    )
