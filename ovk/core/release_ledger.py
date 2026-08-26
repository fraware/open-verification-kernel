"""Release-ledger construction and provenance-bound authorization (WP-17).

Ledger contents are untrusted declarations until required GitHub Actions runs,
their candidate-bound artifacts, and publishable distributions are independently
resolved. Structural validation can run offline, but offline data alone can
never mint ``verified_source_sha`` or authorize publication.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping

from ovk.core.project_status import build_project_status

LEDGER_SCHEMA_VERSION = "ovk.release_ledger.v2"

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

REQUIRED_CONSUMER_REPOSITORIES = (
    "fraware/ovk-consumer-fastapi-terraform",
    "fraware/ovk-consumer-express-actions",
)

WorkflowRunResolver = Callable[[str, int], Mapping[str, Any]]
WorkflowArtifactResolver = Callable[[str, int, str], Mapping[str, Any]]
ReleaseArtifactResolver = Callable[[], Mapping[str, Any]]


def _sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _valid_git_sha(value: str) -> bool:
    return len(value) == 40 and all(char in "0123456789abcdef" for char in value.lower())


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value.lower())
    )


def _normalized_optional_digest(value: Any) -> str | None:
    if value is None:
        return None
    return str(value).lower() if _valid_sha256(value) else str(value)


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
    """Select one attributable run per required workflow."""
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
        selected.append(max(successful or candidates, key=_run_sort_key))
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
    """Construct an unauthorized draft. No caller-supplied field grants authority."""
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
        p0.extend(f"preflight:{item}" for item in (preflight_report.get("failures") or []))

    qual_path = repo_root / ".verification" / "source-profile-qualification.json"
    status = build_project_status(repo_root, candidate_sha=candidate_sha)
    for profile_id, row in (status.get("profile_statuses") or {}).items():
        if row.get("maturity") == "externally_calibrated_strict":
            p0.append(f"illegal_local_external_calibration:{profile_id}")

    holdout_payload = holdout or {
        "candidate_source_sha": candidate_sha,
        "predictions_sha256": None,
        "aggregate_sha256": None,
        "holdout_asset_sha256": None,
        "holdout_tag": None,
    }
    artifact_payload = {
        "wheel_filename": None,
        "wheel_sha256": None,
        "sdist_filename": None,
        "sdist_sha256": None,
        "sbom_sha256": None,
        "sigstore_summary_sha256": None,
        **(artifacts or {}),
    }

    return {
        "schema_version": LEDGER_SCHEMA_VERSION,
        "source": {
            "candidate_sha": candidate_sha,
            "repository": repository,
            "ref": None,
        },
        "required_runs": _select_required_runs(workflow_evidence, candidate_sha=candidate_sha),
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
            "workflow_artifact_provenance": None,
            "release_artifact_provenance": None,
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


def _schema_failures(ledger: dict[str, Any], repo_root: Path | None) -> list[str]:
    if repo_root is None:
        return []
    schema_path = repo_root / "schemas" / "release.ledger.schema.json"
    if not schema_path.is_file():
        return []
    from ovk.core.schema_validation import validate_against_schema

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    report = validate_against_schema(ledger, schema)
    return [
        "release_ledger_schema:"
        + ("/".join(str(part) for part in issue.path) or "$")
        + ":"
        + issue.message
        for issue in report.issues
    ]


def validate_release_ledger_structure(
    ledger: dict[str, Any],
    *,
    repo_root: Path | None = None,
    require_artifacts: bool = False,
    require_consumers: bool = False,
    require_holdout: bool = False,
) -> list[str]:
    """Validate ledger-internal invariants without granting authority."""
    failures = _schema_failures(ledger, repo_root)
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
        lock_path = repo_root / str(toolchain.get("lock_path") or "toolchains/backend-tools.lock.json")
        if _sha256_file(lock_path) != toolchain.get("lock_sha256"):
            failures.append("toolchain.lock_sha256 mismatch vs on-disk lock")

    evidence = ledger.get("evidence") if isinstance(ledger.get("evidence"), dict) else {}
    p0 = list(evidence.get("p0_blockers") or [])
    if p0:
        failures.append("p0_blockers_non_empty:" + ",".join(str(item) for item in p0))

    artifacts = ledger.get("artifacts") if isinstance(ledger.get("artifacts"), dict) else {}
    for key in ("wheel_sha256", "sdist_sha256", "sbom_sha256", "sigstore_summary_sha256"):
        value = artifacts.get(key)
        if value is not None and not _valid_sha256(value):
            failures.append(f"artifacts.{key} malformed")
    for key in ("wheel_filename", "sdist_filename"):
        value = artifacts.get(key)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            failures.append(f"artifacts.{key} malformed")
    if require_artifacts:
        for key in ("wheel_sha256", "sdist_sha256"):
            if not _valid_sha256(artifacts.get(key)):
                failures.append(f"artifacts.{key} required")
        for key in ("wheel_filename", "sdist_filename"):
            if not isinstance(artifacts.get(key), str) or not artifacts[key].strip():
                failures.append(f"artifacts.{key} required")

    consumers = ledger.get("consumers")
    if consumers is not None and not isinstance(consumers, list):
        failures.append("consumers must be a list")
    if require_consumers and not (consumers or []):
        failures.append("consumers_required")

    holdout = ledger.get("holdout") if isinstance(ledger.get("holdout"), dict) else {}
    for key in ("predictions_sha256", "aggregate_sha256", "holdout_asset_sha256"):
        value = holdout.get(key)
        if value is not None and not _valid_sha256(value):
            failures.append(f"holdout.{key} malformed")
    if require_holdout:
        if str(holdout.get("candidate_source_sha") or "").lower() != candidate:
            failures.append("holdout.candidate_source_sha mismatch")
        for key in ("predictions_sha256", "aggregate_sha256", "holdout_asset_sha256"):
            if not _valid_sha256(holdout.get(key)):
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

    for key in (
        "workflow_provenance",
        "workflow_artifact_provenance",
        "release_artifact_provenance",
    ):
        if evidence.get(key) not in (None, {}):
            failures.append(f"input ledger must not self-assert {key}")

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
        except Exception as exc:
            failures.append(
                f"workflow_provenance_lookup_failed:{workflow}:{run_id}:{type(exc).__name__}"
            )
            continue
        if not isinstance(resolved, Mapping):
            failures.append(f"workflow_provenance_invalid_response:{workflow}:{run_id}")
            continue

        before = len(failures)
        resolved_id = _resolved_run_field(resolved, "id", "run_id", "databaseId")
        resolved_name = str(_resolved_run_field(resolved, "name", "workflow", "workflowName") or "")
        resolved_head = str(_resolved_run_field(resolved, "head_sha", "headSha") or "").lower()
        resolved_status = str(_resolved_run_field(resolved, "status") or "").lower()
        resolved_conclusion = str(_resolved_run_field(resolved, "conclusion") or "").lower()
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
    return [], {
        "verifier": "github-actions-api.v1",
        "repository": repository,
        "candidate_sha": candidate,
        "verified_run_ids": verified_ids,
    }


def _preclaim_mismatch(
    failures: list[str],
    *,
    name: str,
    claimed: Any,
    observed: Any,
) -> None:
    if claimed is not None and claimed != observed:
        failures.append(f"{name}_mismatch_live")


def _normalize_consumer(
    payload: Mapping[str, Any],
    *,
    candidate: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    failures: list[str] = []
    repository = str(payload.get("consumer_repository") or "")
    consumer_ref = str(payload.get("consumer_ref") or "")
    consumer_source_sha = str(payload.get("consumer_source_sha") or "").lower()
    ovk_candidate_sha = str(payload.get("ovk_candidate_sha") or "").lower()
    pin = str(payload.get("pin") or "")
    workflow_digests = payload.get("workflow_digests")

    if payload.get("schema_version") != "ovk.consumer_pin_evidence.v1":
        failures.append(f"consumer_evidence_schema:{repository or '<unknown>'}")
    if repository not in REQUIRED_CONSUMER_REPOSITORIES:
        failures.append(f"consumer_repository_unexpected:{repository or '<empty>'}")
    if not consumer_ref:
        failures.append(f"consumer_ref_missing:{repository or '<unknown>'}")
    if not _valid_git_sha(consumer_source_sha):
        failures.append(f"consumer_source_sha_invalid:{repository or '<unknown>'}")
    if ovk_candidate_sha != candidate:
        failures.append(f"consumer_candidate_sha_mismatch:{repository or '<unknown>'}")
    if pin != f"fraware/open-verification-kernel@{candidate}":
        failures.append(f"consumer_pin_mismatch:{repository or '<unknown>'}")

    normalized_digests: list[dict[str, str]] = []
    seen_paths: set[str] = set()
    if not isinstance(workflow_digests, list) or not workflow_digests:
        failures.append(f"consumer_workflow_digests_missing:{repository or '<unknown>'}")
    else:
        for item in workflow_digests:
            if not isinstance(item, Mapping):
                failures.append(f"consumer_workflow_digest_invalid:{repository or '<unknown>'}")
                continue
            path = str(item.get("path") or "")
            digest = item.get("sha256")
            if not path or path in seen_paths or not _valid_sha256(digest):
                failures.append(f"consumer_workflow_digest_invalid:{repository or '<unknown>'}")
                continue
            seen_paths.add(path)
            normalized_digests.append({"path": path, "sha256": str(digest).lower()})

    if failures:
        return None, failures
    return {
        "schema_version": "ovk.consumer_pin_evidence.v1",
        "consumer_repository": repository,
        "consumer_ref": consumer_ref,
        "consumer_source_sha": consumer_source_sha,
        "ovk_candidate_sha": candidate,
        "pin": pin,
        "workflow_digests": sorted(normalized_digests, key=lambda item: item["path"]),
    }, []


def _verify_workflow_artifacts(
    ledger: dict[str, Any],
    *,
    workflow_artifact_resolver: WorkflowArtifactResolver | None,
    require_consumers: bool,
    require_holdout: bool,
) -> tuple[list[str], dict[str, Any] | None, dict[str, Any], list[dict[str, Any]]]:
    holdout_out = json.loads(json.dumps(ledger.get("holdout") or {}))
    consumers_out = json.loads(json.dumps(ledger.get("consumers") or []))
    if not require_consumers and not require_holdout:
        return [], None, holdout_out, consumers_out
    if workflow_artifact_resolver is None:
        return ["workflow_artifact_provenance_not_verified"], None, holdout_out, consumers_out

    source = ledger["source"]
    repository = str(source["repository"])
    candidate = str(source["candidate_sha"]).lower()
    rows = {
        str(run["workflow"]): run
        for run in ledger.get("required_runs") or []
        if isinstance(run, dict)
    }
    failures: list[str] = []
    provenance: dict[str, Any] = {
        "verifier": "github-actions-artifacts.v1",
        "repository": repository,
        "candidate_sha": candidate,
        "holdout": None,
        "consumers": None,
    }

    def resolve(workflow: str) -> Mapping[str, Any] | None:
        row = rows.get(workflow)
        run_id = row.get("run_id") if isinstance(row, dict) else None
        if not isinstance(run_id, int):
            failures.append(f"workflow_artifact_missing_run_id:{workflow}")
            return None
        try:
            payload = workflow_artifact_resolver(repository, run_id, workflow)
        except Exception as exc:
            failures.append(
                f"workflow_artifact_lookup_failed:{workflow}:{run_id}:{type(exc).__name__}"
            )
            return None
        if not isinstance(payload, Mapping):
            failures.append(f"workflow_artifact_invalid_response:{workflow}:{run_id}")
            return None
        return payload

    if require_holdout:
        predict = resolve("FormalPR-Holdout predict")
        aggregate = resolve("FormalPR-Holdout eval")
        if predict is not None:
            pred_sha = predict.get("predictions_sha256")
            manifest_file_sha = predict.get("manifest_sha256")
            pred_candidate = str(predict.get("candidate_source_sha") or "").lower()
            manifest_sha = predict.get("manifest_predictions_sha256")
            manifest_candidate = str(predict.get("manifest_candidate_source_sha") or "").lower()
            if predict.get("kind") != "holdout_predictions.v1":
                failures.append("holdout_predictions_kind_invalid")
            if predict.get("artifact_name") != "formalpr-holdout-predictions":
                failures.append("holdout_predictions_artifact_name_invalid")
            if not _valid_sha256(pred_sha):
                failures.append("holdout_predictions_sha256_invalid")
            if not _valid_sha256(manifest_file_sha):
                failures.append("holdout_prediction_manifest_sha256_invalid")
            if pred_candidate != candidate:
                failures.append("holdout_predictions_candidate_mismatch")
            if manifest_candidate != candidate:
                failures.append("holdout_manifest_candidate_mismatch")
            if manifest_sha != pred_sha:
                failures.append("holdout_manifest_predictions_digest_mismatch")
            if predict.get("label_free") is not True:
                failures.append("holdout_predictions_not_label_free")
            if predict.get("verified_source_sha_present") is not False:
                failures.append("holdout_predictions_illegal_verified_source_sha")
        else:
            pred_sha = None
            manifest_file_sha = None

        if aggregate is not None:
            agg_sha = aggregate.get("aggregate_sha256")
            agg_candidate = str(aggregate.get("candidate_source_sha") or "").lower()
            agg_predictions_sha = aggregate.get("predictions_sha256")
            holdout_asset_sha = aggregate.get("holdout_asset_sha256")
            holdout_tag = str(aggregate.get("holdout_tag") or "")
            if aggregate.get("kind") != "holdout_aggregate.v1":
                failures.append("holdout_aggregate_kind_invalid")
            if aggregate.get("artifact_name") != "formalpr-holdout-aggregates":
                failures.append("holdout_aggregate_artifact_name_invalid")
            if not _valid_sha256(agg_sha):
                failures.append("holdout_aggregate_sha256_invalid")
            if agg_candidate != candidate:
                failures.append("holdout_aggregate_candidate_mismatch")
            if not _valid_sha256(agg_predictions_sha):
                failures.append("holdout_aggregate_predictions_sha256_invalid")
            if pred_sha is not None and agg_predictions_sha != pred_sha:
                failures.append("holdout_aggregate_predictions_digest_mismatch")
            if not _valid_sha256(holdout_asset_sha):
                failures.append("holdout_asset_sha256_invalid")
            if not holdout_tag:
                failures.append("holdout_tag_missing")
            if aggregate.get("schema_valid") is not True:
                failures.append("holdout_aggregate_schema_invalid")
            if aggregate.get("verified_source_sha_present") is not False:
                failures.append("holdout_aggregate_illegal_verified_source_sha")
        else:
            agg_sha = None
            agg_predictions_sha = None
            holdout_asset_sha = None
            holdout_tag = ""

        if predict is not None and aggregate is not None and _valid_sha256(pred_sha) and _valid_sha256(agg_sha):
            claimed = ledger.get("holdout") if isinstance(ledger.get("holdout"), dict) else {}
            _preclaim_mismatch(
                failures,
                name="holdout.candidate_source_sha",
                claimed=(str(claimed.get("candidate_source_sha")).lower() if claimed.get("candidate_source_sha") else None),
                observed=candidate,
            )
            _preclaim_mismatch(
                failures,
                name="holdout.predictions_sha256",
                claimed=_normalized_optional_digest(claimed.get("predictions_sha256")),
                observed=(str(pred_sha).lower() if _valid_sha256(pred_sha) else pred_sha),
            )
            _preclaim_mismatch(
                failures,
                name="holdout.aggregate_sha256",
                claimed=_normalized_optional_digest(claimed.get("aggregate_sha256")),
                observed=(str(agg_sha).lower() if _valid_sha256(agg_sha) else agg_sha),
            )
            _preclaim_mismatch(
                failures,
                name="holdout.holdout_asset_sha256",
                claimed=_normalized_optional_digest(claimed.get("holdout_asset_sha256")),
                observed=(
                    str(holdout_asset_sha).lower()
                    if _valid_sha256(holdout_asset_sha)
                    else holdout_asset_sha
                ),
            )
            _preclaim_mismatch(
                failures,
                name="holdout.holdout_tag",
                claimed=claimed.get("holdout_tag"),
                observed=holdout_tag,
            )
            holdout_out = {
                "candidate_source_sha": candidate,
                "predictions_sha256": str(pred_sha).lower(),
                "aggregate_sha256": str(agg_sha).lower(),
                "holdout_asset_sha256": str(holdout_asset_sha).lower(),
                "holdout_tag": holdout_tag,
            }
            provenance["holdout"] = {
                "predict_run_id": rows["FormalPR-Holdout predict"]["run_id"],
                "eval_run_id": rows["FormalPR-Holdout eval"]["run_id"],
                "predictions_sha256": str(pred_sha).lower(),
                "aggregate_predictions_sha256": str(agg_predictions_sha).lower(),
                "prediction_manifest_sha256": str(manifest_file_sha).lower(),
                "aggregate_sha256": str(agg_sha).lower(),
                "holdout_asset_sha256": str(holdout_asset_sha).lower(),
                "holdout_tag": holdout_tag,
            }

    if require_consumers:
        resolved = resolve("Consumer Pin Verification")
        normalized_live: list[dict[str, Any]] = []
        evidence_digests: dict[str, str] = {}
        if resolved is not None:
            if resolved.get("kind") != "consumer_pin_evidence.v1":
                failures.append("consumer_artifact_kind_invalid")
            if set(resolved.get("artifact_names") or []) != {"consumer-pin-0", "consumer-pin-1"}:
                failures.append("consumer_artifact_name_set_invalid")
            raw_consumers = resolved.get("consumers")
            if not isinstance(raw_consumers, list):
                failures.append("consumer_artifacts_missing")
            else:
                for item in raw_consumers:
                    if not isinstance(item, Mapping):
                        failures.append("consumer_artifact_invalid")
                        continue
                    normalized, item_failures = _normalize_consumer(item, candidate=candidate)
                    failures.extend(item_failures)
                    if normalized is not None:
                        normalized_live.append(normalized)
                raw_digests = resolved.get("evidence_file_sha256")
                if isinstance(raw_digests, Mapping):
                    for repo_name, digest in raw_digests.items():
                        if isinstance(repo_name, str) and _valid_sha256(digest):
                            evidence_digests[repo_name] = str(digest).lower()

        live_by_repo = {item["consumer_repository"]: item for item in normalized_live}
        if len(live_by_repo) != len(normalized_live):
            failures.append("consumer_artifacts_duplicate_repository")
        if set(live_by_repo) != set(REQUIRED_CONSUMER_REPOSITORIES):
            failures.append("consumer_artifacts_required_repository_set_mismatch")
        if set(evidence_digests) != set(REQUIRED_CONSUMER_REPOSITORIES):
            failures.append("consumer_evidence_file_digest_set_mismatch")

        claimed_consumers = ledger.get("consumers") or []
        if claimed_consumers:
            claimed_normalized: list[dict[str, Any]] = []
            if not isinstance(claimed_consumers, list):
                failures.append("consumer_preclaims_invalid")
            else:
                for item in claimed_consumers:
                    if not isinstance(item, Mapping):
                        failures.append("consumer_preclaim_invalid")
                        continue
                    normalized, item_failures = _normalize_consumer(item, candidate=candidate)
                    failures.extend("ledger_" + failure for failure in item_failures)
                    if normalized is not None:
                        claimed_normalized.append(normalized)
            claimed_by_repo = {item["consumer_repository"]: item for item in claimed_normalized}
            if claimed_by_repo != live_by_repo:
                failures.append("consumer_preclaims_mismatch_live")

        if set(live_by_repo) == set(REQUIRED_CONSUMER_REPOSITORIES):
            consumers_out = [live_by_repo[name] for name in REQUIRED_CONSUMER_REPOSITORIES]
            provenance["consumers"] = {
                "run_id": rows["Consumer Pin Verification"]["run_id"],
                "repositories": {
                    name: {
                        "consumer_source_sha": live_by_repo[name]["consumer_source_sha"],
                        "evidence_file_sha256": evidence_digests.get(name),
                    }
                    for name in REQUIRED_CONSUMER_REPOSITORIES
                },
            }

    if failures:
        return failures, None, holdout_out, consumers_out
    return [], provenance, holdout_out, consumers_out


def _verify_release_artifacts(
    ledger: dict[str, Any],
    *,
    release_artifact_resolver: ReleaseArtifactResolver | None,
    require_artifacts: bool,
) -> tuple[list[str], dict[str, Any] | None, dict[str, Any]]:
    artifacts_out = json.loads(json.dumps(ledger.get("artifacts") or {}))
    if not require_artifacts:
        return [], None, artifacts_out
    if release_artifact_resolver is None:
        return ["release_artifacts_not_verified"], None, artifacts_out
    try:
        resolved = release_artifact_resolver()
    except Exception as exc:
        return [f"release_artifact_lookup_failed:{type(exc).__name__}"], None, artifacts_out
    if not isinstance(resolved, Mapping):
        return ["release_artifact_invalid_response"], None, artifacts_out

    failures: list[str] = []
    wheel = resolved.get("wheel")
    sdist = resolved.get("sdist")
    if not isinstance(wheel, Mapping) or not isinstance(sdist, Mapping):
        return ["release_artifact_response_missing_wheel_or_sdist"], None, artifacts_out

    wheel_name = str(wheel.get("filename") or "")
    wheel_sha = wheel.get("sha256")
    sdist_name = str(sdist.get("filename") or "")
    sdist_sha = sdist.get("sha256")
    if not wheel_name.endswith(".whl"):
        failures.append("release_wheel_filename_invalid")
    if not _valid_sha256(wheel_sha):
        failures.append("release_wheel_sha256_invalid")
    if not sdist_name.endswith(".tar.gz"):
        failures.append("release_sdist_filename_invalid")
    if not _valid_sha256(sdist_sha):
        failures.append("release_sdist_sha256_invalid")

    claimed = ledger.get("artifacts") if isinstance(ledger.get("artifacts"), dict) else {}
    for name, observed in (
        ("artifacts.wheel_filename", wheel_name),
        ("artifacts.wheel_sha256", wheel_sha),
        ("artifacts.sdist_filename", sdist_name),
        ("artifacts.sdist_sha256", sdist_sha),
    ):
        key = name.split(".", 1)[1]
        claimed_value = claimed.get(key)
        if key.endswith("_sha256"):
            claimed_value = _normalized_optional_digest(claimed_value)
            observed = str(observed).lower() if _valid_sha256(observed) else observed
        _preclaim_mismatch(
            failures,
            name=name,
            claimed=claimed_value,
            observed=observed,
        )

    if failures:
        return failures, None, artifacts_out

    artifacts_out = {
        **claimed,
        "wheel_filename": wheel_name,
        "wheel_sha256": str(wheel_sha).lower(),
        "sdist_filename": sdist_name,
        "sdist_sha256": str(sdist_sha).lower(),
    }
    provenance = {
        "verifier": "local-dist-sha256.v1",
        "wheel": {"filename": wheel_name, "sha256": str(wheel_sha).lower()},
        "sdist": {"filename": sdist_name, "sha256": str(sdist_sha).lower()},
    }
    return [], provenance, artifacts_out


def verify_release_ledger(
    ledger: dict[str, Any],
    *,
    repo_root: Path | None = None,
    workflow_run_resolver: WorkflowRunResolver | None = None,
    workflow_artifact_resolver: WorkflowArtifactResolver | None = None,
    release_artifact_resolver: ReleaseArtifactResolver | None = None,
    expected_repository: str | None = None,
    expected_candidate_sha: str | None = None,
    require_artifacts: bool = True,
    require_consumers: bool = True,
    require_holdout: bool = True,
) -> tuple[bool, list[str], dict[str, Any]]:
    """Verify provenance; only the full evidence scope may authorize a release.

    Callers may explicitly disable dimensions for diagnostics, but partial
    verification can never set ``release_state.authorized`` or
    ``verified_source_sha``.
    """
    failures = validate_release_ledger_structure(ledger, repo_root=repo_root)

    source = ledger.get("source") if isinstance(ledger.get("source"), dict) else {}
    if expected_repository is not None and source.get("repository") != expected_repository:
        failures.append("source.repository mismatch vs expected repository")
    if expected_candidate_sha is not None:
        expected = expected_candidate_sha.lower()
        if not _valid_git_sha(expected) or str(source.get("candidate_sha") or "").lower() != expected:
            failures.append("source.candidate_sha mismatch vs expected candidate")

    workflow_provenance: dict[str, Any] | None = None
    workflow_artifact_provenance: dict[str, Any] | None = None
    release_artifact_provenance: dict[str, Any] | None = None
    holdout_out = json.loads(json.dumps(ledger.get("holdout") or {}))
    consumers_out = json.loads(json.dumps(ledger.get("consumers") or []))
    artifacts_out = json.loads(json.dumps(ledger.get("artifacts") or {}))

    if not failures:
        provenance_failures, workflow_provenance = _verify_workflow_provenance(
            ledger, workflow_run_resolver=workflow_run_resolver
        )
        failures.extend(provenance_failures)

    if not failures:
        artifact_failures, workflow_artifact_provenance, holdout_out, consumers_out = (
            _verify_workflow_artifacts(
                ledger,
                workflow_artifact_resolver=workflow_artifact_resolver,
                require_consumers=require_consumers,
                require_holdout=require_holdout,
            )
        )
        failures.extend(artifact_failures)

    if not failures:
        release_failures, release_artifact_provenance, artifacts_out = _verify_release_artifacts(
            ledger,
            release_artifact_resolver=release_artifact_resolver,
            require_artifacts=require_artifacts,
        )
        failures.extend(release_failures)

    verification_ok = not failures
    full_authorization_scope = bool(require_artifacts and require_consumers and require_holdout)
    authorized = verification_ok and full_authorization_scope
    out = json.loads(json.dumps(ledger))
    out["holdout"] = holdout_out
    out["consumers"] = consumers_out
    out["artifacts"] = artifacts_out
    out["release_state"] = {
        "authorized": authorized,
        "verified_source_sha": (
            str(out["source"]["candidate_sha"]).lower() if authorized else None
        ),
        "tag": None,
        "published": False,
        "authorization_reason": (
            "github_workflow_artifact_and_distribution_provenance_verified"
            if authorized
            else (
                "partial_provenance_verified_not_release_authorized"
                if verification_ok
                else "release_ledger_verification_failed"
            )
        ),
    }
    out["evidence"] = dict(out.get("evidence") or {})
    out["evidence"]["workflow_provenance"] = workflow_provenance
    out["evidence"]["workflow_artifact_provenance"] = workflow_artifact_provenance
    out["evidence"]["release_artifact_provenance"] = release_artifact_provenance
    if authorized:
        out["evidence"]["p0_blockers"] = []

    if authorized:
        output_schema_failures = _schema_failures(out, repo_root)
        if output_schema_failures:
            failures.extend(output_schema_failures)
            authorized = False
            out["release_state"] = {
                "authorized": False,
                "verified_source_sha": None,
                "tag": None,
                "published": False,
                "authorization_reason": "release_ledger_output_schema_failed",
            }

    return authorized if full_authorization_scope else verification_ok, failures, out


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
