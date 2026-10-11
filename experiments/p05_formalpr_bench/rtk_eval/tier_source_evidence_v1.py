"""Classify RTK source evidence into replay-verified and committed-attestation tiers.

This is a pre-outcome amendment applied only after the frozen v0 source materializer
exposed historical-environment underdetermination. It never executes RTK, never runs a
target-revision validator, and never reads oracle labels.

Tier A / REPLAY_VERIFIED:
    Preserve v0 SOURCE_ACCEPTED records exactly.

Tier B / COMMITTED_NATIVE_ATTESTATION:
    For PCS_WORKFLOW_PROFILE records that are OPERATIONAL_FAILURE solely because exact
    source-runtime replay is unavailable, accept a weaker source-evidence premise only
    where the source revision itself contains a repository-native positive release:
    a ReleaseChainValidationResult.v0 plus the workflow-native certificate that the
    release binds. Both must satisfy the frozen structural predicate below.

The weaker tier does not prove that the historical validator was sound or that its
runtime environment has been reproduced. It records a contemporaneous committed
repository-native validation attestation. Analyses must remain stratified by tier.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any, Iterator


FAMILY_WORKFLOW = "PCS_WORKFLOW_PROFILE"

STATUS_REPLAY = "SOURCE_ACCEPTED"
STATUS_ATTESTED = "SOURCE_ATTESTED"
STATUS_OPERATIONAL = "OPERATIONAL_FAILURE"

CLASS_REPLAY = "REPLAY_VERIFIED"
CLASS_ATTESTED = "COMMITTED_NATIVE_ATTESTATION"

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")

_NATIVE_CERTIFICATE_FILES: dict[str, tuple[str, ...]] = {
    "agent_tool_use.safety_v0": (
        "tool_use_certificate.valid.json",
        "tool_use_certificate.json",
    ),
    "labtrust.qc_release_v0.1": ("trace_certificate.json",),
    "scientific_computation.reproducibility_v0": ("computation_witness.json",),
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _typed_digest(tag: str, value: Any) -> str:
    return _sha256(tag.encode("utf-8") + b"\x00" + _canonical_bytes(value))


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"git -C {repo} {' '.join(args)} failed ({proc.returncode}): "
            + proc.stderr.decode("utf-8", errors="replace")
        )
    return proc


@contextmanager
def _source_worktree(repo: Path, source_sha: str, root: Path) -> Iterator[Path]:
    worktree = root / source_sha
    if worktree.exists():
        shutil.rmtree(worktree)
    _git(repo, "worktree", "add", "--detach", "--force", str(worktree), source_sha)
    try:
        yield worktree
    finally:
        subprocess.run(
            ["git", "-C", str(repo), "worktree", "remove", "--force", str(worktree)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        shutil.rmtree(worktree, ignore_errors=True)


def _commit_time(repo: Path, sha: str) -> datetime:
    raw = _git(repo, "show", "-s", "--format=%aI", sha).stdout.decode("utf-8").strip()
    parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    return parsed.astimezone(timezone.utc)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc)


def _artifact(root: Path, path: Path) -> dict[str, str]:
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": _sha256(path.read_bytes()),
    }


def _directory_artifacts(root: Path, directory: Path) -> list[dict[str, str]]:
    return sorted(
        (
            _artifact(root, path)
            for path in directory.rglob("*")
            if path.is_file() and ".git" not in path.relative_to(root).parts
        ),
        key=lambda row: (row["path"], row["sha256"]),
    )


def _commit_is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
    if not isinstance(ancestor, str) or not _HEX40.fullmatch(ancestor):
        return False
    exists = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-e", f"{ancestor}^{{commit}}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if exists.returncode != 0:
        return False
    relation = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", ancestor, descendant],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return relation.returncode == 0


def _native_certificate(
    directory: Path,
    *,
    workflow_id: str,
) -> tuple[Path | None, dict[str, Any] | None, str | None, list[str]]:
    reasons: list[str] = []
    names = _NATIVE_CERTIFICATE_FILES.get(workflow_id)
    if names is None:
        return None, None, None, ["workflow has no frozen native-certificate mapping"]

    certificate_path = None
    certificate = None
    for name in names:
        candidate = directory / name
        value = _load_json(candidate)
        if value is not None:
            certificate_path = candidate
            certificate = value
            break
    if certificate_path is None or certificate is None:
        return None, None, None, ["workflow-native certificate is missing"]

    if certificate.get("status") != "CertificateChecked":
        reasons.append("workflow-native certificate status is not CertificateChecked")

    violations = certificate.get("violations")
    if violations not in (None, []):
        reasons.append("workflow-native certificate carries violations")

    if certificate.get("counterexample_ref") not in (None, ""):
        reasons.append("workflow-native certificate carries a counterexample")

    certificate_id = None
    for key in ("certificate_id", "witness_id"):
        value = certificate.get(key)
        if isinstance(value, str) and value:
            certificate_id = value
            break
    if certificate_id is None:
        reasons.append("workflow-native certificate identity is missing")

    return certificate_path, certificate, certificate_id, reasons


def _release_manifest_binding(
    directory: Path,
    *,
    workflow_id: str,
    result: dict[str, Any],
    certificate_id: str | None,
) -> tuple[Path | None, list[str]]:
    reasons: list[str] = []
    manifest_path = directory / "release_manifest.v0.json"
    manifest = _load_json(manifest_path)
    if manifest is None:
        return None, ["release_manifest.v0.json is missing or invalid"]

    if manifest.get("workflow_profile_id") != workflow_id:
        reasons.append("release manifest workflow_profile_id mismatch")
    if manifest.get("release_id") != result.get("release_id"):
        reasons.append("release manifest release_id mismatch")
    if manifest.get("release_status") != "Validated":
        reasons.append("release manifest release_status is not Validated")

    chain_root = manifest.get("chain_root")
    if not isinstance(chain_root, dict):
        reasons.append("release manifest chain_root is missing")
    elif certificate_id is None or chain_root.get("certificate_id") != certificate_id:
        reasons.append("release manifest certificate_id does not bind native certificate")

    return manifest_path, reasons


def _subject_binding(result: dict[str, Any]) -> str | None:
    for key in ("release_id", "validation_id"):
        value = result.get(key)
        if isinstance(value, str) and value:
            return _typed_digest("rtk-pcs-attested-subject-v0", value)
    return None


def _attestation_predicate(
    result: dict[str, Any],
    *,
    workflow_id: str,
    source_commit_time: datetime,
    repository: Path,
    anchor_source_sha: str,
    directory: Path,
) -> tuple[bool, list[str], dict[str, Any]]:
    reasons: list[str] = []

    if result.get("schema_version") != "v0":
        reasons.append("schema_version is not v0")
    if result.get("workflow_profile_id") != workflow_id:
        reasons.append("workflow_profile_id mismatch")
    if result.get("validator") != "pcs-core":
        reasons.append("validator is not pcs-core")
    if result.get("status") != "ProofChecked":
        reasons.append("status is not ProofChecked")

    checks = result.get("checks")
    if not isinstance(checks, list) or not checks:
        reasons.append("checks is empty or absent")
    elif any(not isinstance(row, dict) or row.get("status") != "passed" for row in checks):
        reasons.append("one or more checks are not passed")

    failure_codes = result.get("failure_codes")
    if failure_codes not in (None, []):
        reasons.append("failure_codes is nonempty")

    signature = result.get("signature_or_digest")
    if not isinstance(signature, str) or not _SHA256.fullmatch(signature):
        reasons.append("signature_or_digest is not canonical sha256")

    source_repo = result.get("source_repo")
    if source_repo not in (
        "https://github.com/SentinelOps-CI/pcs-core",
        "https://github.com/SentinelOps-CI/pcs-core.git",
    ):
        reasons.append("source_repo is not pcs-core")

    checked_at = _parse_time(result.get("checked_at"))
    if checked_at is None:
        reasons.append("checked_at is missing or invalid")
    elif checked_at > source_commit_time:
        reasons.append("checked_at is later than source revision author timestamp")

    if _subject_binding(result) is None:
        reasons.append("release/validation subject identity is missing")

    result_source_commit = result.get("source_commit")
    source_commit_is_ancestor = (
        isinstance(result_source_commit, str)
        and _commit_is_ancestor(repository, result_source_commit, anchor_source_sha)
    )
    if not source_commit_is_ancestor:
        reasons.append("result source_commit is not a real ancestor of anchor source revision")

    certificate_path, certificate, certificate_id, certificate_reasons = _native_certificate(
        directory,
        workflow_id=workflow_id,
    )
    reasons.extend(certificate_reasons)

    manifest_path, manifest_reasons = _release_manifest_binding(
        directory,
        workflow_id=workflow_id,
        result=result,
        certificate_id=certificate_id,
    )
    reasons.extend(manifest_reasons)

    details = {
        "result_source_commit": result_source_commit,
        "result_source_commit_is_ancestor": source_commit_is_ancestor,
        "native_certificate_locator": (
            certificate_path.relative_to(directory).as_posix()
            if certificate_path is not None else None
        ),
        "native_certificate_id": certificate_id,
        "native_certificate_status": certificate.get("status") if certificate else None,
        "release_manifest_locator": (
            manifest_path.name if manifest_path is not None else None
        ),
    }
    return (not reasons, reasons, details)


def _attestation_candidates(
    worktree: Path,
    *,
    workflow_id: str,
    source_commit_time: datetime,
    source_sha: str,
) -> list[dict[str, Any]]:
    examples = worktree / "examples"
    if not examples.is_dir():
        return []

    out: list[dict[str, Any]] = []
    for profile_path in sorted(examples.rglob("workflow_profile.v0.json")):
        profile = _load_json(profile_path)
        if profile is None or profile.get("workflow_id") != workflow_id:
            continue

        directory = profile_path.parent
        result_path = None
        result = None
        for name in (
            "release_chain_validation_result.v0.json",
            "ReleaseChainValidationResult.v0.json",
        ):
            candidate = directory / name
            value = _load_json(candidate)
            if value is not None:
                result_path = candidate
                result = value
                break
        if result_path is None or result is None:
            continue

        accepted, reasons, details = _attestation_predicate(
            result,
            workflow_id=workflow_id,
            source_commit_time=source_commit_time,
            repository=worktree,
            anchor_source_sha=source_sha,
            directory=directory,
        )
        artifacts = _directory_artifacts(worktree, directory)
        out.append(
            {
                "candidate_id": (
                    "pcs-committed-attestation:"
                    + directory.relative_to(worktree).as_posix()
                    + "#"
                    + _typed_digest("rtk-pcs-attestation-directory-v0", artifacts)
                ),
                "locator": result_path.relative_to(worktree).as_posix(),
                "profile_locator": profile_path.relative_to(worktree).as_posix(),
                "attestation_sha256": _sha256(result_path.read_bytes()),
                "artifacts": artifacts,
                "attestation_accept": accepted,
                "attestation_rejection_reasons": reasons,
                "subject_binding": _subject_binding(result),
                "validator": result.get("validator"),
                "status": result.get("status"),
                "checked_at": result.get("checked_at"),
                **details,
            }
        )
    return sorted(out, key=lambda row: row["candidate_id"])


def _snapshot(
    *,
    repository: str,
    source_sha: str,
    anchor_id: str,
    artifacts: list[dict[str, str]],
    candidate_id: str,
) -> dict[str, Any]:
    policy = {
        "policy_id": "pcs-committed-positive-native-attestation-v1",
        "family": FAMILY_WORKFLOW,
        "source_bytes_only": True,
        "validation_basis": CLASS_ATTESTED,
        "selection": "lexicographically_first_qualifying_positive_native_certificate_attestation",
        "exact_runtime_replayed": False,
        "semantic_validator_soundness_proved": False,
    }
    digest = _typed_digest(
        "rtk-evidence-snapshot-v0",
        {"artifacts": artifacts, "completeness_policy": policy},
    )
    return {
        "snapshot_id": _typed_digest(
            "rtk-evidence-snapshot-id-v0",
            {
                "repository": repository,
                "revision": source_sha,
                "anchor_id": anchor_id,
                "candidate_id": candidate_id,
                "digest": digest,
            },
        ),
        "registry": f"git:{repository}",
        "revision": source_sha,
        "digest": digest,
        "digest_algorithm": "sha256",
        "completeness_policy": policy,
        "artifacts": artifacts,
    }


def _workflow_id(claim_id: str) -> str:
    prefix = "pcs-workflow:"
    if claim_id.startswith(prefix):
        return claim_id[len(prefix):]
    # Historical anchor extractor currently uses pcs-workflow:<workflow_id>.
    # Fail closed if that convention changes.
    raise ValueError(f"unsupported PCS workflow claim_id: {claim_id!r}")


def _parse_repo(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("--repo must use repository=local_path")
    name, raw = value.split("=", 1)
    return name.strip(), Path(raw).resolve()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-evidence", type=Path, required=True)
    parser.add_argument("--repo", action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, default=None)
    args = parser.parse_args()

    repos = dict(_parse_repo(value) for value in args.repo)
    rows = [
        json.loads(line)
        for line in args.source_evidence.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    rows.sort(key=lambda row: str(row["anchor_id"]))

    temp_owner = None
    if args.work_root is None:
        temp_owner = tempfile.TemporaryDirectory(prefix="rtk-source-tiering-v1-")
        work_root = Path(temp_owner.name)
    else:
        work_root = args.work_root.resolve()
        work_root.mkdir(parents=True, exist_ok=True)

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault((str(row["repository"]), str(row["source_sha"])), []).append(row)

    output: list[dict[str, Any]] = []
    try:
        for (repository, source_sha), members in sorted(grouped.items()):
            repo = repos.get(repository)
            if repo is None:
                raise SystemExit(f"missing --repo checkout for {repository}")
            group_root = work_root / _typed_digest(
                "rtk-source-tier-worktree-v1",
                {"repository": repository, "source_sha": source_sha},
            )
            group_root.mkdir(parents=True, exist_ok=True)
            with _source_worktree(repo, source_sha, group_root) as worktree:
                source_time = _commit_time(repo, source_sha)
                for original in sorted(members, key=lambda row: str(row["anchor_id"])):
                    row = dict(original)
                    row["source_evidence_class"] = (
                        CLASS_REPLAY
                        if row.get("materialization_status") == STATUS_REPLAY
                        else None
                    )
                    row["attestation_candidates"] = []
                    row["tiering_amendment_applied"] = True

                    eligible_for_attestation = (
                        repository == "SentinelOps-CI/pcs-core"
                        and row.get("family") == FAMILY_WORKFLOW
                        and row.get("materialization_status") == STATUS_OPERATIONAL
                    )
                    if eligible_for_attestation:
                        workflow_id = _workflow_id(str(row["claim_id"]))
                        candidates = _attestation_candidates(
                            worktree,
                            workflow_id=workflow_id,
                            source_commit_time=source_time,
                            source_sha=source_sha,
                        )
                        row["attestation_candidates"] = candidates
                        accepted = [c for c in candidates if c["attestation_accept"]]
                        if accepted:
                            selected = accepted[0]
                            row["materialization_status"] = STATUS_ATTESTED
                            row["source_evidence_class"] = CLASS_ATTESTED
                            row["selected_candidate_id"] = selected["candidate_id"]
                            row["subject_binding"] = selected["subject_binding"]
                            row["evidence_snapshot"] = _snapshot(
                                repository=repository,
                                source_sha=source_sha,
                                anchor_id=str(row["anchor_id"]),
                                artifacts=selected["artifacts"],
                                candidate_id=selected["candidate_id"],
                            )
                            row.setdefault("notes", []).append(
                                "Exact source-runtime replay unavailable; upgraded only to "
                                "COMMITTED_NATIVE_ATTESTATION from a qualifying committed "
                                "ReleaseChainValidationResult.v0 plus positive workflow-native "
                                "certificate bytes. This is weaker than "
                                "REPLAY_VERIFIED."
                            )
                    output.append(row)
    finally:
        if temp_owner is not None:
            temp_owner.cleanup()

    output.sort(key=lambda row: str(row["anchor_id"]))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="\n") as handle:
        for row in output:
            handle.write(_canonical_bytes(row).decode("utf-8") + "\n")

    status_counts: dict[str, int] = {}
    class_counts: dict[str, int] = {}
    transition_ids_by_class: dict[str, set[str]] = {}
    for row in output:
        status = str(row["materialization_status"])
        status_counts[status] = status_counts.get(status, 0) + 1
        evidence_class = row.get("source_evidence_class")
        if isinstance(evidence_class, str):
            class_counts[evidence_class] = class_counts.get(evidence_class, 0) + 1
            transition_ids_by_class.setdefault(evidence_class, set()).add(
                str(row["transition_id"])
            )

    manifest = {
        "schema_version": "rtk.source_evidence_tiered_manifest.v1",
        "record_count": len(output),
        "status_counts": dict(sorted(status_counts.items())),
        "evidence_class_counts": dict(sorted(class_counts.items())),
        "transition_counts_by_evidence_class": {
            key: len(value) for key, value in sorted(transition_ids_by_class.items())
        },
        "records_sha256": _sha256(args.out.read_bytes()),
        "input_source_evidence_sha256": _sha256(args.source_evidence.read_bytes()),
        "amendment_basis": (
            "pre-outcome source-runtime reconstruction failures; no RTK predictions, "
            "target-native validator results, or oracle labels consulted"
        ),
        "tier_a_interpretation": (
            "REPLAY_VERIFIED means source-revision native validator execution succeeded."
        ),
        "tier_b_interpretation": (
            "COMMITTED_NATIVE_ATTESTATION means exact replay was unavailable and source "
            "revision bytes contain a qualifying repository-native validation result, a "
            "real pcs-core provenance commit, and a positive workflow-native certificate "
            "bound by the release manifest. Validator/runtime soundness is an explicit "
            "unproved premise."
        ),
        "target_native_validators_executed": False,
        "rtk_executed": False,
        "oracle_labels_consulted": False,
        "fresh_evidence_generated": False,
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_bytes(_canonical_bytes(manifest) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
