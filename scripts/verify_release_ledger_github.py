#!/usr/bin/env python
"""Authorize an OVK release ledger against live GitHub and release artifacts.

This command is the network/local-artifact trust boundary for release
authorization. It independently resolves every workflow run through GitHub,
downloads required holdout/consumer artifacts from those exact run IDs, and
hashes the wheel/sdist from the local build. It never tags, creates a release,
signs artifacts, or publishes to PyPI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ovk.core.release_ledger import verify_release_ledger  # noqa: E402
from scripts.digest_holdout_predictions import assert_predictions_label_free  # noqa: E402
from scripts.run_formalpr_holdout import validate_aggregate_schema  # noqa: E402


def _run(args: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"command execution failed: {exc}") from exc


def _gh_json(endpoint: str) -> Mapping[str, Any]:
    completed = _run(["gh", "api", endpoint], timeout=60)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "gh api failed"
        raise RuntimeError(detail)
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("gh api returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("gh api returned a non-object payload")
    return payload


def _run_gh_api(repo: str, run_id: int) -> Mapping[str, Any]:
    return _gh_json(f"repos/{repo}/actions/runs/{run_id}")


def _list_run_artifacts(repo: str, run_id: int) -> list[dict[str, Any]]:
    payload = _gh_json(f"repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100")
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        raise RuntimeError("GitHub run artifact response missing artifacts list")
    return [item for item in artifacts if isinstance(item, dict)]


def _require_artifact_names(
    artifacts: list[dict[str, Any]],
    *,
    exact: set[str] | None = None,
    prefix: str | None = None,
    expected_count: int | None = None,
) -> list[str]:
    names: list[str] = []
    for artifact in artifacts:
        name = str(artifact.get("name") or "")
        if artifact.get("expired") is True:
            if (exact and name in exact) or (prefix and name.startswith(prefix)):
                raise RuntimeError(f"required workflow artifact expired: {name}")
            continue
        if (exact and name in exact) or (prefix and name.startswith(prefix)):
            names.append(name)
    if len(names) != len(set(names)):
        raise RuntimeError("duplicate required workflow artifact names")
    if exact is not None and set(names) != exact:
        raise RuntimeError(
            f"required artifact set mismatch: expected={sorted(exact)} observed={sorted(names)}"
        )
    if expected_count is not None and len(names) != expected_count:
        raise RuntimeError(
            f"required artifact count mismatch: expected={expected_count} observed={len(names)}"
        )
    return sorted(names)


def _download_artifact(repo: str, run_id: int, name: str, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    completed = _run(
        [
            "gh",
            "run",
            "download",
            str(run_id),
            "--repo",
            repo,
            "--name",
            name,
            "--dir",
            str(destination),
        ],
        timeout=180,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "gh run download failed"
        raise RuntimeError(f"cannot download artifact {name!r}: {detail}")


def _exact_file(root: Path, name: str) -> Path:
    matches = [path for path in root.rglob(name) if path.is_file()]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one {name!r}, found {len(matches)}")
    return matches[0]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid JSON artifact {path.name}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"artifact {path.name} must contain a JSON object")
    return payload


def _inspect_holdout_predictions(root: Path) -> dict[str, Any]:
    predictions_path = _exact_file(root, "holdout-predictions.json")
    manifest_path = _exact_file(root, "holdout-prediction-manifest.json")
    predictions = _load_json_object(predictions_path)
    manifest = _load_json_object(manifest_path)
    try:
        assert_predictions_label_free(predictions)
    except SystemExit as exc:
        raise RuntimeError(str(exc)) from exc
    if predictions.get("label_free") is not True:
        raise RuntimeError("holdout predictions must declare label_free=true")
    return {
        "kind": "holdout_predictions.v1",
        "artifact_name": "formalpr-holdout-predictions",
        "predictions_sha256": _sha256(predictions_path),
        "manifest_sha256": _sha256(manifest_path),
        "candidate_source_sha": str(predictions.get("candidate_source_sha") or "").lower(),
        "manifest_candidate_source_sha": str(
            manifest.get("candidate_source_sha") or ""
        ).lower(),
        "manifest_predictions_sha256": str(
            manifest.get("predictions_sha256") or ""
        ).lower(),
        "label_free": True,
        "verified_source_sha_present": (
            "verified_source_sha" in predictions or "verified_source_sha" in manifest
        ),
    }


def _inspect_holdout_aggregate(root: Path) -> dict[str, Any]:
    aggregate_path = _exact_file(root, "holdout-aggregate-metrics.json")
    aggregate = _load_json_object(aggregate_path)
    try:
        validate_aggregate_schema(aggregate)
    except SystemExit as exc:
        raise RuntimeError(str(exc)) from exc
    return {
        "kind": "holdout_aggregate.v1",
        "artifact_name": "formalpr-holdout-aggregates",
        "aggregate_sha256": _sha256(aggregate_path),
        "candidate_source_sha": str(aggregate.get("ovk_commit_sha") or "").lower(),
        "holdout_tag": str(aggregate.get("holdout_release_tag") or ""),
        "schema_valid": True,
        "verified_source_sha_present": (
            "verified_source_sha" in aggregate and aggregate.get("verified_source_sha") is not None
        ),
    }


def _inspect_consumer_pin_artifacts(
    artifact_roots: Mapping[str, Path],
) -> dict[str, Any]:
    consumers: list[dict[str, Any]] = []
    evidence_file_sha256: dict[str, str] = {}
    for artifact_name, root in sorted(artifact_roots.items()):
        matches = [path for path in root.rglob("consumer-pin-*.json") if path.is_file()]
        if len(matches) != 1:
            raise RuntimeError(
                f"{artifact_name}: expected exactly one consumer-pin JSON, found {len(matches)}"
            )
        path = matches[0]
        payload = _load_json_object(path)
        repository = str(payload.get("consumer_repository") or "")
        if not repository:
            raise RuntimeError(f"{artifact_name}: consumer_repository missing")
        if repository in evidence_file_sha256:
            raise RuntimeError(f"duplicate consumer evidence repository: {repository}")
        consumers.append(payload)
        evidence_file_sha256[repository] = _sha256(path)
    return {
        "kind": "consumer_pin_evidence.v1",
        "artifact_names": sorted(artifact_roots),
        "consumers": consumers,
        "evidence_file_sha256": evidence_file_sha256,
    }


def _resolve_workflow_artifacts(
    repository: str,
    run_id: int,
    workflow: str,
) -> Mapping[str, Any]:
    artifacts = _list_run_artifacts(repository, run_id)
    with tempfile.TemporaryDirectory(prefix="ovk-release-evidence-") as tmp:
        root = Path(tmp)
        if workflow == "FormalPR-Holdout predict":
            names = _require_artifact_names(
                artifacts,
                exact={"formalpr-holdout-predictions"},
                expected_count=1,
            )
            dest = root / names[0]
            _download_artifact(repository, run_id, names[0], dest)
            return _inspect_holdout_predictions(dest)

        if workflow == "FormalPR-Holdout eval":
            names = _require_artifact_names(
                artifacts,
                exact={"formalpr-holdout-aggregates"},
                expected_count=1,
            )
            dest = root / names[0]
            _download_artifact(repository, run_id, names[0], dest)
            return _inspect_holdout_aggregate(dest)

        if workflow == "Consumer Pin Verification":
            names = _require_artifact_names(
                artifacts,
                prefix="consumer-pin-",
                expected_count=2,
            )
            roots: dict[str, Path] = {}
            for name in names:
                dest = root / name
                _download_artifact(repository, run_id, name, dest)
                roots[name] = dest
            return _inspect_consumer_pin_artifacts(roots)

    raise RuntimeError(f"no release artifact contract for workflow {workflow!r}")


def _release_artifact_resolver(dist_dir: Path):
    def resolve() -> Mapping[str, Any]:
        wheels = sorted(path for path in dist_dir.glob("*.whl") if path.is_file())
        sdists = sorted(path for path in dist_dir.glob("*.tar.gz") if path.is_file())
        if len(wheels) != 1:
            raise RuntimeError(f"expected exactly one wheel in {dist_dir}, found {len(wheels)}")
        if len(sdists) != 1:
            raise RuntimeError(f"expected exactly one sdist in {dist_dir}, found {len(sdists)}")
        return {
            "wheel": {"filename": wheels[0].name, "sha256": _sha256(wheels[0])},
            "sdist": {"filename": sdists[0].name, "sha256": _sha256(sdists[0])},
        }

    return resolve


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Authorize an OVK release ledger using live provenance"
    )
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument(
        "--dist-dir",
        type=Path,
        required=True,
        help="Directory containing exactly one wheel and one sdist to authorize",
    )
    parser.add_argument("--expected-repository", default=None)
    parser.add_argument("--expected-candidate-sha", default=None)
    parser.add_argument(
        "--write",
        type=Path,
        required=True,
        help="Output path for the provenance-authorized ledger",
    )
    args = parser.parse_args(argv)

    payload = json.loads(args.ledger.read_text(encoding="utf-8"))
    ok, failures, authorized = verify_release_ledger(
        payload,
        repo_root=args.repo_root.resolve(),
        workflow_run_resolver=_run_gh_api,
        workflow_artifact_resolver=_resolve_workflow_artifacts,
        release_artifact_resolver=_release_artifact_resolver(args.dist_dir.resolve()),
        expected_repository=args.expected_repository,
        expected_candidate_sha=args.expected_candidate_sha,
        require_artifacts=True,
        require_consumers=True,
        require_holdout=True,
    )
    for failure in failures:
        print(failure, file=sys.stderr)
    if not ok:
        return 1

    args.write.parent.mkdir(parents=True, exist_ok=True)
    args.write.write_text(
        json.dumps(authorized, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "authorized verified_source_sha="
        f"{authorized['release_state']['verified_source_sha']} "
        "via live workflow, workflow-artifact, and distribution provenance; "
        "published=false tag=null"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
