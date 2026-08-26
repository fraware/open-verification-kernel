#!/usr/bin/env python
"""Re-check that local distributions are exactly those authorized by a v2 ledger.

This verifier does not mint authority. It consumes an already provenance-
authorized ledger and fails closed if candidate identity, required evidence
bindings, or distribution bytes differ from the authorization record.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ovk.core.release_ledger import (  # noqa: E402
    LEDGER_SCHEMA_VERSION,
    REQUIRED_CONSUMER_REPOSITORIES,
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _valid_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(char in "0123456789abcdef" for char in value.lower())
    )


def verify_authorized_release_inputs(
    ledger: dict[str, Any],
    *,
    dist_dir: Path,
    expected_repository: str,
    expected_candidate_sha: str,
) -> list[str]:
    failures: list[str] = []
    expected_candidate_sha = expected_candidate_sha.lower()
    if not _valid_hex(expected_candidate_sha, 40):
        failures.append("expected_candidate_sha must be exact 40-hex")

    if ledger.get("schema_version") != LEDGER_SCHEMA_VERSION:
        failures.append(f"schema_version must be {LEDGER_SCHEMA_VERSION}")
    source = ledger.get("source") if isinstance(ledger.get("source"), dict) else {}
    if source.get("repository") != expected_repository:
        failures.append("source.repository mismatch")
    source_candidate = str(source.get("candidate_sha") or "").lower()
    if not _valid_hex(source_candidate, 40) or source_candidate != expected_candidate_sha:
        failures.append("source.candidate_sha mismatch")

    state = ledger.get("release_state") if isinstance(ledger.get("release_state"), dict) else {}
    if state.get("authorized") is not True:
        failures.append("release ledger is not authorized")
    verified_source_sha = str(state.get("verified_source_sha") or "").lower()
    if not _valid_hex(verified_source_sha, 40) or verified_source_sha != expected_candidate_sha:
        failures.append("verified_source_sha mismatch")
    if state.get("published") is not False:
        failures.append("pre-publication ledger must keep published=false")
    if state.get("tag") is not None:
        failures.append("pre-publication ledger must keep tag=null")

    evidence = ledger.get("evidence") if isinstance(ledger.get("evidence"), dict) else {}
    if not isinstance(evidence.get("workflow_provenance"), dict):
        failures.append("workflow_provenance missing")
    if not isinstance(evidence.get("workflow_artifact_provenance"), dict):
        failures.append("workflow_artifact_provenance missing")
    release_provenance = evidence.get("release_artifact_provenance")
    if not isinstance(release_provenance, dict):
        failures.append("release_artifact_provenance missing")
    if evidence.get("p0_blockers"):
        failures.append("p0_blockers must be empty")

    holdout = ledger.get("holdout") if isinstance(ledger.get("holdout"), dict) else {}
    holdout_candidate = str(holdout.get("candidate_source_sha") or "").lower()
    if not _valid_hex(holdout_candidate, 40) or holdout_candidate != expected_candidate_sha:
        failures.append("holdout candidate_source_sha mismatch")
    for key in ("predictions_sha256", "aggregate_sha256", "holdout_asset_sha256"):
        if not _valid_hex(holdout.get(key), 64):
            failures.append(f"holdout.{key} missing or malformed")
    if not isinstance(holdout.get("holdout_tag"), str) or not holdout["holdout_tag"].strip():
        failures.append("holdout.holdout_tag missing")

    consumers = ledger.get("consumers")
    if not isinstance(consumers, list):
        failures.append("consumers missing")
    else:
        repositories = {
            str(item.get("consumer_repository") or "")
            for item in consumers
            if isinstance(item, dict)
        }
        if repositories != set(REQUIRED_CONSUMER_REPOSITORIES):
            failures.append("consumer repository set mismatch")
        for item in consumers:
            if not isinstance(item, dict):
                failures.append("consumer evidence row malformed")
                continue
            repository = str(item.get("consumer_repository") or "")
            candidate = str(item.get("ovk_candidate_sha") or "").lower()
            if not _valid_hex(candidate, 40) or candidate != expected_candidate_sha:
                failures.append(f"consumer candidate SHA mismatch:{repository or '<unknown>'}")
            consumer_source_sha = str(item.get("consumer_source_sha") or "").lower()
            if not _valid_hex(consumer_source_sha, 40):
                failures.append(f"consumer source SHA missing or malformed:{repository or '<unknown>'}")
            if not isinstance(item.get("consumer_ref"), str) or not item["consumer_ref"].strip():
                failures.append(f"consumer ref missing:{repository or '<unknown>'}")
            if item.get("pin") != f"fraware/open-verification-kernel@{expected_candidate_sha}":
                failures.append(f"consumer pin mismatch:{repository or '<unknown>'}")
            workflow_digests = item.get("workflow_digests")
            if not isinstance(workflow_digests, list) or not workflow_digests:
                failures.append(f"consumer workflow digests missing:{repository or '<unknown>'}")
            else:
                seen_paths: set[str] = set()
                for record in workflow_digests:
                    if not isinstance(record, dict):
                        failures.append(f"consumer workflow digest malformed:{repository or '<unknown>'}")
                        continue
                    path = str(record.get("path") or "")
                    if not path or path in seen_paths or not _valid_hex(record.get("sha256"), 64):
                        failures.append(f"consumer workflow digest malformed:{repository or '<unknown>'}")
                        continue
                    seen_paths.add(path)

    artifacts = ledger.get("artifacts") if isinstance(ledger.get("artifacts"), dict) else {}
    for key in ("wheel_sha256", "sdist_sha256"):
        if not _valid_hex(artifacts.get(key), 64):
            failures.append(f"artifacts.{key} missing or malformed")
    for key in ("wheel_filename", "sdist_filename"):
        if not isinstance(artifacts.get(key), str) or not artifacts[key].strip():
            failures.append(f"artifacts.{key} missing")

    if isinstance(release_provenance, dict):
        for kind, filename_key, digest_key in (
            ("wheel", "wheel_filename", "wheel_sha256"),
            ("sdist", "sdist_filename", "sdist_sha256"),
        ):
            record = release_provenance.get(kind)
            if not isinstance(record, dict):
                failures.append(f"release artifact provenance missing {kind}")
                continue
            if record.get("filename") != artifacts.get(filename_key):
                failures.append(f"{kind} provenance filename mismatch")
            provenance_digest = str(record.get("sha256") or "").lower()
            artifact_digest = str(artifacts.get(digest_key) or "").lower()
            if not _valid_hex(provenance_digest, 64) or provenance_digest != artifact_digest:
                failures.append(f"{kind} provenance digest mismatch")

    wheels = sorted(path for path in dist_dir.glob("*.whl") if path.is_file())
    sdists = sorted(path for path in dist_dir.glob("*.tar.gz") if path.is_file())
    if len(wheels) != 1:
        failures.append(f"expected exactly one wheel, found {len(wheels)}")
    if len(sdists) != 1:
        failures.append(f"expected exactly one sdist, found {len(sdists)}")
    if len(wheels) == 1:
        if artifacts.get("wheel_filename") != wheels[0].name:
            failures.append("wheel filename mismatch")
        if str(artifacts.get("wheel_sha256") or "").lower() != _sha256(wheels[0]):
            failures.append("wheel digest mismatch")
    if len(sdists) == 1:
        if artifacts.get("sdist_filename") != sdists[0].name:
            failures.append("sdist filename mismatch")
        if str(artifacts.get("sdist_sha256") or "").lower() != _sha256(sdists[0]):
            failures.append("sdist digest mismatch")

    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify authorized release distribution inputs")
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--dist-dir", type=Path, required=True)
    parser.add_argument("--expected-repository", required=True)
    parser.add_argument("--expected-candidate-sha", required=True)
    args = parser.parse_args(argv)

    payload = json.loads(args.ledger.read_text(encoding="utf-8"))
    failures = verify_authorized_release_inputs(
        payload,
        dist_dir=args.dist_dir.resolve(),
        expected_repository=args.expected_repository,
        expected_candidate_sha=args.expected_candidate_sha,
    )
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        return 1
    print(
        f"authorized distribution binding verified for "
        f"{args.expected_repository}@{args.expected_candidate_sha.lower()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
