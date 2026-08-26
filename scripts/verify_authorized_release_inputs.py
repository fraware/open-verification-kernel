#!/usr/bin/env python
"""Re-check that local distributions are exactly those authorized by a v2 ledger.

This verifier does not mint authority. It consumes an already provenance-
authorized ledger and fails closed if the candidate identity or distribution
bytes differ from the authorization record.
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


def verify_authorized_release_inputs(
    ledger: dict[str, Any],
    *,
    dist_dir: Path,
    expected_repository: str,
    expected_candidate_sha: str,
) -> list[str]:
    failures: list[str] = []
    expected_candidate_sha = expected_candidate_sha.lower()

    if ledger.get("schema_version") != LEDGER_SCHEMA_VERSION:
        failures.append(f"schema_version must be {LEDGER_SCHEMA_VERSION}")
    source = ledger.get("source") if isinstance(ledger.get("source"), dict) else {}
    if source.get("repository") != expected_repository:
        failures.append("source.repository mismatch")
    if str(source.get("candidate_sha") or "").lower() != expected_candidate_sha:
        failures.append("source.candidate_sha mismatch")

    state = ledger.get("release_state") if isinstance(ledger.get("release_state"), dict) else {}
    if state.get("authorized") is not True:
        failures.append("release ledger is not authorized")
    if str(state.get("verified_source_sha") or "").lower() != expected_candidate_sha:
        failures.append("verified_source_sha mismatch")
    if state.get("published") is not False:
        failures.append("pre-publication ledger must keep published=false")

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
    if str(holdout.get("candidate_source_sha") or "").lower() != expected_candidate_sha:
        failures.append("holdout candidate_source_sha mismatch")
    for key in ("predictions_sha256", "aggregate_sha256"):
        value = holdout.get(key)
        if not isinstance(value, str) or len(value) != 64:
            failures.append(f"holdout.{key} missing")

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
                continue
            if str(item.get("ovk_candidate_sha") or "").lower() != expected_candidate_sha:
                failures.append("consumer candidate SHA mismatch")
            consumer_source_sha = str(item.get("consumer_source_sha") or "")
            if len(consumer_source_sha) != 40:
                failures.append("consumer source SHA missing")

    artifacts = ledger.get("artifacts") if isinstance(ledger.get("artifacts"), dict) else {}
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
            if str(record.get("sha256") or "").lower() != str(
                artifacts.get(digest_key) or ""
            ).lower():
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
