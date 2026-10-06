"""Project source-evidence materialization onto a deterministic semantic record.

The raw materializer preserves execution transcripts and environment details whose bytes
may differ across equivalent GitHub runners. This projection removes volatile details
while retaining the complete semantic decision surface used by the holdout:
candidate identities/artifacts, command completion/exit outcomes, source-runtime
availability reasons and dependency digests, materialization status, selected evidence,
subject binding, verifier identity, and evidence snapshots.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _command_outcome(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"status": None, "exit_code": None}
    return {"status": value.get("status"), "exit_code": value.get("exit_code")}


def project(row: dict[str, Any]) -> dict[str, Any]:
    environment = row.get("environment")
    environment_semantics: dict[str, Any] = {}
    if isinstance(environment, dict):
        source_runtime = environment.get("source_runtime")
        if isinstance(source_runtime, dict):
            environment_semantics["source_runtime"] = {
                "ok": source_runtime.get("ok"),
                "reason": source_runtime.get("reason"),
                "requirements_lock_sha256": source_runtime.get("requirements_lock_sha256"),
                "pyproject_sha256": source_runtime.get("pyproject_sha256"),
                "runtime_identity": source_runtime.get("runtime_identity"),
                "setup_outcomes": [
                    _command_outcome(command)
                    for command in source_runtime.get("runtime_setup", [])
                    if isinstance(command, dict)
                ],
            }
        certifyedge_build = environment.get("certifyedge_build")
        if isinstance(certifyedge_build, dict):
            environment_semantics["certifyedge_build"] = _command_outcome(
                certifyedge_build
            )

    candidates: list[dict[str, Any]] = []
    for candidate in row.get("candidates", []):
        if not isinstance(candidate, dict):
            raise ValueError("candidate must be an object")
        candidates.append(
            {
                "candidate_id": candidate.get("candidate_id"),
                "locator": candidate.get("locator"),
                "artifacts": candidate.get("artifacts"),
                "native_accept": candidate.get("native_accept"),
                "subject_binding": candidate.get("subject_binding"),
                "rejection_reason": candidate.get("rejection_reason"),
                "native_command_outcomes": [
                    _command_outcome(command)
                    for command in candidate.get("native_commands", [])
                    if isinstance(command, dict)
                ],
            }
        )

    return {
        "anchor_id": row.get("anchor_id"),
        "transition_id": row.get("transition_id"),
        "repository": row.get("repository"),
        "source_sha": row.get("source_sha"),
        "family": row.get("family"),
        "claim_id": row.get("claim_id"),
        "contract_locator": row.get("contract_locator"),
        "materialization_status": row.get("materialization_status"),
        "subject_binding": row.get("subject_binding"),
        "selected_candidate_id": row.get("selected_candidate_id"),
        "native_verifier_digest": row.get("native_verifier_digest"),
        "evidence_snapshot": row.get("evidence_snapshot"),
        "candidates": candidates,
        "environment_semantics": environment_semantics,
        "target_native_validator_executed": row.get("target_native_validator_executed"),
        "rtk_executed": row.get("rtk_executed"),
        "oracle_labels_consulted": row.get("oracle_labels_consulted"),
        "notes": row.get("notes", []),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()

    rows = [
        json.loads(line)
        for line in args.input.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    projected = sorted(
        (project(row) for row in rows),
        key=lambda row: str(row["anchor_id"]),
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="\n") as handle:
        for row in projected:
            handle.write(_canonical(row).decode("utf-8") + "\n")

    payload = args.out.read_bytes()
    status_counts: dict[str, int] = {}
    for row in projected:
        status = str(row["materialization_status"])
        status_counts[status] = status_counts.get(status, 0) + 1

    manifest = {
        "schema_version": "rtk.source_evidence_semantic_projection.v0",
        "record_count": len(projected),
        "status_counts": dict(sorted(status_counts.items())),
        "projection_sha256": hashlib.sha256(payload).hexdigest(),
        "raw_input_sha256": hashlib.sha256(args.input.read_bytes()).hexdigest(),
        "excluded_as_volatile": [
            "absolute executable and working-directory paths",
            "platform/kernel string",
            "stdout/stderr digests",
            "runtime reuse/cache state",
            "cargo target path",
        ],
        "retained_command_semantics": ["status", "exit_code"],
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_bytes(_canonical(manifest) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
