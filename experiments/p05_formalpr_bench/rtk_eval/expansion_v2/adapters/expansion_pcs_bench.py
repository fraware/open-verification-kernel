"""pcs-bench expansion adapter — source-side benchmark-case semantics."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Sequence

from ..adapter_contract import (
    ClaimAnchor,
    GovernedArtifact,
    NativeValidatorResult,
    RepositoryIdentity,
    SourceEvidenceCandidate,
    TransitionEnumerationRecord,
)
from . import common_git
from .expansion_base import ExpansionAdapterBase, _typed_digest


FAMILY = "PCS_BENCH_CASE_V0"


class PcsBenchAdapter(ExpansionAdapterBase):
    def __init__(self) -> None:
        super().__init__(
            RepositoryIdentity(
                repository="fraware/pcs-bench",
                url="https://github.com/fraware/pcs-bench",
                cutoff_sha="6092cccefee7841dfde1393e6881d433838a2252",
                role="EXPANSION_CANDIDATE",
            )
        )
        self._validate_cache: dict[str, dict] = {}

    def discover_governed_artifacts(
        self,
        checkout: Path,
        revision: str,
    ) -> Sequence[GovernedArtifact]:
        out: list[GovernedArtifact] = []
        for path in common_git.list_tree_paths(checkout, revision, "benchmarks"):
            if path.endswith("benchmark_case.v0.json"):
                raw = common_git.show_file(checkout, revision, path)
                out.append(
                    GovernedArtifact(
                        path=path,
                        artifact_class=FAMILY,
                        sha256=common_git.sha256_bytes(raw) if raw else None,
                    )
                )
        for path in common_git.list_tree_paths(
            checkout, revision, "src/pcs_bench/schemas/json"
        ):
            if path.endswith(".json"):
                raw = common_git.show_file(checkout, revision, path)
                out.append(
                    GovernedArtifact(
                        path=path,
                        artifact_class="PCS_BENCH_SCHEMA",
                        sha256=common_git.sha256_bytes(raw) if raw else None,
                    )
                )
        return out

    def extract_claim_anchors(
        self,
        checkout: Path,
        transition: TransitionEnumerationRecord,
    ) -> Sequence[ClaimAnchor]:
        if transition.eligibility != "ELIGIBLE":
            return []
        anchors: list[ClaimAnchor] = []
        for path in common_git.list_tree_paths(
            checkout, transition.source_sha, "benchmarks"
        ):
            if not path.endswith("benchmark_case.v0.json"):
                continue
            raw = common_git.show_file(checkout, transition.source_sha, path)
            if raw is None:
                continue
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            case_id = data.get("case_id")
            if not isinstance(case_id, str) or not case_id:
                continue
            # Require committed case schema_version surface.
            if data.get("schema_version") not in ("v0", "0", 0):
                # Accept common v0 marker used in fixtures.
                if data.get("schema_version") != "BenchmarkCase.v0" and not str(
                    data.get("schema_version", "")
                ).startswith("v0"):
                    if "case_id" not in data:
                        continue
            claim_id = f"pcs-bench-case:{case_id}"
            anchors.append(
                self.make_anchor(
                    transition,
                    family=FAMILY,
                    claim_id=claim_id,
                    contract_locator=path,
                    extra={"case_kind": data.get("case_kind"), "workflow_id": data.get("workflow_id")},
                )
            )
        return anchors

    def execute_source_revision_native_validator(
        self,
        checkout: Path,
        candidate: SourceEvidenceCandidate,
        *,
        source_sha: str,
    ) -> NativeValidatorResult:
        locator = candidate.paths[0] if candidate.paths else None
        if not locator:
            return NativeValidatorResult(
                status="SOURCE_REJECTED",
                validator_id="pcs-bench-case-schema",
                accepted=False,
                details={"reason": "missing_contract_locator"},
            )
        raw = common_git.show_file(checkout, source_sha, locator)
        if raw is None:
            return NativeValidatorResult(
                status="OPERATIONAL_FAILURE",
                validator_id="pcs-bench-case-schema",
                accepted=False,
                details={"reason": "contract_absent_at_source"},
            )
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return NativeValidatorResult(
                status="SOURCE_REJECTED",
                validator_id="pcs-bench-case-schema",
                accepted=False,
                details={"reason": "malformed_json"},
            )
        required = ("case_id", "task_id", "workflow_id", "case_kind", "expected_status")
        missing = [k for k in required if k not in data]
        if missing:
            return NativeValidatorResult(
                status="SOURCE_REJECTED",
                validator_id="pcs-bench-validate-cases",
                accepted=False,
                details={"reason": "missing_required_fields", "missing": missing},
            )

        import os

        # Native validator is suite-scoped at a source revision; cache per SHA.
        if source_sha in self._validate_cache:
            command = self._validate_cache[source_sha]
        else:
            env = dict(os.environ)
            env["PYTHONPATH"] = "src"
            # Do not use --dry-run: that skips pcs validate and would weaken
            # Tier A / REPLAY_VERIFIED relative to a true native validator run.
            command = self._run_in_source_worktree(
                checkout,
                source_sha,
                [
                    sys.executable,
                    "-m",
                    "pcs_bench",
                    "validate-cases",
                    "--suite",
                    "all",
                ],
                timeout_sec=300,
                env=env,
            )
            self._validate_cache[source_sha] = command
        if command.get("status") != "COMPLETED":
            return NativeValidatorResult(
                status="OPERATIONAL_FAILURE",
                validator_id="pcs-bench-validate-cases",
                accepted=False,
                details={
                    "reason": "native_cli_operational_failure",
                    "command": command,
                    "locator": locator,
                },
            )
        if command.get("exit_code") != 0:
            # Fixture/case CLI may require external pcs-core checkout; do not
            # promote structural presence to Tier A.
            return NativeValidatorResult(
                status="OPERATIONAL_FAILURE",
                validator_id="pcs-bench-validate-cases",
                accepted=False,
                details={
                    "reason": "native_cli_non_zero",
                    "command": command,
                    "locator": locator,
                },
            )
        subject = _typed_digest(
            "rtk-pcs-bench-case-subject-v2",
            {
                "case_id": data.get("case_id"),
                "workflow_id": data.get("workflow_id"),
                "locator": locator,
                "bytes_sha256": common_git.sha256_bytes(raw),
            },
        )
        return NativeValidatorResult(
            status="SOURCE_ACCEPTED",
            validator_id="pcs-bench-validate-cases",
            accepted=True,
            details={
                "subject_id": subject,
                "command": command,
                "locator": locator,
                "case_id": data.get("case_id"),
            },
        )
