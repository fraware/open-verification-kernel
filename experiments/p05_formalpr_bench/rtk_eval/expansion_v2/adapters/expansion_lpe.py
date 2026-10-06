"""lean-project-evidence expansion adapter."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Sequence

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


FAMILY = "LPE_PROJECT_CONTRACT_V1"


class LeanProjectEvidenceAdapter(ExpansionAdapterBase):
    def __init__(self) -> None:
        super().__init__(
            RepositoryIdentity(
                repository="fraware/lean-project-evidence",
                url="https://github.com/fraware/lean-project-evidence",
                cutoff_sha="4660d97db933b0fbcf5c9af466191055c887bea3",
                role="EXPANSION_CANDIDATE",
            )
        )

    def discover_governed_artifacts(
        self,
        checkout: Path,
        revision: str,
    ) -> Sequence[GovernedArtifact]:
        out: list[GovernedArtifact] = []
        for prefix, cls in (
            ("examples", "LPE_EXAMPLE"),
            ("schemas", "LPE_SCHEMA"),
        ):
            for path in common_git.list_tree_paths(checkout, revision, prefix):
                if not path.endswith((".json", ".yaml", ".yml")):
                    continue
                raw = common_git.show_file(checkout, revision, path)
                out.append(
                    GovernedArtifact(
                        path=path,
                        artifact_class=cls,
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
            checkout, transition.source_sha, "examples"
        ):
            if not path.endswith(".json"):
                continue
            name = Path(path).name.lower()
            is_candidate = path.startswith("examples/candidates/")
            is_contract = "contract" in name or name in {"project.json"}
            if not (is_candidate or is_contract):
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
            identity = (
                data.get("project_id")
                or data.get("candidate_id")
                or data.get("id")
                or Path(path).stem
            )
            claim_id = f"lpe-contract:{identity}"
            anchors.append(
                self.make_anchor(
                    transition,
                    family=FAMILY,
                    claim_id=str(claim_id),
                    contract_locator=path,
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
                validator_id="lpe-contract-validate",
                accepted=False,
                details={"reason": "missing_locator"},
            )
        raw = common_git.show_file(checkout, source_sha, locator)
        if raw is None:
            return NativeValidatorResult(
                status="OPERATIONAL_FAILURE",
                validator_id="lpe-contract-validate",
                accepted=False,
                details={"reason": "contract_absent"},
            )

        # Candidates use candidate validate; contracts use contract validate.
        if "candidates/" in locator:
            argv = [sys.executable, "-m", "lpe", "candidate", "validate", locator]
            validator_id = "lpe-candidate-validate"
        else:
            argv = [sys.executable, "-m", "lpe", "contract", "validate", locator]
            validator_id = "lpe-contract-validate"

        command = self._run_in_source_worktree(
            checkout,
            source_sha,
            argv,
            timeout_sec=300,
            env={
                **{k: v for k, v in __import__("os").environ.items()},
                "PYTHONPATH": "src",
            },
        )
        if command.get("status") != "COMPLETED":
            return NativeValidatorResult(
                status="OPERATIONAL_FAILURE",
                validator_id=validator_id,
                accepted=False,
                details={"command": command, "locator": locator},
            )
        accepted = command.get("exit_code") == 0
        try:
            data = json.loads(raw.decode("utf-8"))
            identity = data.get("project_id") or data.get("candidate_id") or data.get("id")
        except (UnicodeDecodeError, json.JSONDecodeError):
            identity = Path(locator).stem
        subject = _typed_digest(
            "rtk-lpe-subject-v2",
            {
                "identity": identity,
                "locator": locator,
                "bytes_sha256": common_git.sha256_bytes(raw),
            },
        )
        return NativeValidatorResult(
            status="SOURCE_ACCEPTED" if accepted else "SOURCE_REJECTED",
            validator_id=validator_id,
            accepted=accepted,
            details={"subject_id": subject, "command": command, "locator": locator},
        )
