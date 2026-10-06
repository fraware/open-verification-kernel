"""environment-assurance-compiler expansion adapter."""

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


FAMILY = "EAC_EXAMPLE_MANIFEST_V1"


class EnvironmentAssuranceCompilerAdapter(ExpansionAdapterBase):
    def __init__(self) -> None:
        super().__init__(
            RepositoryIdentity(
                repository="fraware/environment-assurance-compiler",
                url="https://github.com/fraware/environment-assurance-compiler",
                cutoff_sha="812b4b13f8acdfcafb50de9d794c7fa0b20b31ad",
                role="EXPANSION_CANDIDATE",
            )
        )

    def discover_governed_artifacts(
        self,
        checkout: Path,
        revision: str,
    ) -> Sequence[GovernedArtifact]:
        out: list[GovernedArtifact] = []
        for path in common_git.list_tree_paths(checkout, revision, "examples"):
            name = Path(path).name
            if name in {
                "example-manifest.json",
                "release-manifest.json",
                "pack-manifest.json",
                "openenv.yaml",
            } or name.endswith((".schema.json",)):
                raw = common_git.show_file(checkout, revision, path)
                out.append(
                    GovernedArtifact(
                        path=path,
                        artifact_class=FAMILY,
                        sha256=common_git.sha256_bytes(raw) if raw else None,
                    )
                )
        for path in common_git.list_tree_paths(checkout, revision, "schemas"):
            if path.endswith(".json"):
                raw = common_git.show_file(checkout, revision, path)
                out.append(
                    GovernedArtifact(
                        path=path,
                        artifact_class="EAC_SCHEMA",
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
            name = Path(path).name
            if name not in {"example-manifest.json", "release-manifest.json"}:
                continue
            raw = common_git.show_file(checkout, transition.source_sha, path)
            if raw is None:
                continue
            example_id = Path(path).parent.name
            claim_id = f"eac-example:{example_id}:{name}"
            anchors.append(
                self.make_anchor(
                    transition,
                    family=FAMILY,
                    claim_id=claim_id,
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
                validator_id="eac-native",
                accepted=False,
                details={"reason": "missing_locator"},
            )
        raw = common_git.show_file(checkout, source_sha, locator)
        if raw is None:
            return NativeValidatorResult(
                status="OPERATIONAL_FAILURE",
                validator_id="eac-native",
                accepted=False,
                details={"reason": "manifest_absent"},
            )

        example_dir = str(Path(locator).parent)
        # Prefer example verify.sh when committed; else eac CLI lint on example.
        verify_sh = f"{example_dir}/verify.sh"
        if common_git.show_file(checkout, source_sha, verify_sh) is not None:
            command = self._run_in_source_worktree(
                checkout,
                source_sha,
                ["bash", verify_sh],
                cwd_relative=example_dir,
                timeout_sec=300,
            )
            validator_id = "eac-example-verify.sh"
        else:
            command = self._run_in_source_worktree(
                checkout,
                source_sha,
                [sys.executable, "-m", "envassure", "lint", example_dir],
                timeout_sec=300,
                env={
                    **{k: v for k, v in __import__("os").environ.items()},
                    "PYTHONPATH": "src",
                },
            )
            validator_id = "eac-lint"

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
            identity = data.get("name") or data.get("id") or Path(locator).parent.name
        except (UnicodeDecodeError, json.JSONDecodeError):
            identity = Path(locator).parent.name
        subject = _typed_digest(
            "rtk-eac-example-subject-v2",
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
