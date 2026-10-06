"""pcs-core source-universe-v0 adapter (expansion_v2).

Calls into authentic extract/materialize helpers; does not edit authentic blobs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..adapter_contract import GovernedArtifact, RepositoryIdentity
from . import common_git
from .v0_base import V0SourceAdapter


class PcsCoreAdapter(V0SourceAdapter):
    def __init__(self) -> None:
        super().__init__(
            RepositoryIdentity(
                repository="SentinelOps-CI/pcs-core",
                url="https://github.com/SentinelOps-CI/pcs-core",
                cutoff_sha="9c971f5f9da8a424924dd8f48d6a3b71a1009e1b",
                role="SOURCE_UNIVERSE_V0",
            )
        )

    def discover_governed_artifacts(
        self,
        checkout: Path,
        revision: str,
    ) -> Sequence[GovernedArtifact]:
        artifacts: list[GovernedArtifact] = []
        for path in common_git.list_tree_paths(
            checkout, revision, "examples/workflow_profiles"
        ):
            if not path.endswith(".json"):
                continue
            raw = common_git.show_file(checkout, revision, path)
            artifacts.append(
                GovernedArtifact(
                    path=path,
                    artifact_class="PCS_WORKFLOW_PROFILE",
                    sha256=common_git.sha256_bytes(raw) if raw is not None else None,
                )
            )
        for path in common_git.list_tree_paths(
            checkout, revision, "examples/verifier_assurance"
        ):
            if not path.endswith(".json"):
                continue
            raw = common_git.show_file(checkout, revision, path)
            artifacts.append(
                GovernedArtifact(
                    path=path,
                    artifact_class="PCS_VERIFIER_PROFILE_V1",
                    sha256=common_git.sha256_bytes(raw) if raw is not None else None,
                )
            )
        return artifacts
