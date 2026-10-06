"""CertifyEdge source-universe-v0 adapter (expansion_v2).

Calls into authentic extract/materialize helpers; does not edit authentic blobs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..adapter_contract import GovernedArtifact, RepositoryIdentity
from . import common_git
from .v0_base import V0SourceAdapter


class CertifyEdgeAdapter(V0SourceAdapter):
    def __init__(self) -> None:
        super().__init__(
            RepositoryIdentity(
                repository="fraware/CertifyEdge",
                url="https://github.com/fraware/CertifyEdge",
                cutoff_sha="6ef02d54c4697886b20577f10eec683861475db2",
                role="SOURCE_UNIVERSE_V0",
            )
        )

    def discover_governed_artifacts(
        self,
        checkout: Path,
        revision: str,
    ) -> Sequence[GovernedArtifact]:
        artifacts: list[GovernedArtifact] = []
        for path in common_git.list_tree_paths(checkout, revision, "templates/profiles"):
            if not path.endswith(".json"):
                continue
            raw = common_git.show_file(checkout, revision, path)
            artifacts.append(
                GovernedArtifact(
                    path=path,
                    artifact_class="CERTIFYEDGE_PROPERTY_PROFILE",
                    sha256=common_git.sha256_bytes(raw) if raw is not None else None,
                )
            )
        for path in common_git.list_tree_paths(checkout, revision, "schemas/pcs"):
            if path.endswith(".json"):
                raw = common_git.show_file(checkout, revision, path)
                artifacts.append(
                    GovernedArtifact(
                        path=path,
                        artifact_class="CERTIFYEDGE_SCHEMA",
                        sha256=common_git.sha256_bytes(raw) if raw is not None else None,
                    )
                )
        return artifacts
