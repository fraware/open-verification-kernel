"""OVK consumer expansion adapters (FastAPI/Terraform and Express/Actions).

Source-side semantics derive from committed scenario fixtures/manifests and the
repository's pin-guard / scenario-matrix scripts — not filename heuristics alone.
"""

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


FAMILY = "OVK_CONSUMER_SCENARIO_V1"


class _OvkConsumerAdapterBase(ExpansionAdapterBase):
    def discover_governed_artifacts(
        self,
        checkout: Path,
        revision: str,
    ) -> Sequence[GovernedArtifact]:
        out: list[GovernedArtifact] = []
        for prefix, cls in (
            ("fixtures/manifests", "OVK_SCENARIO_MANIFEST"),
            ("fixtures/diffs", "OVK_SCENARIO_DIFF"),
            ("fixtures/inputs", "OVK_SCENARIO_INPUT"),
            ("schemas", "OVK_SCHEMA"),
            ("pilot", "OVK_PILOT_LEDGER"),
        ):
            for path in common_git.list_tree_paths(checkout, revision, prefix):
                raw = common_git.show_file(checkout, revision, path)
                out.append(
                    GovernedArtifact(
                        path=path,
                        artifact_class=cls,
                        sha256=common_git.sha256_bytes(raw) if raw else None,
                    )
                )
        pin_script = "scripts/assert_ovk_pin.py"
        if common_git.show_file(checkout, revision, pin_script) is not None:
            raw = common_git.show_file(checkout, revision, pin_script)
            out.append(
                GovernedArtifact(
                    path=pin_script,
                    artifact_class="OVK_PIN_GUARD",
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
        # One claim identity per committed scenario manifest at source revision.
        for path in common_git.list_tree_paths(
            checkout, transition.source_sha, "fixtures/manifests"
        ):
            if not path.endswith((".json", ".yml", ".yaml")):
                continue
            raw = common_git.show_file(checkout, transition.source_sha, path)
            if raw is None:
                continue
            stem = Path(path).stem
            claim_id = f"ovk-consumer-scenario:{stem}"
            anchors.append(
                self.make_anchor(
                    transition,
                    family=FAMILY,
                    claim_id=claim_id,
                    contract_locator=path,
                )
            )
        # Pin-guard claim when assert script exists (repository-level identity).
        pin_script = "scripts/assert_ovk_pin.py"
        if common_git.show_file(checkout, transition.source_sha, pin_script) is not None:
            anchors.append(
                self.make_anchor(
                    transition,
                    family=FAMILY,
                    claim_id="ovk-consumer-pin-guard:v1.2.1",
                    contract_locator=pin_script,
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
                validator_id="ovk-consumer-native",
                accepted=False,
                details={"reason": "missing_locator"},
            )

        if locator.endswith("assert_ovk_pin.py"):
            command = self._run_in_source_worktree(
                checkout,
                source_sha,
                [sys.executable, "scripts/assert_ovk_pin.py"],
                timeout_sec=120,
            )
            accepted = command.get("status") == "COMPLETED" and command.get("exit_code") == 0
            subject = _typed_digest(
                "rtk-ovk-pin-subject-v2",
                {"repository": self.repository, "source_sha": source_sha, "pin": "v1.2.1"},
            )
            return NativeValidatorResult(
                status="SOURCE_ACCEPTED" if accepted else (
                    "OPERATIONAL_FAILURE"
                    if command.get("status") != "COMPLETED"
                    else "SOURCE_REJECTED"
                ),
                validator_id="ovk-assert-pin",
                accepted=accepted,
                details={"subject_id": subject, "command": command, "locator": locator},
            )

        raw = common_git.show_file(checkout, source_sha, locator)
        if raw is None:
            return NativeValidatorResult(
                status="OPERATIONAL_FAILURE",
                validator_id="ovk-scenario-manifest",
                accepted=False,
                details={"reason": "manifest_absent"},
            )
        # Structural source-side check: manifest must be JSON object with scenario identity.
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return NativeValidatorResult(
                status="SOURCE_REJECTED",
                validator_id="ovk-scenario-manifest",
                accepted=False,
                details={"reason": "malformed_manifest"},
            )
        if not isinstance(data, dict):
            return NativeValidatorResult(
                status="SOURCE_REJECTED",
                validator_id="ovk-scenario-manifest",
                accepted=False,
                details={"reason": "manifest_not_object"},
            )
        # Full scenario-matrix execution requires pinned OVK wheel/Action; record
        # as unsupported native validator when only structural surface is present.
        subject = _typed_digest(
            "rtk-ovk-scenario-subject-v2",
            {
                "locator": locator,
                "bytes_sha256": common_git.sha256_bytes(raw),
                "keys": sorted(data.keys()),
            },
        )
        return NativeValidatorResult(
            status="UNSUPPORTED_NATIVE_VALIDATOR",
            validator_id="ovk-scenario-matrix-requires-ovk-1.2.1",
            accepted=False,
            details={
                "subject_id": subject,
                "reason": (
                    "Committed scenario manifests are present, but source-revision "
                    "native replay requires the pinned OVK 1.2.1 action/wheel which "
                    "is not executed as a Tier-A substitute from structure alone."
                ),
                "locator": locator,
            },
        )


class OvkConsumerFastapiTerraformAdapter(_OvkConsumerAdapterBase):
    def __init__(self) -> None:
        super().__init__(
            RepositoryIdentity(
                repository="fraware/ovk-consumer-fastapi-terraform",
                url="https://github.com/fraware/ovk-consumer-fastapi-terraform",
                cutoff_sha="784576bc5fd01ac80092662887a896301d4fe186",
                role="EXPANSION_CANDIDATE",
            )
        )


class OvkConsumerExpressActionsAdapter(_OvkConsumerAdapterBase):
    def __init__(self) -> None:
        super().__init__(
            RepositoryIdentity(
                repository="fraware/ovk-consumer-express-actions",
                url="https://github.com/fraware/ovk-consumer-express-actions",
                cutoff_sha="31aed31a04c7bca67d3bd6151caf1e42f4b7d1f8",
                role="EXPANSION_CANDIDATE",
            )
        )
