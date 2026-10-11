"""Shared base for frozen expansion-candidate adapters."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from abc import abstractmethod
from pathlib import Path
from typing import Any, Sequence

from ..adapter_contract import (
    ClaimAnchor,
    EvidenceSnapshot,
    GovernedArtifact,
    NativeValidatorResult,
    RepositoryIdentity,
    SourceEvidenceCandidate,
    SourceRepositoryAdapter,
    SubjectBinding,
    TransitionEnumerationRecord,
)
from . import common_git


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _typed_digest(tag: str, value: Any) -> str:
    return _sha256(tag.encode("utf-8") + b"\x00" + _canonical_bytes(value))


def _anchor_id(
    repository: str,
    source: str,
    target: str,
    family: str,
    claim_id: str,
    contract_locator: str,
) -> str:
    material = "\x00".join(
        ("rtk-anchor-v1", repository, source, target, family, claim_id, contract_locator)
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class ExpansionAdapterBase(SourceRepositoryAdapter):
    """Repository-specific expansion adapter with shared census/snapshot helpers."""

    def __init__(self, identity: RepositoryIdentity) -> None:
        self._identity = identity
        self._command_cache: dict[tuple[Any, ...], dict[str, Any]] = {}

    @property
    def identity(self) -> RepositoryIdentity:
        return self._identity

    @property
    def implementation_status(self) -> str:
        return "READY_FOR_MATERIALIZATION"

    def enumerate_transitions(
        self,
        checkout: Path,
        *,
        cutoff_sha: str | None = None,
    ) -> Sequence[TransitionEnumerationRecord]:
        cutoff = cutoff_sha or self.identity.cutoff_sha
        # Uniform with sealed v0 admission: every FIRST_PARENT edge is ELIGIBLE.
        # Later stages record zero-anchor / validator failures with reason codes.
        return common_git.enumerate_first_parent_transitions(
            checkout,
            repository=self.repository,
            cutoff_sha=cutoff,
        )

    @abstractmethod
    def discover_governed_artifacts(
        self,
        checkout: Path,
        revision: str,
    ) -> Sequence[GovernedArtifact]:
        raise NotImplementedError

    @abstractmethod
    def extract_claim_anchors(
        self,
        checkout: Path,
        transition: TransitionEnumerationRecord,
    ) -> Sequence[ClaimAnchor]:
        raise NotImplementedError

    def discover_source_evidence_candidates(
        self,
        checkout: Path,
        anchor: ClaimAnchor,
    ) -> Sequence[SourceEvidenceCandidate]:
        return [
            SourceEvidenceCandidate(
                candidate_id=f"primary:{anchor.anchor_id}",
                anchor_id=anchor.anchor_id,
                paths=(anchor.contract_locator,),
                discovery_rule=f"{self.repository}:contract_locator",
            )
        ]

    @abstractmethod
    def execute_source_revision_native_validator(
        self,
        checkout: Path,
        candidate: SourceEvidenceCandidate,
        *,
        source_sha: str,
    ) -> NativeValidatorResult:
        raise NotImplementedError

    def bind_subject(
        self,
        anchor: ClaimAnchor,
        validator_result: NativeValidatorResult,
    ) -> SubjectBinding:
        details = dict(validator_result.details)
        subject = details.get("subject_id")
        if not isinstance(subject, str) or not subject:
            subject = _typed_digest(
                "rtk-expansion-subject-v2",
                {
                    "anchor_id": anchor.anchor_id,
                    "claim_id": anchor.claim_id,
                    "accepted": validator_result.accepted,
                    "status": validator_result.status,
                },
            )
        binding_digest = _typed_digest(
            "rtk-subject-binding-v0",
            subject,
        )
        return SubjectBinding(
            subject_id=str(subject),
            anchor_id=anchor.anchor_id,
            binding_digest=binding_digest,
            payload=details,
        )

    def construct_evidence_snapshot(
        self,
        checkout: Path,
        binding: SubjectBinding,
        *,
        source_sha: str,
        artifacts: Sequence[GovernedArtifact],
        policy: dict[str, Any] | None = None,
    ) -> EvidenceSnapshot:
        art_rows = []
        for artifact in artifacts:
            digest = artifact.sha256
            if digest is None:
                raw = common_git.show_file(checkout, source_sha, artifact.path)
                digest = common_git.sha256_bytes(raw) if raw is not None else ""
            art_rows.append({"path": artifact.path, "role": artifact.artifact_class, "sha256": digest})
        art_rows_sorted = tuple(
            sorted(art_rows, key=lambda r: (r["role"], r["path"], r["sha256"]))
        )
        policy_obj = policy or {
            "policy_id": f"expansion_v2:{self.repository}",
            "source_bytes_only": True,
            "selection": "native_accept_with_subject_binding",
        }
        digest = _typed_digest(
            "rtk-evidence-snapshot-v0",
            {
                "repository": self.repository,
                "revision": source_sha,
                "binding_digest": binding.binding_digest,
                "artifacts": list(art_rows_sorted),
                "policy": policy_obj,
            },
        )
        return EvidenceSnapshot(
            snapshot_id=f"snap:{digest[:32]}",
            repository=self.repository,
            revision=source_sha,
            digest=digest,
            artifacts=art_rows_sorted,
            completeness_policy=policy_obj,
        )

    def make_anchor(
        self,
        transition: TransitionEnumerationRecord,
        *,
        family: str,
        claim_id: str,
        contract_locator: str,
        extra: dict[str, Any] | None = None,
    ) -> ClaimAnchor:
        aid = _anchor_id(
            transition.repository,
            transition.source_sha,
            transition.target_sha,
            family,
            claim_id,
            contract_locator,
        )
        payload = {
            "anchor_id": aid,
            "transition_id": transition.transition_id,
            "contract_locator": contract_locator,
            "repository": transition.repository,
            "source_sha": transition.source_sha,
            "target_sha": transition.target_sha,
            "family": family,
            "claim_id": claim_id,
            "materialization_status": "PENDING",
            "source_evidence_manifest_digest": None,
        }
        if extra:
            payload.update(extra)
        return ClaimAnchor(
            anchor_id=aid,
            repository=transition.repository,
            family=family,
            claim_id=claim_id,
            contract_locator=contract_locator,
            source_sha=transition.source_sha,
            target_sha=transition.target_sha,
            payload=payload,
        )

    def _run_in_source_worktree(
        self,
        checkout: Path,
        source_sha: str,
        argv: list[str],
        *,
        cwd_relative: str = ".",
        timeout_sec: int = 600,
        env: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        cache_key = (source_sha, tuple(argv), cwd_relative)
        cached = self._command_cache.get(cache_key)
        if cached is not None:
            return dict(cached)

        mse_work = tempfile.mkdtemp(prefix="rtk-exp-wt-")
        worktree = Path(mse_work) / source_sha
        try:
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(checkout),
                    "worktree",
                    "add",
                    "--detach",
                    "--force",
                    str(worktree),
                    source_sha,
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            cwd = worktree / cwd_relative
            proc = subprocess.run(
                argv,
                cwd=str(cwd),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=timeout_sec,
            )
            result = {
                "status": "COMPLETED",
                "exit_code": proc.returncode,
                "argv": argv,
                "stdout_sha256": _sha256(proc.stdout),
                "stderr_sha256": _sha256(proc.stderr),
            }
            self._command_cache[cache_key] = result
            return dict(result)
        except subprocess.TimeoutExpired:
            result = {
                "status": "TIMEOUT",
                "exit_code": None,
                "argv": argv,
            }
            self._command_cache[cache_key] = result
            return dict(result)
        except Exception as exc:  # noqa: BLE001 — recorded as operational failure
            result = {
                "status": "OPERATIONAL_FAILURE",
                "exit_code": None,
                "argv": argv,
                "error": str(exc),
            }
            self._command_cache[cache_key] = result
            return dict(result)
        finally:
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(checkout),
                    "worktree",
                    "remove",
                    "--force",
                    str(worktree),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            import shutil

            shutil.rmtree(mse_work, ignore_errors=True)
