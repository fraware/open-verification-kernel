"""expansion_v2 materialization pipeline (pre-oracle).

Flow per repository: census_v2 → extract/anchors → materialize → project → tier_v1.
Does not invoke RTK, oracle labels, baselines, or unblinding.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from .adapter_contract import (
    ClaimAnchor,
    SourceRepositoryAdapter,
    TransitionEnumerationRecord,
)
from .adapters.v0_base import V0SourceAdapter
from .adapters.v0_bridge import project_record
from .generate_transition_census_v2 import (
    build_manifest,
    records_to_jsonl_bytes,
)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_jsonl(path: Path, rows: Sequence[Mapping[str, Any]]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = b"".join(_canonical_bytes(dict(row)) + b"\n" for row in rows)
    path.write_bytes(payload)
    return _sha256(payload)


def write_json(path: Path, value: Mapping[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _canonical_bytes(dict(value)) + b"\n"
    path.write_bytes(payload)
    return _sha256(payload)


@dataclass
class RepoPipelineResult:
    repository: str
    cutoff_sha: str
    first_parent_transitions: int = 0
    eligible_transitions: int = 0
    excluded_transitions: int = 0
    anchors: int = 0
    source_evidence_status_counts: dict[str, int] = field(default_factory=dict)
    tier_a_transitions: int = 0
    tier_a_anchors: int = 0
    tier_b_transitions: int = 0
    tier_b_anchors: int = 0
    reason_coded_failures: dict[str, int] = field(default_factory=dict)
    census_jsonl_sha256: str | None = None
    anchors_jsonl_sha256: str | None = None
    evidence_jsonl_sha256: str | None = None
    semantic_jsonl_sha256: str | None = None
    tiered_jsonl_sha256: str | None = None
    outcome: str = "PROCESSED"
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "cutoff_sha": self.cutoff_sha,
            "first_parent_transitions": self.first_parent_transitions,
            "eligible_transitions": self.eligible_transitions,
            "excluded_transitions": self.excluded_transitions,
            "anchors": self.anchors,
            "source_evidence_status_counts": dict(
                sorted(self.source_evidence_status_counts.items())
            ),
            "tier_a_replay_verified": {
                "transition_count": self.tier_a_transitions,
                "anchor_count": self.tier_a_anchors,
            },
            "tier_b_committed_native_attestation": {
                "transition_count": self.tier_b_transitions,
                "anchor_count": self.tier_b_anchors,
            },
            "reason_coded_failures": dict(sorted(self.reason_coded_failures.items())),
            "digests": {
                "census_jsonl_sha256": self.census_jsonl_sha256,
                "anchors_jsonl_sha256": self.anchors_jsonl_sha256,
                "evidence_jsonl_sha256": self.evidence_jsonl_sha256,
                "semantic_jsonl_sha256": self.semantic_jsonl_sha256,
                "tiered_jsonl_sha256": self.tiered_jsonl_sha256,
            },
            "outcome": self.outcome,
            "notes": list(self.notes),
        }


def _evidence_from_validator(
    adapter: SourceRepositoryAdapter,
    checkout: Path,
    anchor: ClaimAnchor,
    *,
    timeout_sec: int = 300,
) -> dict[str, Any]:
    candidates = list(adapter.discover_source_evidence_candidates(checkout, anchor))
    if not candidates:
        return {
            "anchor_id": anchor.anchor_id,
            "transition_id": anchor.payload.get("transition_id"),
            "repository": anchor.repository,
            "source_sha": anchor.source_sha,
            "family": anchor.family,
            "claim_id": anchor.claim_id,
            "contract_locator": anchor.contract_locator,
            "materialization_status": "NO_CANDIDATES",
            "subject_binding": None,
            "selected_candidate_id": None,
            "native_verifier_digest": None,
            "evidence_snapshot": None,
            "candidates": [],
            "environment": {},
            "target_native_validator_executed": False,
            "rtk_executed": False,
            "oracle_labels_consulted": False,
            "notes": ["no source-evidence candidates"],
        }

    # Evaluate primary candidate (deterministic first by candidate_id).
    candidates = sorted(candidates, key=lambda c: c.candidate_id)
    selected_meta = None
    validator = None
    for cand in candidates:
        validator = adapter.execute_source_revision_native_validator(
            checkout, cand, source_sha=anchor.source_sha
        )
        selected_meta = cand
        if validator.accepted:
            break
    assert selected_meta is not None and validator is not None

    status = validator.status
    subject_binding = None
    selected_candidate_id = None
    evidence_snapshot = None
    cand_rows = []
    for cand in candidates:
        accepted = bool(validator.accepted and cand.candidate_id == selected_meta.candidate_id)
        cand_rows.append(
            {
                "candidate_id": cand.candidate_id,
                "locator": cand.paths[0] if cand.paths else None,
                "artifacts": [
                    {"path": p, "sha256": None} for p in cand.paths
                ],
                "native_accept": accepted,
                "subject_binding": None,
                "rejection_reason": None if accepted else validator.status,
                "native_command_outcomes": [
                    {
                        "status": (validator.details.get("command") or {}).get("status"),
                        "exit_code": (validator.details.get("command") or {}).get(
                            "exit_code"
                        ),
                    }
                ],
            }
        )

    if validator.accepted:
        binding = adapter.bind_subject(anchor, validator)
        arts = list(adapter.discover_governed_artifacts(checkout, anchor.source_sha))
        # Restrict snapshot artifacts to the accepted candidate paths when possible.
        path_set = set(selected_meta.paths)
        snap_arts = [a for a in arts if a.path in path_set] or arts[:1]
        snapshot = adapter.construct_evidence_snapshot(
            checkout,
            binding,
            source_sha=anchor.source_sha,
            artifacts=snap_arts,
        )
        subject_binding = binding.binding_digest
        selected_candidate_id = selected_meta.candidate_id
        evidence_snapshot = {
            "snapshot_id": snapshot.snapshot_id,
            "digest": snapshot.digest,
            "repository": snapshot.repository,
            "revision": snapshot.revision,
            "artifacts": list(snapshot.artifacts),
            "completeness_policy": dict(snapshot.completeness_policy),
        }
        for row in cand_rows:
            if row["candidate_id"] == selected_candidate_id:
                row["subject_binding"] = subject_binding
                row["native_accept"] = True
                row["rejection_reason"] = None

    return {
        "anchor_id": anchor.anchor_id,
        "transition_id": anchor.payload.get("transition_id"),
        "repository": anchor.repository,
        "source_sha": anchor.source_sha,
        "family": anchor.family,
        "claim_id": anchor.claim_id,
        "contract_locator": anchor.contract_locator,
        "materialization_status": status,
        "subject_binding": subject_binding,
        "selected_candidate_id": selected_candidate_id,
        "native_verifier_digest": validator.validator_id,
        "evidence_snapshot": evidence_snapshot,
        "candidates": cand_rows,
        "environment": {"validator_details": dict(validator.details)},
        "target_native_validator_executed": False,
        "rtk_executed": False,
        "oracle_labels_consulted": False,
        "notes": [],
    }


def _tier_expansion_records(semantic_rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Apply Tier A policy without promoting Tier B.

    Tier A = SOURCE_ACCEPTED with subject binding + evidence snapshot (replay).
    Expansion adapters do not mint COMMITTED_NATIVE_ATTESTATION Tier B here.
    """
    out: list[dict[str, Any]] = []
    for row in semantic_rows:
        record = dict(row)
        status = row.get("materialization_status")
        if (
            status == "SOURCE_ACCEPTED"
            and row.get("subject_binding")
            and row.get("evidence_snapshot")
        ):
            record["source_evidence_class"] = "REPLAY_VERIFIED"
            record["tiering_amendment_applied"] = True
        else:
            record["source_evidence_class"] = None
            record["tiering_amendment_applied"] = True
        record["attestation_candidates"] = []
        out.append(record)
    return out


def process_repository(
    adapter: SourceRepositoryAdapter,
    checkout: Path,
    out_dir: Path,
    *,
    timeout_sec: int = 300,
    materialize_v0_via_authentic: bool = True,
    work_root: Path | None = None,
) -> RepoPipelineResult:
    result = RepoPipelineResult(
        repository=adapter.repository,
        cutoff_sha=adapter.identity.cutoff_sha,
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    transitions = list(
        adapter.enumerate_transitions(checkout, cutoff_sha=adapter.identity.cutoff_sha)
    )
    result.first_parent_transitions = len(transitions)
    result.eligible_transitions = sum(1 for t in transitions if t.eligibility == "ELIGIBLE")
    result.excluded_transitions = sum(1 for t in transitions if t.eligibility != "ELIGIBLE")
    for t in transitions:
        if t.eligibility != "ELIGIBLE" and t.exclusion_reason:
            result.reason_coded_failures[t.exclusion_reason] = (
                result.reason_coded_failures.get(t.exclusion_reason, 0) + 1
            )

    census_bytes = records_to_jsonl_bytes(transitions)
    census_path = out_dir / "TRANSITION_CENSUS.overlay.jsonl"
    census_path.write_bytes(census_bytes)
    result.census_jsonl_sha256 = _sha256(census_bytes)
    manifest = build_manifest(
        records=transitions,
        jsonl_sha256=result.census_jsonl_sha256,
        repositories=[adapter.repository],
    )
    write_json(out_dir / "TRANSITION_CENSUS.overlay.MANIFEST.json", manifest)

    anchors: list[ClaimAnchor] = []
    for transition in transitions:
        if transition.eligibility != "ELIGIBLE":
            continue
        anchors.extend(adapter.extract_claim_anchors(checkout, transition))
    anchors.sort(
        key=lambda a: (
            a.repository,
            a.target_sha,
            a.family,
            a.claim_id,
            a.contract_locator,
            a.anchor_id,
        )
    )
    result.anchors = len(anchors)
    anchor_rows = [dict(a.payload) if a.payload else {
        "anchor_id": a.anchor_id,
        "repository": a.repository,
        "family": a.family,
        "claim_id": a.claim_id,
        "contract_locator": a.contract_locator,
        "source_sha": a.source_sha,
        "target_sha": a.target_sha,
    } for a in anchors]
    result.anchors_jsonl_sha256 = write_jsonl(out_dir / "HISTORICAL_ANCHORS.overlay.jsonl", anchor_rows)

    evidence_rows: list[dict[str, Any]] = []
    if isinstance(adapter, V0SourceAdapter) and materialize_v0_via_authentic:
        # Group by source_sha for authentic materializer efficiency.
        from collections import defaultdict

        grouped: dict[str, list[ClaimAnchor]] = defaultdict(list)
        for anchor in anchors:
            grouped[anchor.source_sha].append(anchor)
        root = work_root or Path(tempfile.mkdtemp(prefix="rtk-v0-pipe-"))
        for source_sha, members in sorted(grouped.items()):
            cache: dict[str, Any] = {}
            for anchor in sorted(members, key=lambda a: a.anchor_id):
                record = adapter.materialize_anchor_record(
                    checkout,
                    anchor,
                    timeout_sec=timeout_sec,
                    work_root=root,
                    cache=cache,
                )
                evidence_rows.append(record)
    else:
        for anchor in anchors:
            evidence_rows.append(
                _evidence_from_validator(
                    adapter, checkout, anchor, timeout_sec=timeout_sec
                )
            )

    evidence_rows.sort(key=lambda r: str(r["anchor_id"]))
    result.evidence_jsonl_sha256 = write_jsonl(
        out_dir / "SOURCE_EVIDENCE.overlay.jsonl", evidence_rows
    )
    for row in evidence_rows:
        status = str(row.get("materialization_status"))
        result.source_evidence_status_counts[status] = (
            result.source_evidence_status_counts.get(status, 0) + 1
        )

    semantic_rows = [project_record(row) for row in evidence_rows]
    semantic_rows.sort(key=lambda r: str(r["anchor_id"]))
    result.semantic_jsonl_sha256 = write_jsonl(
        out_dir / "SOURCE_EVIDENCE_SEMANTIC.overlay.jsonl", semantic_rows
    )

    if isinstance(adapter, V0SourceAdapter):
        # For v0 compatibility path, authentic tier_v1 is applied by the
        # dedicated compatibility harness against sealed inputs. Overlay tier
        # counts for v0 are taken from SOURCE_ACCEPTED only here.
        tiered = []
        for row in semantic_rows:
            rec = dict(row)
            if row.get("materialization_status") == "SOURCE_ACCEPTED":
                rec["source_evidence_class"] = "REPLAY_VERIFIED"
            else:
                rec["source_evidence_class"] = None
            tiered.append(rec)
    else:
        tiered = _tier_expansion_records(semantic_rows)

    result.tiered_jsonl_sha256 = write_jsonl(
        out_dir / "SOURCE_EVIDENCE_TIERED.overlay.jsonl", tiered
    )
    replay_anchors = {
        r["anchor_id"]
        for r in tiered
        if r.get("source_evidence_class") == "REPLAY_VERIFIED"
    }
    replay_transitions = {
        r.get("transition_id")
        for r in tiered
        if r.get("source_evidence_class") == "REPLAY_VERIFIED" and r.get("transition_id")
    }
    result.tier_a_anchors = len(replay_anchors)
    result.tier_a_transitions = len(replay_transitions)

    attested_anchors = {
        r["anchor_id"]
        for r in tiered
        if r.get("source_evidence_class") == "COMMITTED_NATIVE_ATTESTATION"
    }
    attested_transitions = {
        r.get("transition_id")
        for r in tiered
        if r.get("source_evidence_class") == "COMMITTED_NATIVE_ATTESTATION"
        and r.get("transition_id")
    }
    result.tier_b_anchors = len(attested_anchors)
    result.tier_b_transitions = len(attested_transitions)

    write_json(out_dir / "REPO_PIPELINE_RESULT.json", result.as_dict())
    return result


def extract_all_v0_anchors(
    adapters: Mapping[str, SourceRepositoryAdapter],
    checkouts: Mapping[str, Path],
    transitions: Sequence[TransitionEnumerationRecord],
) -> list[dict[str, Any]]:
    """Extract authentic-equivalent anchors for sealed census transitions."""
    rows: list[dict[str, Any]] = []
    for transition in transitions:
        if transition.eligibility != "ELIGIBLE":
            continue
        adapter = adapters[transition.repository]
        checkout = checkouts[transition.repository]
        for anchor in adapter.extract_claim_anchors(checkout, transition):
            rows.append(dict(anchor.payload))
    rows.sort(
        key=lambda row: (
            str(row["repository"]),
            str(row["target_sha"]),
            str(row["family"]),
            str(row["claim_id"]),
            str(row["contract_locator"]),
            str(row["anchor_id"]),
        )
    )
    return rows
