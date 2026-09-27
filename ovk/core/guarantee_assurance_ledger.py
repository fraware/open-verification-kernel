"""Signed, content-addressed ledger for durable guarantee assurance snapshots.

The ledger commits to assurance admission results; it does not re-run proof
engines or replace the underlying VerificationEvidence records. Each state keeps
its admitted evidence digest, so an independent audit can retrieve and verify the
referenced evidence separately.

A non-genesis ledger entry is valid only when its predecessor is supplied and:
- the predecessor entry is self-valid;
- repository identity is unchanged;
- current subject_base_sha equals predecessor subject_head_sha;
- previous entry/snapshot digests match exactly;
- sequence increments by one; and
- the stored guarantee deltas equal a deterministic recomputation.

The entire entry is content-addressed and signed with the existing OVK HMAC
attestation primitive.
"""

from __future__ import annotations

import hmac
from typing import Literal

from pydantic import BaseModel, Field

from ovk.core.attestation_signing import SIGNATURE_ALG, sign_payload
from ovk.core.bundle import content_digest
from ovk.core.evidence_integrity import utc_now_iso
from ovk.core.guarantee_assurance_state import (
    GuaranteeAssuranceSnapshot,
    GuaranteeAssuranceState,
    GuaranteeAssuranceStatus,
    GuaranteeEvidenceOrigin,
)


LEDGER_SCHEMA_VERSION = "ovk.guarantee_assurance_ledger.v1"

GuaranteeLedgerDeltaKind = Literal[
    "new_guarantee",
    "removed_guarantee",
    "current_established_fresh",
    "current_established_reused",
    "assurance_established",
    "assurance_lost",
    "violation_observed",
    "violation_no_longer_observed",
    "status_unchanged",
    "status_changed",
]


class GuaranteeAssuranceDelta(BaseModel):
    """Deterministic state delta for one durable guarantee."""

    guarantee_id: str
    kind: GuaranteeLedgerDeltaKind
    base_status: GuaranteeAssuranceStatus | None = None
    head_status: GuaranteeAssuranceStatus | None = None
    base_definition_digest: str | None = None
    head_definition_digest: str | None = None
    base_semantic_slice_digest: str | None = None
    head_semantic_slice_digest: str | None = None
    head_evidence_origin: GuaranteeEvidenceOrigin | None = None
    head_evidence_digest: str | None = None
    reason_codes: list[str] = Field(default_factory=list)


class GuaranteeAssuranceLedgerEntry(BaseModel):
    """Signed assurance snapshot plus its predecessor linkage and deltas."""

    schema_version: Literal["ovk.guarantee_assurance_ledger.v1"] = (
        "ovk.guarantee_assurance_ledger.v1"
    )
    sequence: int = Field(ge=0)
    created_at: str

    snapshot: GuaranteeAssuranceSnapshot
    snapshot_digest: str

    previous_entry_digest: str | None = None
    previous_snapshot_digest: str | None = None

    deltas: list[GuaranteeAssuranceDelta] = Field(default_factory=list)

    entry_digest: str
    signature: dict[str, str]


class GuaranteeAssuranceLedgerVerification(BaseModel):
    """Machine-readable ledger verification result."""

    valid: bool
    reason_codes: list[str] = Field(default_factory=list)
    entry_digest: str | None = None
    sequence: int | None = None


def compute_guarantee_assurance_snapshot_digest(
    snapshot: GuaranteeAssuranceSnapshot,
) -> str:
    """Return the canonical content identity of one admitted assurance snapshot."""

    return content_digest(snapshot.model_dump(mode="json"))


def _state_index(
    snapshot: GuaranteeAssuranceSnapshot,
) -> dict[str, GuaranteeAssuranceState]:
    index: dict[str, GuaranteeAssuranceState] = {}
    for state in snapshot.states:
        if state.guarantee_id in index:
            raise ValueError(
                f"duplicate guarantee state in snapshot: {state.guarantee_id}"
            )
        index[state.guarantee_id] = state
    return index


def validate_guarantee_assurance_snapshot_structure(
    snapshot: GuaranteeAssuranceSnapshot,
) -> list[str]:
    """Return structural invariant violations for an assurance snapshot.

    This validates the consistency of the admitted state representation. It does
    not independently retrieve or revalidate the VerificationEvidence objects
    referenced by evidence_digest.
    """

    reasons: list[str] = []
    graph = snapshot.graph

    if graph.assurance_ir_digest != snapshot.assurance_ir_digest:
        reasons.append("graph_ir_digest_mismatch")
    if graph.subject_repo != snapshot.subject_repo:
        reasons.append("graph_repository_mismatch")
    if graph.subject_head_sha != snapshot.subject_head_sha:
        reasons.append("graph_head_revision_mismatch")
    if not snapshot.policy_digest.strip():
        reasons.append("empty_policy_digest")

    try:
        states = _state_index(snapshot)
    except ValueError:
        reasons.append("duplicate_guarantee_state")
        return sorted(set(reasons))

    binding_by_id = {}
    for binding in graph.bindings:
        if binding.guarantee_id in binding_by_id:
            reasons.append("duplicate_guarantee_binding")
        binding_by_id[binding.guarantee_id] = binding

    expected_ids = set(graph.spec_definition_digests)
    if set(states) != expected_ids:
        reasons.append("state_set_mismatch")
    if set(binding_by_id) != expected_ids:
        reasons.append("binding_set_mismatch")
    if set(graph.dependency_edges) != expected_ids:
        reasons.append("dependency_edge_set_mismatch")

    for guarantee_id in sorted(expected_ids & set(states) & set(binding_by_id)):
        state = states[guarantee_id]
        binding = binding_by_id[guarantee_id]

        if state.binding != binding:
            reasons.append(f"binding_payload_mismatch:{guarantee_id}")
        if (
            state.guarantee_definition_digest
            != graph.spec_definition_digests[guarantee_id]
        ):
            reasons.append(f"definition_digest_mismatch:{guarantee_id}")

        expected_dependencies = sorted(graph.dependency_edges[guarantee_id])
        if sorted(state.dependencies) != expected_dependencies:
            reasons.append(f"dependency_list_mismatch:{guarantee_id}")
        if sorted(state.dependency_statuses) != expected_dependencies:
            reasons.append(f"dependency_status_set_mismatch:{guarantee_id}")

        if binding.status != "bound":
            if state.local_status != "unbound" or state.status != "unbound":
                reasons.append(f"unbound_state_mismatch:{guarantee_id}")
            if state.evidence_digest is not None or state.evidence_origin is not None:
                reasons.append(f"unbound_state_has_evidence:{guarantee_id}")
            continue

        if state.local_status == "unbound":
            reasons.append(f"bound_state_marked_unbound:{guarantee_id}")

        if state.local_status == "established":
            if not state.evidence_digest:
                reasons.append(f"established_missing_evidence_digest:{guarantee_id}")
            if state.evidence_origin not in {"fresh", "reused"}:
                reasons.append(f"established_missing_evidence_origin:{guarantee_id}")
            if state.protected_effect_claim_status != "pass":
                reasons.append(f"established_without_pass_claim:{guarantee_id}")

        dependency_values = list(state.dependency_statuses.values())
        all_dependencies_established = all(
            value == "established" for value in dependency_values
        )

        if state.status == "established":
            if state.local_status != "established":
                reasons.append(f"established_local_status_mismatch:{guarantee_id}")
            if not all_dependencies_established:
                reasons.append(f"established_dependency_mismatch:{guarantee_id}")
        elif state.status == "dependency_unestablished":
            if state.local_status != "established":
                reasons.append(
                    f"dependency_unestablished_local_mismatch:{guarantee_id}"
                )
            if all_dependencies_established:
                reasons.append(
                    f"dependency_unestablished_without_failed_dependency:{guarantee_id}"
                )
        elif state.local_status != state.status:
            reasons.append(f"local_final_status_mismatch:{guarantee_id}")

    for guarantee_id, state in states.items():
        for dependency, recorded_status in state.dependency_statuses.items():
            target = states.get(dependency)
            if target is None:
                reasons.append(
                    f"dependency_status_references_missing_state:{guarantee_id}:{dependency}"
                )
            elif recorded_status != target.status:
                reasons.append(
                    f"dependency_status_value_mismatch:{guarantee_id}:{dependency}"
                )

    return sorted(set(reasons))


def _semantic_digest(state: GuaranteeAssuranceState | None) -> str | None:
    if state is None:
        return None
    return state.binding.semantic_slice_digest


def _delta_kind(
    base: GuaranteeAssuranceState | None,
    head: GuaranteeAssuranceState | None,
) -> GuaranteeLedgerDeltaKind:
    if base is None:
        return "new_guarantee"
    if head is None:
        return "removed_guarantee"

    if base.status == "established" and head.status == "established":
        if head.evidence_origin == "reused":
            return "current_established_reused"
        return "current_established_fresh"

    if base.status != "established" and head.status == "established":
        return "assurance_established"
    if base.status == "established" and head.status != "established":
        return "assurance_lost"

    if base.status != "violated" and head.status == "violated":
        return "violation_observed"
    if base.status == "violated" and head.status != "violated":
        return "violation_no_longer_observed"

    if base.status == head.status:
        return "status_unchanged"
    return "status_changed"


def compute_guarantee_assurance_deltas(
    base: GuaranteeAssuranceSnapshot | None,
    head: GuaranteeAssuranceSnapshot,
) -> list[GuaranteeAssuranceDelta]:
    """Deterministically compare admitted guarantee states."""

    base_states = _state_index(base) if base is not None else {}
    head_states = _state_index(head)

    deltas: list[GuaranteeAssuranceDelta] = []
    for guarantee_id in sorted(set(base_states) | set(head_states)):
        old = base_states.get(guarantee_id)
        new = head_states.get(guarantee_id)

        reasons: list[str] = []
        if (
            old is not None
            and new is not None
            and old.guarantee_definition_digest
            != new.guarantee_definition_digest
        ):
            reasons.append("guarantee_definition_changed")
        if _semantic_digest(old) != _semantic_digest(new):
            reasons.append("semantic_support_changed")
        if new is not None:
            reasons.extend(new.reason_codes)

        deltas.append(
            GuaranteeAssuranceDelta(
                guarantee_id=guarantee_id,
                kind=_delta_kind(old, new),
                base_status=old.status if old is not None else None,
                head_status=new.status if new is not None else None,
                base_definition_digest=(
                    old.guarantee_definition_digest
                    if old is not None
                    else None
                ),
                head_definition_digest=(
                    new.guarantee_definition_digest
                    if new is not None
                    else None
                ),
                base_semantic_slice_digest=_semantic_digest(old),
                head_semantic_slice_digest=_semantic_digest(new),
                head_evidence_origin=(
                    new.evidence_origin if new is not None else None
                ),
                head_evidence_digest=(
                    new.evidence_digest if new is not None else None
                ),
                reason_codes=sorted(set(reasons)),
            )
        )
    return deltas


def _entry_digest_payload(
    entry: GuaranteeAssuranceLedgerEntry | dict,
) -> dict:
    payload = (
        entry.model_dump(mode="json")
        if isinstance(entry, GuaranteeAssuranceLedgerEntry)
        else dict(entry)
    )
    return {
        key: value
        for key, value in payload.items()
        if key not in {"entry_digest", "signature"}
    }


def compute_guarantee_assurance_entry_digest(
    entry: GuaranteeAssuranceLedgerEntry | dict,
) -> str:
    """Compute the content identity of a ledger entry."""

    return content_digest(_entry_digest_payload(entry))


def _unsigned_entry_payload(
    entry: GuaranteeAssuranceLedgerEntry | dict,
) -> dict:
    payload = (
        entry.model_dump(mode="json")
        if isinstance(entry, GuaranteeAssuranceLedgerEntry)
        else dict(entry)
    )
    return {
        key: value
        for key, value in payload.items()
        if key != "signature"
    }


def _verify_entry_self(
    entry: GuaranteeAssuranceLedgerEntry,
    *,
    key: bytes,
) -> list[str]:
    reasons = validate_guarantee_assurance_snapshot_structure(entry.snapshot)

    if entry.schema_version != LEDGER_SCHEMA_VERSION:
        reasons.append("unsupported_ledger_schema")

    expected_snapshot_digest = compute_guarantee_assurance_snapshot_digest(
        entry.snapshot
    )
    if not hmac.compare_digest(entry.snapshot_digest, expected_snapshot_digest):
        reasons.append("snapshot_digest_mismatch")

    expected_entry_digest = compute_guarantee_assurance_entry_digest(entry)
    if not hmac.compare_digest(entry.entry_digest, expected_entry_digest):
        reasons.append("entry_digest_mismatch")

    expected_signature = sign_payload(_unsigned_entry_payload(entry), key)
    signature = entry.signature
    if signature.get("algorithm") != SIGNATURE_ALG:
        reasons.append("signature_algorithm_mismatch")
    if not hmac.compare_digest(
        str(signature.get("digest") or ""),
        expected_signature["digest"],
    ):
        reasons.append("invalid_entry_signature")

    if entry.sequence == 0:
        if entry.previous_entry_digest is not None:
            reasons.append("genesis_has_previous_entry")
        if entry.previous_snapshot_digest is not None:
            reasons.append("genesis_has_previous_snapshot")

    return sorted(set(reasons))


def build_guarantee_assurance_ledger_entry(
    snapshot: GuaranteeAssuranceSnapshot,
    *,
    signing_key: bytes,
    previous: GuaranteeAssuranceLedgerEntry | None = None,
    created_at: str | None = None,
) -> GuaranteeAssuranceLedgerEntry:
    """Seal one assurance snapshot into a signed, predecessor-linked ledger entry."""

    if not signing_key:
        raise ValueError("signing_key must be non-empty")

    structure_issues = validate_guarantee_assurance_snapshot_structure(snapshot)
    if structure_issues:
        raise ValueError(
            "invalid guarantee assurance snapshot: "
            + ", ".join(structure_issues)
        )

    if previous is None:
        sequence = 0
        previous_entry_digest = None
        previous_snapshot_digest = None
        base_snapshot = None
    else:
        previous_issues = _verify_entry_self(previous, key=signing_key)
        if previous_issues:
            raise ValueError(
                "cannot extend invalid predecessor ledger entry: "
                + ", ".join(previous_issues)
            )
        if snapshot.subject_repo != previous.snapshot.subject_repo:
            raise ValueError("ledger repository changed across predecessor link")
        if snapshot.subject_base_sha is None:
            raise ValueError(
                "non-genesis assurance snapshot must include subject_base_sha"
            )
        if snapshot.subject_base_sha != previous.snapshot.subject_head_sha:
            raise ValueError(
                "assurance revision discontinuity: current base SHA does not "
                "equal predecessor head SHA"
            )
        sequence = previous.sequence + 1
        previous_entry_digest = previous.entry_digest
        previous_snapshot_digest = previous.snapshot_digest
        base_snapshot = previous.snapshot

    deltas = compute_guarantee_assurance_deltas(base_snapshot, snapshot)
    timestamp = created_at or utc_now_iso()
    snapshot_digest = compute_guarantee_assurance_snapshot_digest(snapshot)

    payload = {
        "schema_version": LEDGER_SCHEMA_VERSION,
        "sequence": sequence,
        "created_at": timestamp,
        "snapshot": snapshot.model_dump(mode="json"),
        "snapshot_digest": snapshot_digest,
        "previous_entry_digest": previous_entry_digest,
        "previous_snapshot_digest": previous_snapshot_digest,
        "deltas": [delta.model_dump(mode="json") for delta in deltas],
    }
    entry_digest = content_digest(payload)
    unsigned = {**payload, "entry_digest": entry_digest}
    signature = sign_payload(unsigned, signing_key)

    return GuaranteeAssuranceLedgerEntry.model_validate(
        {**unsigned, "signature": signature}
    )


def verify_guarantee_assurance_ledger_entry(
    entry: GuaranteeAssuranceLedgerEntry,
    *,
    key: bytes,
    previous: GuaranteeAssuranceLedgerEntry | None = None,
) -> GuaranteeAssuranceLedgerVerification:
    """Verify entry integrity and, for non-genesis entries, predecessor continuity."""

    reasons = _verify_entry_self(entry, key=key)

    if entry.sequence == 0:
        if previous is not None:
            reasons.append("genesis_given_predecessor")
        expected_deltas = compute_guarantee_assurance_deltas(None, entry.snapshot)
        if entry.deltas != expected_deltas:
            reasons.append("delta_mismatch")
    else:
        if previous is None:
            reasons.append("predecessor_required")
        else:
            predecessor_issues = _verify_entry_self(previous, key=key)
            if predecessor_issues:
                reasons.append("invalid_predecessor")
            if entry.sequence != previous.sequence + 1:
                reasons.append("sequence_discontinuity")
            if entry.previous_entry_digest != previous.entry_digest:
                reasons.append("previous_entry_digest_mismatch")
            if entry.previous_snapshot_digest != previous.snapshot_digest:
                reasons.append("previous_snapshot_digest_mismatch")
            if entry.snapshot.subject_repo != previous.snapshot.subject_repo:
                reasons.append("repository_discontinuity")
            if entry.snapshot.subject_base_sha is None:
                reasons.append("missing_subject_base_sha")
            elif (
                entry.snapshot.subject_base_sha
                != previous.snapshot.subject_head_sha
            ):
                reasons.append("revision_discontinuity")

            expected_deltas = compute_guarantee_assurance_deltas(
                previous.snapshot,
                entry.snapshot,
            )
            if entry.deltas != expected_deltas:
                reasons.append("delta_mismatch")

    return GuaranteeAssuranceLedgerVerification(
        valid=not reasons,
        reason_codes=sorted(set(reasons)),
        entry_digest=entry.entry_digest,
        sequence=entry.sequence,
    )


def verify_guarantee_assurance_ledger_chain(
    entries: list[GuaranteeAssuranceLedgerEntry],
    *,
    key: bytes,
) -> GuaranteeAssuranceLedgerVerification:
    """Verify a complete ordered ledger chain from genesis to latest entry."""

    if not entries:
        return GuaranteeAssuranceLedgerVerification(
            valid=False,
            reason_codes=["empty_ledger_chain"],
        )

    reasons: list[str] = []
    for index, entry in enumerate(entries):
        previous = entries[index - 1] if index > 0 else None
        result = verify_guarantee_assurance_ledger_entry(
            entry,
            key=key,
            previous=previous,
        )
        reasons.extend(
            f"entry[{index}]:{reason}" for reason in result.reason_codes
        )

    return GuaranteeAssuranceLedgerVerification(
        valid=not reasons,
        reason_codes=sorted(set(reasons)),
        entry_digest=entries[-1].entry_digest,
        sequence=entries[-1].sequence,
    )
