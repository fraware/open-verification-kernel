"""Explicitly new FIRST_PARENT transition census generator for expansion_v2.

This module is **not** authentic `generate_transition_census.py` and must never
be described as recovered v0. Authentic generator blob remains UNAVAILABLE
(see experiments/rtk/sealed/SEALED_CENSUS_PROVENANCE.json).

Interface-freeze behavior:
- Documents the output schema.
- Exposes a skeleton entrypoint that refuses live expansion materialization.
- Does not invent overlay census bytes for the five frozen candidates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .adapter_contract import SourceRepositoryAdapter, TransitionEnumerationRecord
from .reason_codes import EXCLUSION_REASON_CODES, require_known_exclusion_reason
from .registry import EXPANSION_IDENTITIES, frozen_expansion_repository_ids

SCHEMA_VERSION_JSONL = "rtk.transition_census.v2"
SCHEMA_VERSION_MANIFEST = "rtk.transition_census_manifest.v2"
GENERATOR_ROLE = "NEW_V2_CENSUS_NOT_AUTHENTIC_V0"
INTERFACE_STATUS = "V2_ADAPTERS_IMPLEMENTED_MATERIALIZATION_AUTHORIZED"

# Output schema (documentation + validation helpers).
# Each JSONL record mirrors the v0 transition schema field set so overlays can
# be consumed by downstream stages without rewriting sealed v0 census bytes.
CENSUS_RECORD_REQUIRED_FIELDS: tuple[str, ...] = (
    "transition_id",
    "repository",
    "source_sha",
    "target_sha",
    "source_timestamp",
    "target_timestamp",
    "changed_paths",
    "eligibility",
    "history_rule",
)

CENSUS_OUTPUT_SCHEMA: dict[str, Any] = {
    "schema_version": SCHEMA_VERSION_JSONL,
    "description": (
        "Complete FIRST_PARENT universe per frozen candidate, including "
        "EXCLUDED rows with reason codes. Content-addressed via SHA-256 of "
        "canonical JSONL bytes."
    ),
    "record_required_fields": list(CENSUS_RECORD_REQUIRED_FIELDS),
    "eligibility_enum": ["ELIGIBLE", "EXCLUDED"],
    "exclusion_reason_codes": sorted(EXCLUSION_REASON_CODES),
    "history_rule": "FIRST_PARENT",
    "content_addressing": {
        "jsonl": "sha256(utf-8 canonical JSONL with trailing newlines per record)",
        "manifest": "sha256(canonical JSON object + trailing newline)",
    },
    "manifest_fields": [
        "schema_version",
        "generator_role",
        "generator_module",
        "interface_status",
        "repositories",
        "record_count",
        "records_by_repository",
        "eligible_count",
        "excluded_count",
        "exclusion_reason_counts",
        "census_jsonl_sha256",
        "rtk_outputs_consulted",
        "oracle_labels_consulted",
        "authentic_v0_claim",
    ],
    "authentic_v0_claim": False,
    "materialization_authorized_in_interface_freeze": False,
    "materialization_authorized_after_v0_compat": True,
}


@dataclass(frozen=True)
class CensusWritePlan:
    """Planned outputs for a future materialization pass (not executed here)."""

    out_jsonl: Path
    out_manifest: Path
    repositories: tuple[str, ...]


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_census_record(record: Mapping[str, Any]) -> None:
    missing = [key for key in CENSUS_RECORD_REQUIRED_FIELDS if key not in record]
    if missing:
        raise ValueError(f"census record missing fields: {missing}")
    eligibility = record["eligibility"]
    if eligibility not in ("ELIGIBLE", "EXCLUDED"):
        raise ValueError(f"invalid eligibility: {eligibility!r}")
    if eligibility == "EXCLUDED":
        reason = record.get("exclusion_reason")
        if not isinstance(reason, str) or not reason:
            raise ValueError("EXCLUDED records require exclusion_reason")
        require_known_exclusion_reason(reason)
    if record.get("history_rule") != "FIRST_PARENT":
        raise ValueError("expansion_v2 census requires history_rule=FIRST_PARENT")


def records_to_jsonl_bytes(records: Sequence[TransitionEnumerationRecord]) -> bytes:
    lines: list[bytes] = []
    for record in records:
        payload = record.as_dict()
        validate_census_record(payload)
        lines.append(_canonical_bytes(payload) + b"\n")
    return b"".join(lines)


def build_manifest(
    *,
    records: Sequence[TransitionEnumerationRecord],
    jsonl_sha256: str,
    repositories: Iterable[str],
) -> dict[str, Any]:
    by_repo: dict[str, int] = {}
    exclusion_counts: dict[str, int] = {}
    eligible = 0
    excluded = 0
    for record in records:
        by_repo[record.repository] = by_repo.get(record.repository, 0) + 1
        if record.eligibility == "ELIGIBLE":
            eligible += 1
        else:
            excluded += 1
            reason = record.exclusion_reason or "UNKNOWN"
            exclusion_counts[reason] = exclusion_counts.get(reason, 0) + 1
    return {
        "schema_version": SCHEMA_VERSION_MANIFEST,
        "generator_role": GENERATOR_ROLE,
        "generator_module": (
            "experiments/p05_formalpr_bench/rtk_eval/expansion_v2/"
            "generate_transition_census_v2.py"
        ),
        "interface_status": INTERFACE_STATUS,
        "repositories": list(repositories),
        "record_count": len(records),
        "records_by_repository": dict(sorted(by_repo.items())),
        "eligible_count": eligible,
        "excluded_count": excluded,
        "exclusion_reason_counts": dict(sorted(exclusion_counts.items())),
        "census_jsonl_sha256": jsonl_sha256,
        "rtk_outputs_consulted": False,
        "oracle_labels_consulted": False,
        "authentic_v0_claim": False,
        "output_schema": CENSUS_OUTPUT_SCHEMA,
    }


def enumerate_via_adapter(
    adapter: SourceRepositoryAdapter,
    checkout: Path,
    *,
    cutoff_sha: str | None = None,
) -> list[TransitionEnumerationRecord]:
    """Invoke adapter enumeration and validate reason codes.

    Not used for live expansion materialization in the interface-freeze pass.
    """
    records = list(
        adapter.enumerate_transitions(checkout, cutoff_sha=cutoff_sha)
    )
    for record in records:
        validate_census_record(record.as_dict())
    return records


def refuse_expansion_materialization() -> int:
    """Entrypoint outcome for the interface-freeze pass."""
    payload = {
        "status": INTERFACE_STATUS,
        "generator_role": GENERATOR_ROLE,
        "authentic_v0_claim": False,
        "frozen_expansion_repositories": list(frozen_expansion_repository_ids()),
        "frozen_expansion_cutoffs": [
            {
                "repository": identity.repository,
                "cutoff_sha": identity.cutoff_sha,
                "url": identity.url,
            }
            for identity in EXPANSION_IDENTITIES
        ],
        "message": (
            "generate_transition_census_v2 interface is frozen. Live FIRST_PARENT "
            "enumeration and overlay census writes for the five expansion "
            "candidates are deferred until after human review of the v2 "
            "methodology gate and v0 compatibility. No overlay census bytes "
            "were invented in this pass."
        ),
        "output_schema": CENSUS_OUTPUT_SCHEMA,
    }
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "expansion_v2 transition census skeleton (NOT authentic v0). "
            "Interface freeze refuses live expansion materialization."
        )
    )
    parser.add_argument(
        "--describe-schema",
        action="store_true",
        help="Print the frozen output schema and exit 0.",
    )
    parser.add_argument(
        "--authorize-materialization",
        action="store_true",
        help=(
            "Reserved for a future pass after human review. In this interface "
            "freeze, the flag still refuses execution."
        ),
    )
    parser.add_argument("--out", type=Path, help="Reserved overlay JSONL path.")
    parser.add_argument(
        "--manifest", type=Path, help="Reserved overlay manifest path."
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.describe_schema:
        sys.stdout.write(
            json.dumps(CENSUS_OUTPUT_SCHEMA, indent=2, sort_keys=True) + "\n"
        )
        return 0

    # Interface freeze: never write overlay census for expansion candidates.
    if args.authorize_materialization:
        sys.stderr.write(
            "generate_transition_census_v2: --authorize-materialization is "
            "recognized but refused during "
            f"{INTERFACE_STATUS}\n"
        )
    return refuse_expansion_materialization()


if __name__ == "__main__":
    raise SystemExit(main())
