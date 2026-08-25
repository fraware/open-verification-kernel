#!/usr/bin/env python
"""Build a machine-generated template claim registry from v3 conformance."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ovk.core.capabilities import validate_capability_manifest  # noqa: E402
from ovk.core.json_io import read_json_file  # noqa: E402
from ovk.core.template_conformance_v3 import build_conformance_matrix  # noqa: E402

BRIDGE_PATH = ROOT / "templates" / "registry" / "bridge.json"
OUTPUT_PATH = ROOT / ".verification" / "template-claim-registry.json"


def _claim_class(bridge: dict[str, Any], property_kind: str, claimed_backends: list[str]) -> str:
    mapping = bridge.get("default_claim_class_by_property_kind") or {}
    if property_kind in mapping:
        return str(mapping[property_kind])
    if claimed_backends:
        return f"template_claim:{claimed_backends[0]}"
    return "template_property_claim"


def _release_status(bridge: dict[str, Any], row: dict[str, Any]) -> str:
    """Map release_status from conformance_status_v3 only (never production_status)."""
    v3 = str(row.get("conformance_status_v3") or "")
    v3_map = bridge.get("conformance_status_v3_to_release_status") or {}
    if v3 in v3_map:
        return str(v3_map[v3])
    # Conservative fallback when v3 is somehow absent: experimental, not legacy production_status.
    return "experimental"


def build_entries(
    *,
    conformance: dict[str, Any],
    bridge: dict[str, Any],
) -> dict[str, Any]:
    rows = conformance.get("templates") or conformance.get("rows") or []
    if not isinstance(rows, list):
        raise ValueError("template conformance matrix missing templates/rows array")

    entries: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        intent_id = str(row.get("intent_id") or "").strip()
        if not intent_id:
            continue
        property_kind = str(row.get("property_kind") or "invariant")
        claimed_backends = [str(item) for item in (row.get("claimed_backends") or [])]
        domain = str(row.get("domain") or "unknown")
        version = str(row.get("version") or "0.0.0")
        release_status = _release_status(bridge, row)
        claim_class = _claim_class(bridge, property_kind, claimed_backends)
        status_v3 = str(row.get("conformance_status_v3") or "catalog_only")
        status_v2 = str(row.get("conformance_status_v2") or "catalog_only")
        entry = {
            "capability_id": f"template-{intent_id}-v1",
            "checker_id": f"template:{intent_id}",
            "version": version,
            "implementation": str(row.get("path") or f"templates/{domain}/{intent_id}.intent.json"),
            "input_contract": (
                f"Intent template {intent_id} over domain {domain}; "
                "materials supplied by lane compilers / examples."
            ),
            "output_contract": "ovk.evidence via lane evaluator linked by template conformance",
            "claim_class": claim_class,
            "tool": {
                "name": f"template:{intent_id}",
                "adapter": "ovk-template-registry",
                "adapter_version": version,
            },
            "backend_class": "custom",
            "supported_domains": [domain],
            "supported_property_kinds": [property_kind],
            "guarantee": {
                "type": claim_class,
                "meaning_of_pass": f"Template {intent_id} obligation passed under linked evaluator.",
                "meaning_of_fail": f"Template {intent_id} obligation found a violation.",
                "meaning_of_unknown": f"Template {intent_id} could not be decided from available materials.",
            },
            "assumptions": [
                "Template conformance links accurately describe executable surfaces.",
                f"conformance_status_v3={status_v3}",
                f"conformance_status_v2_compatibility={status_v2}",
            ],
            "trusted_components": [
                "intent template",
                *(str(link) for link, present in (row.get("executable_links") or {}).items() if present),
            ],
            "failure_semantics": "Missing executable links keep the template experimental/catalog_only.",
            "timeout_semantics": "unknown",
            "unsupported_semantics": (
                "Template claims only what linked evaluators and source profiles establish; "
                "catalog_only templates make no production enforcement claim."
            ),
            "determinism_status": "deterministic",
            "release_status": release_status,
            "owner": "ovk-maintainers",
            "native_execution": False,
            "template_conformance_status_v3": status_v3,
            "template_conformance_status_v2": status_v2,
            "claimed_backends": claimed_backends,
        }
        qualification = row.get("source_profile_qualification")
        if isinstance(qualification, dict):
            entry["source_profile_qualification"] = qualification
        entries.append(entry)

    entries.sort(key=lambda item: str(item["checker_id"]))
    return {
        "schema_version": "ovk.template_capability_registry.v2",
        "bridge_schema_version": bridge.get("schema_version"),
        "source_conformance_schema_version": conformance.get("schema_version"),
        "entry_count": len(entries),
        "entries": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build template claim registry from normative conformance")
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--bridge", type=Path, default=None)
    parser.add_argument(
        "--conformance",
        type=Path,
        default=None,
        help="Optional conformance artifact; default builds normative v3 conformance from source.",
    )
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate the generated registry before emitting it.",
    )
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()
    bridge_path = (args.bridge or (repo_root / "templates" / "registry" / "bridge.json")).resolve()
    output = (args.output or (repo_root / ".verification" / "template-claim-registry.json")).resolve()

    bridge = read_json_file(bridge_path)
    if args.conformance is not None:
        conformance = read_json_file(args.conformance.resolve())
    else:
        conformance = build_conformance_matrix(repo_root)
    payload = build_entries(conformance=conformance, bridge=bridge)

    failures: list[str] = []
    for index, entry in enumerate(payload["entries"]):
        failures.extend(validate_capability_manifest(entry, source=f"entries[{index}]"))
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.check:
        print(
            "template registry generated and validated "
            f"({payload['entry_count']} entries, {payload['source_conformance_schema_version']})"
        )
    else:
        print(f"wrote {payload['entry_count']} template registry entries -> {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
