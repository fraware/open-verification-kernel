"""Conformance tests for the RTK reference predictor.

Uses synthetic fixtures only. Does not load sealed Tier-A holdout targets.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_PKG = Path(__file__).resolve().parents[1]


def _load(name: str, relative: str):
    path = _PKG / relative
    # Ensure sibling imports resolve when modules are file-loaded.
    pkg_dir = str(_PKG)
    if pkg_dir not in sys.path:
        sys.path.insert(0, pkg_dir)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


canonicalize = _load(
    "rtk_reference_canonicalize",
    "canonicalize.py",
)
# Alias expected by predictor's fallback absolute import.
sys.modules.setdefault("canonicalize", canonicalize)
predictor = _load(
    "rtk_reference_predictor",
    "predictor.py",
)
builders = _load(
    "rtk_reference_builders",
    "fixtures/builders.py",
)


class CanonicalizationTests(unittest.TestCase):
    def test_digest_stable_under_key_reorder_and_array_permutation(self) -> None:
        base = builders.build_cdi(
            case_name="canon-stable",
            completeness="COMPLETE",
            elements=["b.txt", "a.txt"],
            changed_paths=["z.txt", "a.txt"],
        )
        shuffled = {
            "canonical_digest": base["canonical_digest"],
            "relying_profile": base["relying_profile"],
            "schema_version": base["schema_version"],
            "evidence_snapshot": {
                "completeness": base["evidence_snapshot"]["completeness"],
                "digest_algorithm": base["evidence_snapshot"]["digest_algorithm"],
                "snapshot_id": base["evidence_snapshot"]["snapshot_id"],
                "digest": base["evidence_snapshot"]["digest"],
                "artifact_refs": list(reversed(base["evidence_snapshot"]["artifact_refs"])),
            },
            "decision_input_id": base["decision_input_id"],
            "claim": base["claim"],
            "context_footprint": {
                "footprint_digest": base["context_footprint"]["footprint_digest"],
                "mapping_id": base["context_footprint"]["mapping_id"],
                "elements": list(reversed(base["context_footprint"]["elements"])),
            },
            "transition": {
                "history_rule": base["transition"]["history_rule"],
                "target_sha": base["transition"]["target_sha"],
                "source_sha": base["transition"]["source_sha"],
                "repository": base["transition"]["repository"],
                "transition_id": base["transition"]["transition_id"],
                "changed_paths": list(reversed(base["transition"]["changed_paths"])),
            },
        }
        self.assertEqual(
            canonicalize.compute_canonical_digest(base),
            canonicalize.compute_canonical_digest(shuffled),
        )
        self.assertTrue(canonicalize.digests_match(base))
        self.assertTrue(canonicalize.digests_match(shuffled))


class PredictorConformanceTests(unittest.TestCase):
    def test_valid_when_no_footprint_path_changed(self) -> None:
        cdi = builders.build_cdi(
            case_name="valid-no-overlap",
            completeness="COMPLETE",
            elements=["claim/a.json", "claim/b.json"],
            changed_paths=["unrelated/readme.md", "docs/note.txt"],
        )
        out = predictor.predict(cdi)
        self.assertEqual(out["execution_status"], "OK")
        self.assertEqual(out["verdict"], "VALID")
        self.assertIsNone(out["failure_category"])
        self.assertIn("NO_FOOTPRINT_PATH_CHANGED", out["rationale_codes"])

    def test_revalidation_when_footprint_path_changed(self) -> None:
        cdi = builders.build_cdi(
            case_name="reval-overlap",
            completeness="COMPLETE",
            elements=["claim/a.json", "claim/b.json"],
            changed_paths=["claim/a.json", "other.txt"],
            include_repair=True,
        )
        out = predictor.predict(cdi)
        self.assertEqual(out["execution_status"], "OK")
        self.assertEqual(out["verdict"], "REVALIDATION_REQUIRED")
        self.assertEqual(out["impacted_paths"], ["claim/a.json"])
        self.assertEqual(
            out["predicted_repair_catalog_id"],
            cdi["repair_catalog_ref"]["catalog_id"],
        )
        self.assertIn("FOOTPRINT_PATH_CHANGED", out["rationale_codes"])

    def test_revalidation_when_evidence_incomplete(self) -> None:
        cdi = builders.build_cdi(
            case_name="incomplete",
            completeness="INCOMPLETE",
            elements=["claim/a.json"],
            changed_paths=["claim/a.json"],
            include_repair=True,
        )
        out = predictor.predict(cdi)
        self.assertEqual(out["verdict"], "REVALIDATION_REQUIRED")
        self.assertIn("EVIDENCE_SNAPSHOT_INCOMPLETE", out["rationale_codes"])
        self.assertEqual(
            out["predicted_repair_catalog_id"],
            cdi["repair_catalog_ref"]["catalog_id"],
        )

    def test_unresolved_when_completeness_unknown(self) -> None:
        cdi = builders.build_cdi(
            case_name="unknown",
            completeness="UNKNOWN",
            elements=["claim/a.json"],
            changed_paths=[],
        )
        out = predictor.predict(cdi)
        self.assertEqual(out["verdict"], "UNRESOLVED")
        self.assertIn("EVIDENCE_COMPLETENESS_UNKNOWN", out["rationale_codes"])

    def test_invalid_when_complete_footprint_not_in_artifacts(self) -> None:
        cdi = builders.build_cdi(
            case_name="invalid-cover",
            completeness="COMPLETE",
            elements=["claim/a.json", "claim/missing.json"],
            changed_paths=["unrelated.txt"],
            artifact_paths=["claim/a.json"],
        )
        out = predictor.predict(cdi)
        self.assertEqual(out["verdict"], "INVALID")
        self.assertEqual(out["impacted_paths"], ["claim/missing.json"])
        self.assertIn("FOOTPRINT_NOT_COVERED_BY_ARTIFACT_REFS", out["rationale_codes"])

    def test_operational_failure_on_digest_mismatch_never_valid(self) -> None:
        cdi = builders.build_cdi(
            case_name="bad-digest",
            completeness="COMPLETE",
            elements=["claim/a.json"],
            changed_paths=[],
            corrupt_digest=True,
        )
        out = predictor.predict(cdi)
        self.assertEqual(out["execution_status"], "OPERATIONAL_FAILURE")
        self.assertIsNone(out["verdict"])
        self.assertEqual(out["failure_category"], "CANONICAL_DIGEST_MISMATCH")
        self.assertNotEqual(out["verdict"], "VALID")

    def test_operational_failure_on_schema_violation(self) -> None:
        out = predictor.predict({"schema_version": "not-a-cdi"})
        self.assertEqual(out["execution_status"], "OPERATIONAL_FAILURE")
        self.assertIsNone(out["verdict"])
        self.assertEqual(out["failure_category"], "SCHEMA_VALIDATION_FAILURE")

    def test_implementation_kind_is_not_historical_go(self) -> None:
        cdi = builders.build_cdi(
            case_name="kind-check",
            completeness="COMPLETE",
            elements=["a"],
            changed_paths=[],
        )
        out = predictor.predict(cdi)
        self.assertEqual(out["implementation_kind"], "REFERENCE_NOT_HISTORICAL_GO")
        self.assertEqual(out["implementation_id"], "rtk.reference_implementation.v0")

    def test_all_verdict_space_members_are_reachable_on_synthetics(self) -> None:
        cases = {
            "VALID": builders.build_cdi(
                case_name="space-valid",
                completeness="COMPLETE",
                elements=["a"],
                changed_paths=["b"],
            ),
            "INVALID": builders.build_cdi(
                case_name="space-invalid",
                completeness="COMPLETE",
                elements=["a", "missing"],
                changed_paths=[],
                artifact_paths=["a"],
            ),
            "REVALIDATION_REQUIRED": builders.build_cdi(
                case_name="space-reval",
                completeness="COMPLETE",
                elements=["a"],
                changed_paths=["a"],
            ),
            "UNRESOLVED": builders.build_cdi(
                case_name="space-unresolved",
                completeness="UNKNOWN",
                elements=["a"],
                changed_paths=[],
            ),
        }
        seen = {name: predictor.predict(cdi)["verdict"] for name, cdi in cases.items()}
        self.assertEqual(seen, {name: name for name in cases})


class ContaminationGuardTests(unittest.TestCase):
    def test_fixture_builders_do_not_load_sealed_corpus(self) -> None:
        builders_text = Path(builders.__file__).read_text(encoding="utf-8")
        forbidden = [
            "TRANSITION_CENSUS",
            "CanonicalDecisionInput.v1.jsonl",
            "SOURCE_EVIDENCE",
            "sealed/frozen_outputs",
        ]
        for token in forbidden:
            self.assertNotIn(token, builders_text)

if __name__ == "__main__":
    unittest.main()
