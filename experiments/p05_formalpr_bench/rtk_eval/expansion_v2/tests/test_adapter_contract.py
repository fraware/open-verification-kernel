"""Contract compliance, prohibition, and reason-code tests for expansion_v2.

No expansion-candidate materialization. No RTK / oracle / baseline execution.
"""

from __future__ import annotations

import abc
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT.parent) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT.parent))

from expansion_v2 import (  # noqa: E402
    ADAPTER_METHOD_NAMES,
    EXCLUSION_REASON_CODES,
    PROHIBITED_CAPABILITIES,
    SourceRepositoryAdapter,
)
from expansion_v2.adapter_contract import (  # noqa: E402
    AdapterNotYetImplemented,
    ClaimAnchor,
    EvidenceSnapshot,
    GovernedArtifact,
    NativeValidatorResult,
    RepositoryIdentity,
    SourceEvidenceCandidate,
    SubjectBinding,
    TransitionEnumerationRecord,
)
from expansion_v2.generate_transition_census_v2 import (  # noqa: E402
    CENSUS_OUTPUT_SCHEMA,
    INTERFACE_STATUS,
    build_manifest,
    main as census_main,
    records_to_jsonl_bytes,
    refuse_expansion_materialization,
    validate_census_record,
)
from expansion_v2.prohibitions import (  # noqa: E402
    AdapterProhibitionError,
    refuse_prohibited,
)
from expansion_v2.reason_codes import (  # noqa: E402
    ExclusionReasonCode,
    is_known_exclusion_reason,
    require_known_exclusion_reason,
)
from expansion_v2.registry import (  # noqa: E402
    EXPANSION_IDENTITIES,
    V0_IDENTITIES,
    build_default_registry,
    frozen_expansion_repository_ids,
)


class _MinimalCompliantAdapter(SourceRepositoryAdapter):
    """Minimal concrete adapter used only to prove ABC completeness."""

    def __init__(self) -> None:
        self._identity = RepositoryIdentity(
            repository="example/test-repo",
            url="https://example.invalid/test-repo",
            cutoff_sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            role="TEST_ONLY",
        )

    @property
    def identity(self) -> RepositoryIdentity:
        return self._identity

    @property
    def implementation_status(self) -> str:
        return "INTERFACE_STUB"

    def enumerate_transitions(self, checkout, *, cutoff_sha=None):
        return [
            TransitionEnumerationRecord(
                transition_id="t1",
                repository=self.repository,
                source_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                target_sha="cccccccccccccccccccccccccccccccccccccccc",
                source_timestamp="2026-01-01T00:00:00+00:00",
                target_timestamp="2026-01-02T00:00:00+00:00",
                changed_paths=("README.md",),
                eligibility="EXCLUDED",
                exclusion_reason=ExclusionReasonCode.ADAPTER_DECLARED_INELIGIBLE.value,
            )
        ]

    def discover_governed_artifacts(self, checkout, revision):
        return [GovernedArtifact(path="README.md", artifact_class="docs")]

    def extract_claim_anchors(self, checkout, transition):
        return [
            ClaimAnchor(
                anchor_id="a1",
                repository=self.repository,
                family="TEST",
                claim_id="claim-1",
                contract_locator="README.md",
                source_sha=transition.source_sha,
                target_sha=transition.target_sha,
            )
        ]

    def discover_source_evidence_candidates(self, checkout, anchor):
        return [
            SourceEvidenceCandidate(
                candidate_id="c1",
                anchor_id=anchor.anchor_id,
                paths=("README.md",),
                discovery_rule="test",
            )
        ]

    def execute_source_revision_native_validator(
        self, checkout, candidate, *, source_sha
    ):
        return NativeValidatorResult(
            status="SOURCE_REJECTED",
            validator_id="test-validator",
            accepted=False,
        )

    def bind_subject(self, anchor, validator_result):
        return SubjectBinding(
            subject_id="s1",
            anchor_id=anchor.anchor_id,
            binding_digest="0" * 64,
        )

    def construct_evidence_snapshot(
        self, checkout, binding, *, source_sha, artifacts
    ):
        return EvidenceSnapshot(
            snapshot_id="snap1",
            repository=self.repository,
            revision=source_sha,
            digest="1" * 64,
        )


class AdapterContractTests(unittest.TestCase):
    def test_required_methods_are_abstract(self) -> None:
        abstract = SourceRepositoryAdapter.__abstractmethods__
        for name in ADAPTER_METHOD_NAMES:
            self.assertIn(name, abstract)
        self.assertIn("identity", abstract)

    def test_cannot_instantiate_abc_directly(self) -> None:
        with self.assertRaises(TypeError):
            SourceRepositoryAdapter()  # type: ignore[abstract]

    def test_minimal_adapter_is_concrete(self) -> None:
        adapter = _MinimalCompliantAdapter()
        self.assertEqual(adapter.implementation_status, "INTERFACE_STUB")
        adapter.assert_source_side_only()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            records = adapter.enumerate_transitions(root)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].eligibility, "EXCLUDED")

    def test_placeholder_raises_adapter_not_yet_implemented(self) -> None:
        identity = EXPANSION_IDENTITIES[0]
        adapter = AdapterNotYetImplemented(identity)
        self.assertEqual(adapter.implementation_status, "SEMANTIC_MAPPING_PENDING")
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(NotImplementedError) as ctx:
                adapter.enumerate_transitions(Path(tmp))
        self.assertIn("ADAPTER_NOT_YET_IMPLEMENTED", str(ctx.exception))

    def test_default_registry_covers_v0_and_five_expansion(self) -> None:
        registry = build_default_registry()
        self.assertEqual(len(registry), 7)
        for identity in V0_IDENTITIES:
            self.assertIn(identity.repository, registry)
        expansion_ids = frozen_expansion_repository_ids()
        self.assertEqual(len(expansion_ids), 5)
        for repo_id in expansion_ids:
            self.assertIn(repo_id, registry)
            self.assertIsInstance(registry[repo_id], AdapterNotYetImplemented)

    def test_expansion_candidate_count_frozen_at_five(self) -> None:
        self.assertEqual(len(EXPANSION_IDENTITIES), 5)
        # Cutoffs must match SOURCE_REPOSITORY_CANDIDATES.v1.json pin set.
        expected = {
            "fraware/pcs-bench": "6092cccefee7841dfde1393e6881d433838a2252",
            "fraware/ovk-consumer-fastapi-terraform": (
                "784576bc5fd01ac80092662887a896301d4fe186"
            ),
            "fraware/ovk-consumer-express-actions": (
                "31aed31a04c7bca67d3bd6151caf1e42f4b7d1f8"
            ),
            "fraware/environment-assurance-compiler": (
                "812b4b13f8acdfcafb50de9d794c7fa0b20b31ad"
            ),
            "fraware/lean-project-evidence": (
                "4660d97db933b0fbcf5c9af466191055c887bea3"
            ),
        }
        observed = {
            identity.repository: identity.cutoff_sha
            for identity in EXPANSION_IDENTITIES
        }
        self.assertEqual(observed, expected)


class ProhibitionGuardTests(unittest.TestCase):
    def test_prohibited_capabilities_closed_set(self) -> None:
        required = {
            "rtk_prediction",
            "rtk_import",
            "target_revision_validator",
            "oracle_label_read",
            "unblinded_information",
            "tier_a_attestation_substitution",
            "tier_b_promotion_to_tier_a",
        }
        self.assertTrue(required.issubset(PROHIBITED_CAPABILITIES))

    def test_refuse_prohibited_raises(self) -> None:
        with self.assertRaises(AdapterProhibitionError):
            refuse_prohibited("oracle_label_read")
        with self.assertRaises(AdapterProhibitionError):
            refuse_prohibited("rtk_prediction")
        with self.assertRaises(AdapterProhibitionError):
            refuse_prohibited("target_revision_validator")

    def test_minimal_adapter_source_side_guard_hook(self) -> None:
        adapter = _MinimalCompliantAdapter()
        adapter.assert_source_side_only()  # documentation hook; must not raise
        # Explicit capability refusals remain hard errors:
        for capability in (
            "rtk_prediction",
            "oracle_label_read",
            "target_revision_validator",
            "unblinded_information",
            "tier_a_attestation_substitution",
            "tier_b_promotion_to_tier_a",
        ):
            with self.assertRaises(AdapterProhibitionError):
                refuse_prohibited(capability)


class ReasonCodeSchemaTests(unittest.TestCase):
    def test_known_codes_include_adapter_pending(self) -> None:
        self.assertIn("ADAPTER_NOT_YET_IMPLEMENTED", EXCLUSION_REASON_CODES)
        self.assertTrue(is_known_exclusion_reason("NO_GOVERNED_ARTIFACT_SURFACE"))

    def test_unknown_code_rejected(self) -> None:
        self.assertFalse(is_known_exclusion_reason("MADE_UP_REASON"))
        with self.assertRaises(ValueError):
            require_known_exclusion_reason("MADE_UP_REASON")

    def test_excluded_census_record_requires_known_code(self) -> None:
        with self.assertRaises(ValueError):
            validate_census_record(
                {
                    "transition_id": "t",
                    "repository": "r",
                    "source_sha": "a" * 40,
                    "target_sha": "b" * 40,
                    "source_timestamp": None,
                    "target_timestamp": None,
                    "changed_paths": [],
                    "eligibility": "EXCLUDED",
                    "exclusion_reason": "NOT_A_REAL_CODE",
                    "history_rule": "FIRST_PARENT",
                }
            )


class CensusV2SkeletonTests(unittest.TestCase):
    def test_schema_declares_not_authentic_v0(self) -> None:
        self.assertIs(CENSUS_OUTPUT_SCHEMA["authentic_v0_claim"], False)
        self.assertIs(
            CENSUS_OUTPUT_SCHEMA["materialization_authorized_in_interface_freeze"],
            False,
        )

    def test_entrypoint_refuses_materialization(self) -> None:
        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = refuse_expansion_materialization()
            self.assertEqual(code, 2)
            self.assertEqual(census_main([]), 2)
            self.assertEqual(census_main(["--authorize-materialization"]), 2)

    def test_describe_schema_ok(self) -> None:
        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(census_main(["--describe-schema"]), 0)

    def test_content_address_helpers_without_writing_overlay(self) -> None:
        record = TransitionEnumerationRecord(
            transition_id="t1",
            repository="fraware/pcs-bench",
            source_sha="a" * 40,
            target_sha="b" * 40,
            source_timestamp="2026-01-01T00:00:00+00:00",
            target_timestamp="2026-01-02T00:00:00+00:00",
            changed_paths=("x.py",),
            eligibility="EXCLUDED",
            exclusion_reason=ExclusionReasonCode.ADAPTER_NOT_YET_IMPLEMENTED.value,
        )
        payload = records_to_jsonl_bytes([record])
        manifest = build_manifest(
            records=[record],
            jsonl_sha256="c" * 64,
            repositories=["fraware/pcs-bench"],
        )
        self.assertTrue(payload.endswith(b"\n"))
        self.assertEqual(manifest["interface_status"], INTERFACE_STATUS)
        self.assertIs(manifest["authentic_v0_claim"], False)
        # Ensure no file write occurred as part of helper use beyond tempfile.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "should_not_exist.jsonl"
            self.assertFalse(out.exists())


class AbcHygieneTests(unittest.TestCase):
    def test_adapter_is_abc(self) -> None:
        self.assertTrue(issubclass(SourceRepositoryAdapter, abc.ABC))

    def test_package_importable_as_module_path(self) -> None:
        path = PACKAGE_ROOT / "__init__.py"
        spec = importlib.util.spec_from_file_location(
            "expansion_v2_pkg_check", path
        )
        self.assertIsNotNone(spec)


if __name__ == "__main__":
    unittest.main()
