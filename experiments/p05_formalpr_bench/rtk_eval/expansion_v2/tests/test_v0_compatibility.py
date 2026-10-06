"""v0 compatibility harness for expansion_v2 adapters.

Requirement (SOURCE_UNIVERSE_EXPANSION_PROTOCOL.v2.md):
Before external expansion materialization, CertifyEdge and pcs-core must be
fed through the new adapter mechanism and produce semantic equivalence to
sealed v0 anchors/evidence for the overlapping supported surface.

Byte identity of intermediate JSONL is not required unless separately
contracted. Semantic divergence is a blocker.

This interface-freeze pass declares the sealed digests and gate. Full
repository-specific v0 adapters are not yet implemented, so the live
equivalence check is skipped with reason ADAPTER_NOT_YET_IMPLEMENTED.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[5]
if str(PACKAGE_ROOT.parent) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT.parent))

from expansion_v2.adapter_contract import AdapterNotYetImplemented  # noqa: E402
from expansion_v2.registry import V0_IDENTITIES, build_default_registry  # noqa: E402

# Sealed digests the compatibility gate will check once adapters exist.
SEALED_V0_DIGESTS = {
    "transition_census_sha256": (
        "b1816276176297adf345981fe5d9c8271cf00f5b71653d59a21d8261d64a6b11"
    ),
    "historical_anchors_sha256": (
        "44cb1f2701705375e9354b4a51a07064d2dba2d33f757e0955fc03db00d4d5cc"
    ),
    "source_evidence_semantic_projection_sha256": (
        "7ea32cb2c579077f281a3356683a3e926872492b6e756b44c0c39d077358f1fe"
    ),
}

SEALED_PATHS = {
    "census": REPO_ROOT
    / "experiments/rtk/sealed/TRANSITION_CENSUS.jsonl",
    "anchors": REPO_ROOT
    / "experiments/rtk/sealed/frozen_outputs/HISTORICAL_ANCHORS.jsonl",
    "semantic": REPO_ROOT
    / "experiments/rtk/sealed/frozen_outputs/SOURCE_EVIDENCE_SEMANTIC.jsonl",
    "binding": REPO_ROOT / "experiments/rtk/SOURCE_EVIDENCE_V1_BINDING.json",
}

SKIP_REASON = "ADAPTER_NOT_YET_IMPLEMENTED"


def _sha256_file(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


class SealedDigestDeclarationTests(unittest.TestCase):
    """Always-run declarations: sealed targets exist and match published digests."""

    def test_sealed_census_digest_matches_declaration(self) -> None:
        path = SEALED_PATHS["census"]
        self.assertTrue(path.is_file(), f"missing sealed census: {path}")
        self.assertEqual(
            _sha256_file(path), SEALED_V0_DIGESTS["transition_census_sha256"]
        )

    def test_sealed_anchors_digest_matches_declaration(self) -> None:
        path = SEALED_PATHS["anchors"]
        self.assertTrue(path.is_file(), f"missing sealed anchors: {path}")
        self.assertEqual(
            _sha256_file(path), SEALED_V0_DIGESTS["historical_anchors_sha256"]
        )

    def test_sealed_semantic_digest_matches_declaration(self) -> None:
        path = SEALED_PATHS["semantic"]
        self.assertTrue(path.is_file(), f"missing sealed semantic: {path}")
        self.assertEqual(
            _sha256_file(path),
            SEALED_V0_DIGESTS["source_evidence_semantic_projection_sha256"],
        )

    def test_binding_records_same_digests(self) -> None:
        binding = json.loads(SEALED_PATHS["binding"].read_text(encoding="utf-8"))
        frozen = binding["frozen_digests"]
        self.assertEqual(
            frozen["transition_census_sha256"],
            SEALED_V0_DIGESTS["transition_census_sha256"],
        )
        self.assertEqual(
            frozen["historical_anchors_sha256"],
            SEALED_V0_DIGESTS["historical_anchors_sha256"],
        )
        self.assertEqual(
            frozen["source_evidence_semantic_projection_sha256"],
            SEALED_V0_DIGESTS["source_evidence_semantic_projection_sha256"],
        )


class V0AdapterCompatibilityGateTests(unittest.TestCase):
    """Live semantic-equivalence check — gated until v0 adapters exist."""

    def test_v0_registry_entries_are_placeholders(self) -> None:
        registry = build_default_registry()
        for identity in V0_IDENTITIES:
            adapter = registry[identity.repository]
            self.assertIsInstance(adapter, AdapterNotYetImplemented)
            self.assertEqual(adapter.implementation_status, "SEMANTIC_MAPPING_PENDING")

    def test_semantic_equivalence_via_adapters(self) -> None:
        registry = build_default_registry()
        pending = [
            identity.repository
            for identity in V0_IDENTITIES
            if isinstance(registry[identity.repository], AdapterNotYetImplemented)
        ]
        if pending:
            self.skipTest(
                f"{SKIP_REASON}: v0 adapters pending for {pending}; "
                "external expansion must not proceed until semantic equivalence "
                "to sealed digests "
                f"(census={SEALED_V0_DIGESTS['transition_census_sha256'][:12]}…, "
                f"anchors={SEALED_V0_DIGESTS['historical_anchors_sha256'][:12]}…, "
                f"semantic={SEALED_V0_DIGESTS['source_evidence_semantic_projection_sha256'][:12]}…) "
                "is demonstrated on the overlapping supported surface."
            )
        # Future pass: run adapters on CertifyEdge/pcs-core checkouts, compare
        # semantic projections to sealed outputs, fail on divergence.
        self.fail("reachable only when non-placeholder v0 adapters are registered")


if __name__ == "__main__":
    unittest.main()
