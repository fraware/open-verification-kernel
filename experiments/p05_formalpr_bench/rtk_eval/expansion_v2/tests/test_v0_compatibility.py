"""v0 compatibility harness for expansion_v2 adapters.

Requirement (SOURCE_UNIVERSE_EXPANSION_PROTOCOL.v2.md):
Before external expansion materialization, CertifyEdge and pcs-core must be
fed through the new adapter mechanism and produce semantic equivalence to
sealed v0 anchors/evidence for the overlapping supported surface.

Byte identity of intermediate JSONL is not required unless separately
contracted. Semantic divergence is a blocker.
"""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[5]
if str(PACKAGE_ROOT.parent) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT.parent))

from expansion_v2.adapter_contract import AdapterNotYetImplemented  # noqa: E402
from expansion_v2.adapters.v0_base import V0SourceAdapter  # noqa: E402
from expansion_v2.adapters.v0_bridge import (  # noqa: E402
    materialize_source_evidence,
    project_record,
)
from expansion_v2.pipeline import extract_all_v0_anchors  # noqa: E402
from expansion_v2.registry import V0_IDENTITIES, build_default_registry  # noqa: E402

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
    "census": REPO_ROOT / "experiments/rtk/sealed/TRANSITION_CENSUS.jsonl",
    "anchors": REPO_ROOT
    / "experiments/rtk/sealed/frozen_outputs/HISTORICAL_ANCHORS.jsonl",
    "semantic": REPO_ROOT
    / "experiments/rtk/sealed/frozen_outputs/SOURCE_EVIDENCE_SEMANTIC.jsonl",
    "binding": REPO_ROOT / "experiments/rtk/SOURCE_EVIDENCE_V1_BINDING.json",
}

DEFAULT_CHECKOUTS = {
    "fraware/CertifyEdge": REPO_ROOT / "_rtk_sources/CertifyEdge",
    "SentinelOps-CI/pcs-core": REPO_ROOT / "_rtk_sources/pcs-core",
}


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _load_jsonl(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


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
    """Live semantic-equivalence check against sealed v0 anchors/evidence."""

    def test_v0_registry_entries_are_concrete_adapters(self) -> None:
        registry = build_default_registry()
        for identity in V0_IDENTITIES:
            adapter = registry[identity.repository]
            self.assertNotIsInstance(adapter, AdapterNotYetImplemented)
            self.assertIsInstance(adapter, V0SourceAdapter)
            self.assertEqual(adapter.implementation_status, "READY_FOR_MATERIALIZATION")

    def test_transition_identity_equivalence_via_adapters(self) -> None:
        registry = build_default_registry()
        sealed = _load_jsonl(SEALED_PATHS["census"])
        sealed_keys = {
            (
                r["repository"],
                r["source_sha"],
                r["target_sha"],
                r["transition_id"],
                r["eligibility"],
            )
            for r in sealed
        }
        observed_keys = set()
        for identity in V0_IDENTITIES:
            checkout = DEFAULT_CHECKOUTS[identity.repository]
            self.assertTrue(checkout.is_dir(), f"missing checkout {checkout}")
            adapter = registry[identity.repository]
            for record in adapter.enumerate_transitions(
                checkout, cutoff_sha=identity.cutoff_sha
            ):
                observed_keys.add(
                    (
                        record.repository,
                        record.source_sha,
                        record.target_sha,
                        record.transition_id,
                        record.eligibility,
                    )
                )
        self.assertEqual(
            observed_keys,
            sealed_keys,
            "adapter FIRST_PARENT identities diverge from sealed census",
        )

    def test_anchor_byte_equivalence_via_adapters(self) -> None:
        registry = build_default_registry()
        sealed_census = [
            r
            for r in _load_jsonl(SEALED_PATHS["census"])
            if r.get("eligibility") == "ELIGIBLE"
        ]
        from expansion_v2.adapter_contract import TransitionEnumerationRecord

        transitions = [
            TransitionEnumerationRecord(
                transition_id=r["transition_id"],
                repository=r["repository"],
                source_sha=r["source_sha"],
                target_sha=r["target_sha"],
                source_timestamp=r.get("source_timestamp"),
                target_timestamp=r.get("target_timestamp"),
                changed_paths=tuple(r.get("changed_paths") or ()),
                eligibility=r["eligibility"],
                exclusion_reason=r.get("exclusion_reason"),
                candidate_semantic_categories=tuple(
                    r.get("candidate_semantic_categories") or ()
                ),
            )
            for r in sealed_census
        ]
        rows = extract_all_v0_anchors(registry, DEFAULT_CHECKOUTS, transitions)
        payload = b"".join(_canonical_bytes(row) + b"\n" for row in rows)
        digest = _sha256_bytes(payload)
        self.assertEqual(
            digest,
            SEALED_V0_DIGESTS["historical_anchors_sha256"],
            "adapter anchors diverge from sealed HISTORICAL_ANCHORS digest",
        )

    def test_semantic_equivalence_via_authentic_materializer_bridge(self) -> None:
        """Re-run authentic materialize+project through v0 adapters.

        Byte identity of the full semantic JSONL is not contracted (host Python
        affects runtime_identity). Decision-surface fields must match sealed
        records for every anchor_id on the overlapping supported surface.
        """
        registry = build_default_registry()
        anchors = _load_jsonl(SEALED_PATHS["anchors"])
        anchors.sort(
            key=lambda row: (
                str(row["repository"]),
                str(row["source_sha"]),
                str(row["anchor_id"]),
            )
        )
        work_root = REPO_ROOT / "_rtk_materialize_work"
        work_root.mkdir(parents=True, exist_ok=True)

        from collections import defaultdict

        from expansion_v2.adapters import v0_bridge

        grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for anchor in anchors:
            grouped[(str(anchor["repository"]), str(anchor["source_sha"]))].append(
                anchor
            )

        results: list[dict] = []
        mse = materialize_source_evidence
        for (repository, source_sha), members in sorted(grouped.items()):
            adapter = registry[repository]
            checkout = DEFAULT_CHECKOUTS[repository]
            assert isinstance(adapter, V0SourceAdapter)
            group_root = work_root / mse._typed_digest(
                "rtk-source-worktree-v0",
                {"repository": repository, "source_sha": source_sha},
            )
            group_root.mkdir(parents=True, exist_ok=True)
            with mse._source_worktree(checkout, source_sha, group_root) as worktree:
                cache: dict = {}
                for anchor in sorted(members, key=lambda r: str(r["anchor_id"])):
                    claim = adapter.claim_anchor_from_payload(anchor)
                    record = v0_bridge.materialize_anchor(
                        dict(claim.payload),
                        worktree,
                        timeout_sec=1800,
                        cache=cache,
                    )
                    results.append(record)

        results.sort(key=lambda row: str(row["anchor_id"]))
        semantic = [project_record(row) for row in results]
        semantic.sort(key=lambda row: str(row["anchor_id"]))
        sealed_sem = {r["anchor_id"]: r for r in _load_jsonl(SEALED_PATHS["semantic"])}
        self.assertEqual(
            {r["anchor_id"] for r in semantic},
            set(sealed_sem),
            "adapter semantic anchor_id set diverges from sealed",
        )

        def candidate_surface(rows: list[dict]) -> list[dict]:
            out = []
            for cand in rows:
                out.append(
                    {
                        "candidate_id": cand.get("candidate_id"),
                        "locator": cand.get("locator"),
                        "native_accept": cand.get("native_accept"),
                        "subject_binding": cand.get("subject_binding"),
                        "rejection_reason": cand.get("rejection_reason"),
                        "artifacts": cand.get("artifacts"),
                    }
                )
            return out

        divergences = []
        for row in semantic:
            other = sealed_sem[row["anchor_id"]]
            diff = {}
            for key in (
                "materialization_status",
                "subject_binding",
                "selected_candidate_id",
                "native_verifier_digest",
                "family",
                "claim_id",
                "contract_locator",
                "evidence_snapshot",
                "target_native_validator_executed",
                "rtk_executed",
                "oracle_labels_consulted",
            ):
                if row.get(key) != other.get(key):
                    diff[key] = {"adapter": row.get(key), "sealed": other.get(key)}
            if candidate_surface(row.get("candidates") or []) != candidate_surface(
                other.get("candidates") or []
            ):
                diff["candidates_surface"] = {
                    "adapter": candidate_surface(row.get("candidates") or []),
                    "sealed": candidate_surface(other.get("candidates") or []),
                }
            # Environment: require source_runtime.ok/reason and dependency digests;
            # ignore host-volatile runtime_identity / setup_outcomes.
            env_a = (row.get("environment_semantics") or {}).get("source_runtime") or {}
            env_s = (other.get("environment_semantics") or {}).get("source_runtime") or {}
            for key in ("ok", "reason", "requirements_lock_sha256", "pyproject_sha256"):
                if env_a.get(key) != env_s.get(key):
                    diff[f"source_runtime.{key}"] = {
                        "adapter": env_a.get(key),
                        "sealed": env_s.get(key),
                    }
            ce_a = (row.get("environment_semantics") or {}).get("certifyedge_build") or {}
            ce_s = (other.get("environment_semantics") or {}).get("certifyedge_build") or {}
            for key in ("status", "exit_code"):
                if ce_a.get(key) != ce_s.get(key):
                    diff[f"certifyedge_build.{key}"] = {
                        "adapter": ce_a.get(key),
                        "sealed": ce_s.get(key),
                    }
            if diff:
                divergences.append({"anchor_id": row["anchor_id"], "diff": diff})

        if divergences:
            self.fail(
                "BLOCKER: semantic decision-surface divergence from sealed v0. "
                f"divergence_count={len(divergences)} sample={divergences[:5]!r}"
            )


if __name__ == "__main__":
    unittest.main()
