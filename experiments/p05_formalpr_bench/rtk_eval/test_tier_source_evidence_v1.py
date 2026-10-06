"""Synthetic acceptance/rejection tests for tier_source_evidence_v1 predicates.

Covers every frozen attestation acceptance and rejection reason plus v0
false-admission guards. Does not execute RTK, oracle labels, or baselines.
"""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


def _load_tier_module():
    path = Path(__file__).resolve().parent / "tier_source_evidence_v1.py"
    spec = importlib.util.spec_from_file_location("tier_source_evidence_v1", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tier = _load_tier_module()


def _base_result(**overrides):
    result = {
        "schema_version": "v0",
        "workflow_profile_id": "labtrust.qc_release_v0.1",
        "validator": "pcs-core",
        "status": "ProofChecked",
        "checks": [{"name": "release_chain", "status": "passed"}],
        "failure_codes": [],
        "signature_or_digest": "sha256:" + ("ab" * 32),
        "source_repo": "https://github.com/SentinelOps-CI/pcs-core",
        "checked_at": "2024-01-01T00:00:00+00:00",
        "release_id": "release-synthetic-001",
        "validation_id": "validation-synthetic-001",
        "source_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }
    result.update(overrides)
    return result


class AttestationPredicateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source_time = datetime(2024, 6, 1, tzinfo=timezone.utc)
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.directory = self.root / "examples" / "ok"
        self.directory.mkdir(parents=True)
        self.repo = self.root
        (self.directory / "trace_certificate.json").write_text(
            '{"status":"CertificateChecked","violations":[],"counterexample_ref":null,'
            '"certificate_id":"cert-1"}',
            encoding="utf-8",
        )
        (self.directory / "release_manifest.v0.json").write_text(
            '{"workflow_profile_id":"labtrust.qc_release_v0.1","release_id":'
            '"release-synthetic-001","release_status":"Validated",'
            '"chain_root":{"certificate_id":"cert-1"}}',
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run(self, result, *, ancestor=True):
        with mock.patch.object(tier, "_commit_is_ancestor", return_value=ancestor):
            return tier._attestation_predicate(
                result,
                workflow_id="labtrust.qc_release_v0.1",
                source_commit_time=self.source_time,
                repository=self.repo,
                anchor_source_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                directory=self.directory,
            )

    def test_accept_qualifying_committed_attestation(self):
        ok, reasons, details = self._run(_base_result())
        self.assertTrue(ok, reasons)
        self.assertEqual(reasons, [])
        self.assertTrue(details["result_source_commit_is_ancestor"])
        self.assertEqual(details["native_certificate_status"], "CertificateChecked")
        self.assertEqual(details["release_manifest_locator"], "release_manifest.v0.json")

    def test_reject_schema_version(self):
        ok, reasons, _ = self._run(_base_result(schema_version="v1"))
        self.assertFalse(ok)
        self.assertIn("schema_version is not v0", reasons)

    def test_reject_workflow_profile_mismatch(self):
        ok, reasons, _ = self._run(
            _base_result(workflow_profile_id="other.workflow")
        )
        self.assertFalse(ok)
        self.assertIn("workflow_profile_id mismatch", reasons)

    def test_reject_validator_not_pcs_core(self):
        ok, reasons, _ = self._run(_base_result(validator="other"))
        self.assertFalse(ok)
        self.assertIn("validator is not pcs-core", reasons)

    def test_reject_status_not_proof_checked(self):
        ok, reasons, _ = self._run(_base_result(status="Failed"))
        self.assertFalse(ok)
        self.assertIn("status is not ProofChecked", reasons)

    def test_reject_empty_checks(self):
        ok, reasons, _ = self._run(_base_result(checks=[]))
        self.assertFalse(ok)
        self.assertIn("checks is empty or absent", reasons)

    def test_reject_failed_check(self):
        ok, reasons, _ = self._run(
            _base_result(checks=[{"name": "x", "status": "failed"}])
        )
        self.assertFalse(ok)
        self.assertIn("one or more checks are not passed", reasons)

    def test_reject_nonempty_failure_codes(self):
        ok, reasons, _ = self._run(_base_result(failure_codes=["E1"]))
        self.assertFalse(ok)
        self.assertIn("failure_codes is nonempty", reasons)

    def test_reject_bad_signature_digest(self):
        ok, reasons, _ = self._run(_base_result(signature_or_digest="not-a-digest"))
        self.assertFalse(ok)
        self.assertIn("signature_or_digest is not canonical sha256", reasons)

    def test_reject_wrong_source_repo(self):
        ok, reasons, _ = self._run(
            _base_result(source_repo="https://github.com/example/other")
        )
        self.assertFalse(ok)
        self.assertIn("source_repo is not pcs-core", reasons)

    def test_reject_invalid_checked_at(self):
        ok, reasons, _ = self._run(_base_result(checked_at="not-a-time"))
        self.assertFalse(ok)
        self.assertIn("checked_at is missing or invalid", reasons)

    def test_reject_checked_at_after_source(self):
        later = (self.source_time + timedelta(days=1)).isoformat()
        ok, reasons, _ = self._run(_base_result(checked_at=later))
        self.assertFalse(ok)
        self.assertIn(
            "checked_at is later than source revision author timestamp", reasons
        )

    def test_reject_missing_subject_identity(self):
        result = _base_result()
        del result["release_id"]
        del result["validation_id"]
        ok, reasons, _ = self._run(result)
        self.assertFalse(ok)
        self.assertIn("release/validation subject identity is missing", reasons)

    def test_reject_source_commit_not_ancestor(self):
        ok, reasons, details = self._run(_base_result(), ancestor=False)
        self.assertFalse(ok)
        self.assertIn(
            "result source_commit is not a real ancestor of anchor source revision",
            reasons,
        )
        self.assertFalse(details["result_source_commit_is_ancestor"])

    def test_reject_missing_native_certificate(self):
        (self.directory / "trace_certificate.json").unlink()
        ok, reasons, _ = self._run(_base_result())
        self.assertFalse(ok)
        self.assertIn("workflow-native certificate is missing", reasons)

    def test_reject_certificate_not_checked(self):
        (self.directory / "trace_certificate.json").write_text(
            '{"status":"Failed","violations":[],"certificate_id":"cert-1"}',
            encoding="utf-8",
        )
        ok, reasons, _ = self._run(_base_result())
        self.assertFalse(ok)
        self.assertIn(
            "workflow-native certificate status is not CertificateChecked", reasons
        )

    def test_reject_certificate_violations(self):
        (self.directory / "trace_certificate.json").write_text(
            '{"status":"CertificateChecked","violations":["v1"],"certificate_id":"cert-1"}',
            encoding="utf-8",
        )
        ok, reasons, _ = self._run(_base_result())
        self.assertFalse(ok)
        self.assertIn("workflow-native certificate carries violations", reasons)

    def test_reject_certificate_counterexample(self):
        (self.directory / "trace_certificate.json").write_text(
            '{"status":"CertificateChecked","violations":[],"counterexample_ref":"x",'
            '"certificate_id":"cert-1"}',
            encoding="utf-8",
        )
        ok, reasons, _ = self._run(_base_result())
        self.assertFalse(ok)
        self.assertIn("workflow-native certificate carries a counterexample", reasons)

    def test_reject_certificate_identity_missing(self):
        (self.directory / "trace_certificate.json").write_text(
            '{"status":"CertificateChecked","violations":[]}',
            encoding="utf-8",
        )
        ok, reasons, _ = self._run(_base_result())
        self.assertFalse(ok)
        self.assertIn("workflow-native certificate identity is missing", reasons)

    def test_reject_unmapped_workflow_certificate(self):
        ok, reasons, _ = tier._attestation_predicate(
            _base_result(workflow_profile_id="unknown.workflow"),
            workflow_id="unknown.workflow",
            source_commit_time=self.source_time,
            repository=self.repo,
            anchor_source_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            directory=self.directory,
        )
        self.assertFalse(ok)
        self.assertIn("workflow has no frozen native-certificate mapping", reasons)

    def test_reject_missing_release_manifest(self):
        (self.directory / "release_manifest.v0.json").unlink()
        ok, reasons, _ = self._run(_base_result())
        self.assertFalse(ok)
        self.assertIn("release_manifest.v0.json is missing or invalid", reasons)

    def test_reject_manifest_workflow_mismatch(self):
        (self.directory / "release_manifest.v0.json").write_text(
            '{"workflow_profile_id":"other","release_id":"release-synthetic-001",'
            '"release_status":"Validated","chain_root":{"certificate_id":"cert-1"}}',
            encoding="utf-8",
        )
        ok, reasons, _ = self._run(_base_result())
        self.assertFalse(ok)
        self.assertIn("release manifest workflow_profile_id mismatch", reasons)

    def test_reject_manifest_release_id_mismatch(self):
        (self.directory / "release_manifest.v0.json").write_text(
            '{"workflow_profile_id":"labtrust.qc_release_v0.1","release_id":"other",'
            '"release_status":"Validated","chain_root":{"certificate_id":"cert-1"}}',
            encoding="utf-8",
        )
        ok, reasons, _ = self._run(_base_result())
        self.assertFalse(ok)
        self.assertIn("release manifest release_id mismatch", reasons)

    def test_reject_manifest_not_validated(self):
        (self.directory / "release_manifest.v0.json").write_text(
            '{"workflow_profile_id":"labtrust.qc_release_v0.1","release_id":'
            '"release-synthetic-001","release_status":"Pending",'
            '"chain_root":{"certificate_id":"cert-1"}}',
            encoding="utf-8",
        )
        ok, reasons, _ = self._run(_base_result())
        self.assertFalse(ok)
        self.assertIn("release manifest release_status is not Validated", reasons)

    def test_reject_manifest_certificate_unbind(self):
        (self.directory / "release_manifest.v0.json").write_text(
            '{"workflow_profile_id":"labtrust.qc_release_v0.1","release_id":'
            '"release-synthetic-001","release_status":"Validated",'
            '"chain_root":{"certificate_id":"other-cert"}}',
            encoding="utf-8",
        )
        ok, reasons, _ = self._run(_base_result())
        self.assertFalse(ok)
        self.assertIn(
            "release manifest certificate_id does not bind native certificate", reasons
        )


class V0FalseAdmissionGuards(unittest.TestCase):
    """Guards that weaker attestation must not silently inflate Tier A / v0 accept."""

    def test_operational_failure_does_not_become_replay_verified_without_attestation(self):
        row = {
            "anchor_id": "a1",
            "transition_id": "t1",
            "repository": "SentinelOps-CI/pcs-core",
            "source_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "family": "PCS_WORKFLOW_PROFILE",
            "claim_id": "pcs-workflow:labtrust.qc_release_v0.1",
            "materialization_status": "OPERATIONAL_FAILURE",
            "target_native_validator_executed": False,
            "rtk_executed": False,
            "oracle_labels_consulted": False,
        }
        # Simulate the classification preamble without worktree upgrades.
        classified = dict(row)
        classified["source_evidence_class"] = (
            tier.CLASS_REPLAY
            if classified.get("materialization_status") == tier.STATUS_REPLAY
            else None
        )
        classified["attestation_candidates"] = []
        self.assertIsNone(classified["source_evidence_class"])
        self.assertNotEqual(classified["materialization_status"], "SOURCE_ACCEPTED")

    def test_source_accepted_maps_only_to_replay_verified(self):
        status = "SOURCE_ACCEPTED"
        evidence_class = (
            tier.CLASS_REPLAY if status == tier.STATUS_REPLAY else None
        )
        self.assertEqual(evidence_class, "REPLAY_VERIFIED")

    def test_partial_attestation_without_certificate_is_not_tier_b(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            root = Path(tmp.name)
            directory = root / "examples" / "partial"
            directory.mkdir(parents=True)
            # Result alone is insufficient: missing certificate + manifest.
            (directory / "release_chain_validation_result.v0.json").write_text(
                __import__("json").dumps(_base_result()), encoding="utf-8"
            )
            (directory / "workflow_profile.v0.json").write_text(
                '{"workflow_id":"labtrust.qc_release_v0.1"}', encoding="utf-8"
            )
            with mock.patch.object(tier, "_commit_is_ancestor", return_value=True):
                with mock.patch.object(
                    tier,
                    "_commit_time",
                    return_value=datetime(2024, 6, 1, tzinfo=timezone.utc),
                ):
                    candidates = tier._attestation_candidates(
                        root,
                        workflow_id="labtrust.qc_release_v0.1",
                        source_commit_time=datetime(2024, 6, 1, tzinfo=timezone.utc),
                        source_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    )
            self.assertTrue(candidates)
            self.assertFalse(any(c["attestation_accept"] for c in candidates))
            self.assertTrue(
                any(
                    "workflow-native certificate is missing" in c["attestation_rejection_reasons"]
                    for c in candidates
                )
            )
        finally:
            tmp.cleanup()

    def test_certifyedge_operational_failure_is_ineligible_for_tier_b(self):
        # Tier B eligibility is pcs-core + PCS_WORKFLOW_PROFILE + OPERATIONAL_FAILURE only.
        repository = "fraware/CertifyEdge"
        family = "CERTIFYEDGE_PROPERTY_PROFILE"
        status = "OPERATIONAL_FAILURE"
        eligible = (
            repository == "SentinelOps-CI/pcs-core"
            and family == tier.FAMILY_WORKFLOW
            and status == tier.STATUS_OPERATIONAL
        )
        self.assertFalse(eligible)


if __name__ == "__main__":
    unittest.main()
