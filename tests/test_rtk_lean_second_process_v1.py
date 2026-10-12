"""Strict synthetic negative checks; actual kernel validation is Lean workflow."""

from __future__ import annotations

import hashlib
import json

import pytest

from experiments.rtk.lean_second_process_source_v1 import (
    export_checked_source_proof,
    separate_native_driver,
)
from experiments.rtk.lean_second_process_witness_v1 import attest_second_process
from experiments.rtk.lean_structural_expr_v1 import _digest

NAT = ["const", ["str", ["anonymous"], "Nat"], []]
CLAIM = ["forallE", ["str", ["anonymous"], "n"], NAT,
         ["app", ["const", ["str", ["anonymous"], "Eq.refl"], []], ["bvar", 0]],
         "default"]
PROOF = ["lam", ["str", ["anonymous"], "n"], NAT,
         ["app", ["const", ["str", ["anonymous"], "Eq.refl"], []], ["bvar", 0]],
         "default"]
SOURCE = b"import Lean\ntheorem historical_claim (n : Nat) : n = n :=\n  Eq.refl n\n"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fixture():
    native = {
        "schema_version": "rtk.lean_native_structural_expr.v1-development",
        "theorem_name": "historical_claim",
        "theorem_kind": "theorem",
        "theorem_type_ast": CLAIM,
        "theorem_value_ast": PROOF,
        "op_name": "op",
        "op_type_ast": NAT,
        "op_value_ast": NAT,
        "unsupported_constructs_silently_omitted": False,
        "imported_support_closure_proved": False,
    }
    log = "source.lean: info: RTK_STRUCTURAL_EXPR_JSON=" + json.dumps(native)
    envelope = {
        "schema_version": "rtk.lean_preoracle_native_evidence.v1-development",
        "source_structural_native_log_sha256": _sha(log.encode()),
        "source_exact_checked_input_sha256": _sha(SOURCE),
        "source_checked_proof_expr_ast_sha256": _digest(PROOF),
        "statement_expr_ast_sha256": _digest(CLAIM),
        "target_historical_proof_replay_executed": False,
        "target_claim_established": False,
        "reliance_authorization": False,
        "complete_semantic_support_established": False,
        "independent_runner_attestation_verified": False,
        "historical_evidence_applicability": "UNDETERMINED",
    }
    return log, envelope


def _payload():
    log, envelope = _fixture()
    return export_checked_source_proof(
        native_structural_log=log,
        native_envelope=envelope,
        checked_source_file=SOURCE,
    )


def _witness(payload: dict) -> str:
    record = {
        "schema_version": "rtk.lean_second_process_kernel_check.v1-development",
        "declaration_name": "historical_claim",
        "claim_ast": payload["claim_ast"],
        "proof_ast": payload["proof_ast"],
        "source_proof_kernel_checked": True,
        "source_proof_type_defeq_serialized_claim": True,
        "historical_theorem_not_imported_or_declared": True,
        "serialized_expr_loaded_from_disk": True,
        "independent_process_from_serializer": True,
        "target_historical_proof_replayed": False,
        "target_claim_established": False,
        "independently_governed_provenance": False,
        "transitive_support_completeness_proved": False,
        "transport_applicability_established": False,
    }
    return "run: info: RTK_SECOND_PROCESS_PROOF_JSON=" + json.dumps(record)


def _attest_input():
    payload = _payload()
    payload_bytes = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode() + b"\n"
    driver = b"import Lean\nimport RTKSemanticSupport\nrun_cmd do\n  pure ()\n"
    log, _ = _fixture()
    manifest = {
        "schema_version": "rtk.lean_second_process_export_manifest.v1-development",
        "payload_sha256": _sha(payload_bytes),
        "driver_sha256": _sha(driver),
        "source_structural_log_sha256": _sha(log.encode()),
        "source_checked_file_sha256": _sha(SOURCE),
        "source_native_proof_expr_ast_sha256": _digest(PROOF),
        "target_old_proof_replayed": False,
        "target_claim_established": False,
        "independent_native_process_proven": False,
        "source_proof_type_checked_in_new_process": False,
        "transport_applicability": "UNDETERMINED",
    }
    return {
        "payload_bytes": payload_bytes, "manifest": manifest,
        "native_log": _witness(payload), "driver_bytes": driver,
    }


def test_source_export_and_separate_witness_fail_closed_nontransport():
    payload = _payload()
    assert payload["declaration_name"] == "historical_claim"
    record = attest_second_process(**_attest_input())
    assert record["native_source_proof_type_matches_serialized_claim"] is True
    assert record["target_claim_established"] is False
    assert record["reliance_authorization"] is False
    assert record["target_transport_applicability"] == "UNDETERMINED"


@pytest.mark.parametrize(
    ("key", "value", "diagnostic"),
    [
        ("source_checked_proof_expr_ast_sha256", "0" * 64, "claim/proof AST"),
        ("source_structural_native_log_sha256", "0" * 64, "native source log"),
        ("historical_evidence_applicability", "ADMISSIBLE", "contaminated"),
        ("target_claim_established", True, "contaminated"),
    ],
)
def test_export_rejects_tampered_or_overstated_native_evidence(key, value, diagnostic):
    log, env = _fixture()
    env[key] = value
    with pytest.raises(ValueError, match=diagnostic):
        export_checked_source_proof(
            native_structural_log=log, native_envelope=env,
            checked_source_file=SOURCE,
        )


def test_export_rejects_incorrect_source_checked_input():
    log, env = _fixture()
    with pytest.raises(ValueError, match="checked input mismatch"):
        export_checked_source_proof(
            native_structural_log=log, native_envelope=env,
            checked_source_file=b"theorem historical_claim : True := by trivial",
        )


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("payload_sha256", "f" * 64, "payload or driver"),
        ("independent_native_process_proven", True, "export authority"),
        ("transport_applicability", "ADMISSIBLE", "export authority"),
    ],
)
def test_manifest_tamper_fails_closed(field, value, reason):
    kwargs = _attest_input()
    kwargs["manifest"][field] = value
    with pytest.raises(ValueError, match=reason):
        attest_second_process(**kwargs)


def test_native_witness_substitution_and_forged_target_pass_rejected():
    kwargs = _attest_input()
    marker = "RTK_SECOND_PROCESS_PROOF_JSON="
    record = json.loads(kwargs["native_log"].split(marker)[1])
    record["claim_ast"] = ["sort", ["zero"]]
    kwargs["native_log"] = marker + json.dumps(record)
    with pytest.raises(ValueError, match="does not match exported"):
        attest_second_process(**kwargs)
    kwargs = _attest_input()
    record = json.loads(kwargs["native_log"].split(marker)[1])
    record["target_historical_proof_replayed"] = True
    kwargs["native_log"] = marker + json.dumps(record)
    with pytest.raises(ValueError, match="external native reliance"):
        attest_second_process(**kwargs)


def test_separate_driver_only_allows_one_command_boundary():
    defs = "private def helper : Nat := 0\nrun_cmd do\n  pure ()\n"
    driver = "run_cmd do\n  pure ()\n"
    result = separate_native_driver(encoder=defs, decoder=defs, driver=driver)
    assert result.count("run_cmd do") == 1
    assert result.startswith("import Lean\nimport RTKSemanticSupport")
    with pytest.raises(ValueError, match="unsupported command boundary"):
        separate_native_driver(
            encoder=defs, decoder=defs,
            driver="import Lean\nrun_cmd do\n  pure ()\n",
        )
    with pytest.raises(ValueError, match="unexpected encoder"):
        separate_native_driver(encoder="private def helper := 0", decoder=defs,
                               driver=driver)


def test_payload_byte_mutation_rejected_even_if_ast_is_parseable():
    kwargs = _attest_input()
    kwargs["payload_bytes"] = kwargs["payload_bytes"] + b" "
    with pytest.raises(ValueError, match="payload or driver bytes"):
        attest_second_process(**kwargs)


def test_duplicate_witness_markers_rejected():
    kwargs = _attest_input()
    kwargs["native_log"] += "\n" + kwargs["native_log"]
    with pytest.raises(ValueError, match="missing or duplicated"):
        attest_second_process(**kwargs)
