"""Development-only independent target replay of exact historical Lean Expr bytes.

This adapter exports an *unproved* target claim observed by native Lean and
checks the native target-kernel replay witness. It does not infer historical
applicability from hashes, dependency graphs, or fresh target proof success.
CI supplies the exact binaries, modules, and runner; hashes do not attest
their independent trustworthiness. No output authorizes production reliance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from experiments.rtk.lean_second_process_source_v1 import separate_native_driver
from experiments.rtk.lean_structural_expr_v1 import (
    _canonical, _digest, _expression, _structural_ast,
)

_SOURCE_SCHEMA = "rtk.lean_separate_source_proof_payload.v1-development"
_TARGET_SCHEMA = "rtk.lean_target_claim_export.v1-development"
_WITNESS_SCHEMA = "rtk.lean_historical_target_replay.v1-development"
_MARKER = "RTK_HISTORICAL_TARGET_REPLAY_JSON="


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_object(raw: bytes, what: str) -> dict[str, Any]:
    if len(raw) > 12_000_000:
        raise ValueError(f"{what}: input too large")
    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"{what}: invalid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{what}: expected JSON object")
    return data


def _source(raw: bytes) -> dict[str, Any]:
    data = _load_object(raw, "historical source payload")
    keys = {
        "schema_version", "declaration_name", "claim_ast", "proof_ast",
        "source_native_log_sha256", "source_checked_file_sha256",
        "source_proof_expr_ast_sha256", "historical_transport_applicability",
        "target_historical_proof_replay_executed", "target_claim_established",
        "reliance_authorization",
    }
    if set(data) != keys or data["schema_version"] != _SOURCE_SCHEMA or (
        data["declaration_name"] != "historical_claim"
    ):
        raise ValueError("incorrect historical source evidence identity")
    if data["historical_transport_applicability"] != "UNDETERMINED" or any(
        data[k] is not False for k in (
            "target_historical_proof_replay_executed", "target_claim_established",
            "reliance_authorization",
        )
    ):
        raise ValueError("historical source contains target oracle contamination")
    budget = [100_000]
    _expression(data["claim_ast"], 0, budget)
    _expression(data["proof_ast"], 0, budget)
    if _digest(data["proof_ast"]) != data["source_proof_expr_ast_sha256"]:
        raise ValueError("source proof AST does not match exported proof digest")
    for k in ("source_native_log_sha256", "source_checked_file_sha256"):
        if not isinstance(data[k], str) or len(data[k]) != 64 or any(
            c not in "0123456789abcdef" for c in data[k]
        ):
            raise ValueError("source artifact digest malformed")
    return data


def export_target_claim(
    *, source_payload_bytes: bytes, target_native_log: str,
) -> dict[str, Any]:
    """Export an independently observed unproved target claim, not its result."""
    source = _source(source_payload_bytes)
    target = _structural_ast(target_native_log)
    if (
        target["theorem_name"] != "rtk_unproven_target_claim"
        or target["theorem_kind"] != "axiom"
        or target["theorem_value_ast"] is not None
    ):
        raise ValueError("target claim is not the unproved target placeholder")
    if source["claim_ast"] != target["theorem_type_ast"]:
        raise ValueError("bounded fixture has mismatched statement AST")
    return {
        "schema_version": _TARGET_SCHEMA,
        "claim_name": "rtk_unproven_target_claim",
        "claim_ast": target["theorem_type_ast"],
        "claim_ast_sha256": _digest(target["theorem_type_ast"]),
        "target_native_preoracle_log_sha256": _sha(
            target_native_log.encode("utf-8")
        ),
        "historical_source_payload_sha256": _sha(source_payload_bytes),
        "target_claim_established": False,
        "native_target_proof_replay_executed": False,
        "reliance_authorization": False,
    }


def verify_target_replay(
    *, source_payload_bytes: bytes, target_payload_bytes: bytes,
    driver_bytes: bytes, module_bytes: bytes, native_log: str,
    expected_decision: str,
) -> dict[str, Any]:
    """Adjudicate a native replay log against the original serialized bytes.

    The expected decision is a *development fixture assertion*. It is not a
    prediction and is never read by the Lean kernel driver.
    """
    source = _source(source_payload_bytes)
    target = _load_object(target_payload_bytes, "target claim export")
    if set(target) != {
        "schema_version", "claim_name", "claim_ast", "claim_ast_sha256",
        "target_native_preoracle_log_sha256", "historical_source_payload_sha256",
        "target_claim_established", "native_target_proof_replay_executed",
        "reliance_authorization",
    } or target["schema_version"] != _TARGET_SCHEMA or (
        target["claim_name"] != "rtk_unproven_target_claim"
    ):
        raise ValueError("target claim export has invalid identity")
    if (
        target["historical_source_payload_sha256"] != _sha(source_payload_bytes)
        or target["claim_ast_sha256"] != _digest(target["claim_ast"])
        or target["claim_ast"] != source["claim_ast"]
        or any(target[k] is not False for k in (
            "target_claim_established", "native_target_proof_replay_executed",
            "reliance_authorization",
        ))
    ):
        raise ValueError("source/target export mismatch or replay contamination")
    if not isinstance(target["target_native_preoracle_log_sha256"], str) or (
        len(target["target_native_preoracle_log_sha256"]) != 64
    ):
        raise ValueError("target native log provenance digest missing")
    budget = [100_000]
    _expression(target["claim_ast"], 0, budget)

    markers = [
        line.partition(_MARKER)[2].strip()
        for line in native_log.splitlines() if _MARKER in line
    ]
    if len(markers) != 1 or len(markers[0]) > 12_000_000:
        raise ValueError("one native historical replay witness required")
    witness = _load_object(markers[0].encode("utf-8"), "native replay witness")
    if set(witness) != {
        "schema_version", "source_proof_ast", "target_claim_ast",
        "kernel_check_accepted", "inferred_type_defeq_target_claim",
        "adjudication", "target_theorem_or_placeholder_preloaded",
        "fresh_target_proof_supplied_to_oracle", "rtk_predictor_consulted",
        "relying_authority", "semantic_support_soundness_proved",
    } or witness["schema_version"] != _WITNESS_SCHEMA:
        raise ValueError("invalid native replay witness schema")
    if witness["source_proof_ast"] != source["proof_ast"] or (
        witness["target_claim_ast"] != target["claim_ast"]
    ):
        raise ValueError("native replay used substituted certificate or claim")
    if any(witness[k] is not False for k in (
        "target_theorem_or_placeholder_preloaded",
        "fresh_target_proof_supplied_to_oracle", "rtk_predictor_consulted",
        "relying_authority", "semantic_support_soundness_proved",
    )):
        raise ValueError("native replay leaked external reliance or SUT authority")
    checked = witness["kernel_check_accepted"]
    defeq = witness["inferred_type_defeq_target_claim"]
    if type(checked) is not bool or type(defeq) is not bool or (
        defeq and not checked
    ):
        raise ValueError("inconsistent native kernel result flags")
    if checked and defeq:
        inferred = "ADMISSIBLE"
    elif checked:
        inferred = "INADMISSIBLE"
    else:
        inferred = "UNDETERMINED"
    if witness["adjudication"] != inferred:
        raise ValueError("native replay decision inconsistent with kernel flags")
    if expected_decision not in {"ADMISSIBLE", "INADMISSIBLE", "UNDETERMINED"}:
        raise ValueError("unknown development control verdict")
    if inferred != expected_decision:
        raise ValueError("native replay disagrees with development control")
    if not driver_bytes or not module_bytes:
        raise ValueError("missing target checker driver or imported module bytes")
    return {
        "schema_version": "rtk.lean_independent_target_oracle_observation.v1-development",
        "historical_source_payload_sha256": _sha(source_payload_bytes),
        "target_claim_payload_sha256": _sha(target_payload_bytes),
        "native_target_log_sha256": _sha(native_log.encode()),
        "replay_driver_sha256": _sha(driver_bytes),
        "target_imported_olean_sha256": _sha(module_bytes),
        "historical_certificate_adjudication": inferred,
        "target_claim_truth_adjudicated": False,
        "native_target_kernel_replay_observed": True,
        "predictor_consulted": False,
        "complete_semantic_support_proved": False,
        "runner_or_toolchain_provenance_independently_attested": False,
        "production_reliance_authorized": False,
    }


def _save_new(path: Path, value: bytes) -> None:
    with path.open("xb") as file:
        file.write(value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    pre = commands.add_parser("prepare", help="Create target claim and native driver")
    for name in ("source-payload", "target-native-log", "encoder-source",
                 "decoder-source", "driver-source", "target-output",
                 "lean-driver-output"):
        pre.add_argument("--" + name, required=True, type=Path)
    post = commands.add_parser("verify", help="Validate native replay witness")
    for name in ("source-payload", "target-payload", "lean-driver",
                 "target-olean", "native-log", "output"):
        post.add_argument("--" + name, required=True, type=Path)
    post.add_argument("--expected-decision", required=True,
                      choices=("ADMISSIBLE", "INADMISSIBLE", "UNDETERMINED"))
    args = parser.parse_args()
    if args.command == "prepare":
        result = export_target_claim(
            source_payload_bytes=args.source_payload.read_bytes(),
            target_native_log=args.target_native_log.read_text(),
        )
        _save_new(args.target_output, _canonical(result) + b"\n")
        driver = separate_native_driver(
            encoder=args.encoder_source.read_text(),
            decoder=args.decoder_source.read_text(),
            driver=args.driver_source.read_text(),
        )
        _save_new(args.lean_driver_output, driver.encode())
        print("UNPROVED_TARGET_CLAIM_EXPORTED_NO_ORACLE_LABEL")
    else:
        record = verify_target_replay(
            source_payload_bytes=args.source_payload.read_bytes(),
            target_payload_bytes=args.target_payload.read_bytes(),
            driver_bytes=args.lean_driver.read_bytes(),
            module_bytes=args.target_olean.read_bytes(),
            native_log=args.native_log.read_text(),
            expected_decision=args.expected_decision,
        )
        _save_new(args.output, json.dumps(
            record, sort_keys=True, indent=2,
        ).encode() + b"\n")
        print("INDEPENDENT_TARGET_CERTIFICATE_REPLAY_DEVELOPMENT_" +
              record["historical_certificate_adjudication"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
