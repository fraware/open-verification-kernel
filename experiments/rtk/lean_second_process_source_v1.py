"""Export checked historical Lean proof Expr bytes for a second native process.

The exported file is serialized, SHA-256 identified and verified against the
separately captured source native log and #190 evidence envelope. The target
proof is never supplied to this workflow. The separate process itself runs
Lean.Kernel.check and Kernel.isDefEq, not this Python adapter.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from experiments.rtk.lean_structural_expr_v1 import _structural_ast, _canonical, _digest

_SCHEMA = "rtk.lean_separate_source_proof_payload.v1-development"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write_new(path: Path, content: bytes) -> None:
    with path.open("xb") as output:
        output.write(content)


def export_checked_source_proof(
    *,
    native_structural_log: str,
    native_envelope: object,
    checked_source_file: bytes,
) -> dict:
    native = _structural_ast(native_structural_log)
    if native["theorem_name"] != "historical_claim" or (
        native["theorem_kind"] != "theorem"
    ):
        raise ValueError("only source checked theorem may be exported")
    if not isinstance(native_envelope, dict) or (
        native_envelope.get("schema_version") !=
        "rtk.lean_preoracle_native_evidence.v1-development"
    ):
        raise ValueError("unrecognized preoracle evidence envelope")
    if native_envelope.get("source_structural_native_log_sha256") != _sha(
        native_structural_log.encode()
    ) or native_envelope.get("source_exact_checked_input_sha256") != _sha(
        checked_source_file
    ):
        raise ValueError("native source log or checked input mismatch")
    if any(native_envelope.get(key) is not False for key in (
        "target_historical_proof_replay_executed", "target_claim_established",
        "reliance_authorization", "complete_semantic_support_established",
        "independent_runner_attestation_verified",
    )) or native_envelope.get("historical_evidence_applicability") != (
        "UNDETERMINED"
    ):
        raise ValueError("contaminated or improperly authorized source evidence")
    if (
        b"theorem historical_claim " not in checked_source_file
        or b"Eq.refl n" not in checked_source_file
    ):
        raise ValueError("missing source declaration or historical proof source")
    if _digest(native["theorem_value_ast"]) != native_envelope.get(
        "source_checked_proof_expr_ast_sha256"
    ) or _digest(native["theorem_type_ast"]) != native_envelope.get(
        "statement_expr_ast_sha256"
    ):
        raise ValueError("checked source claim/proof AST digest mismatch")

    return {
        "schema_version": _SCHEMA,
        "declaration_name": "historical_claim",
        "claim_ast": native["theorem_type_ast"],
        "proof_ast": native["theorem_value_ast"],
        "source_native_log_sha256": _sha(native_structural_log.encode()),
        "source_checked_file_sha256": _sha(checked_source_file),
        "source_proof_expr_ast_sha256":
            native_envelope["source_checked_proof_expr_ast_sha256"],
        "historical_transport_applicability": "UNDETERMINED",
        "target_historical_proof_replay_executed": False,
        "target_claim_established": False,
        "reliance_authorization": False,
    }


def separate_native_driver(
    *, encoder: str, decoder: str, driver: str,
) -> str:
    marker = "\nrun_cmd do\n"
    for fragment, label in ((encoder, "encoder"), (decoder, "decoder")):
        if fragment.count(marker) != 1:
            raise ValueError("unexpected " + label + " native driver boundary")
    encoder_defs = encoder.partition(marker)[0]
    decoder_defs = decoder.partition(marker)[0]
    if "run_cmd do" in driver or "import " in driver:
        raise ValueError("standalone driver contains forbidden front matter")
    return (
        "import Lean\nimport RTKSemanticSupport\n"
        + encoder_defs + "\n"
        + decoder_defs + "\n"
        + driver
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "source-structural-log", "native-envelope", "source-checked-input",
        "encoder-source", "decoder-source", "driver-source",
        "payload-output", "lean-driver-output", "manifest-output",
    ):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    source_log = args.source_structural_log.read_text()
    source_input = args.source_checked_input.read_bytes()
    payload = export_checked_source_proof(
        native_structural_log=source_log,
        native_envelope=json.loads(args.native_envelope.read_text()),
        checked_source_file=source_input,
    )
    payload_bytes = _canonical(payload) + b"\n"
    driver = separate_native_driver(
        encoder=args.encoder_source.read_text(),
        decoder=args.decoder_source.read_text(),
        driver=args.driver_source.read_text(),
    )
    driver_bytes = driver.encode("utf-8")
    _write_new(args.payload_output, payload_bytes)
    _write_new(args.lean_driver_output, driver_bytes)
    manifest = {
        "schema_version": "rtk.lean_second_process_export_manifest.v1-development",
        "payload_sha256": _sha(payload_bytes),
        "driver_sha256": _sha(driver_bytes),
        "source_structural_log_sha256": _sha(source_log.encode()),
        "source_checked_file_sha256": _sha(source_input),
        "source_native_proof_expr_ast_sha256":
            payload["source_proof_expr_ast_sha256"],
        "target_old_proof_replayed": False,
        "target_claim_established": False,
        "independent_native_process_proven": False,
        "source_proof_type_checked_in_new_process": False,
        "transport_applicability": "UNDETERMINED",
    }
    _write_new(args.manifest_output, _canonical(manifest) + b"\n")
    print("SOURCE_PROOF_AST_EXPORTED_FOR_INDEPENDENT_PROCESS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
