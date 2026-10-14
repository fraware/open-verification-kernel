"""Patched Lean 4.35 historical-certificate research adapter.

All files are new per workflow execution. The original historical expression is
exported from a 4.35 checked theorem, sealed before target replay, and never
replaced by a freshly generated target proof. This is NOT production reliance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from experiments.rtk.lean_historical_target_oracle_v1 import (
    _source, export_target_claim, verify_target_replay,
)
from experiments.rtk.lean_second_process_source_v1 import separate_native_driver
from experiments.rtk.lean_structural_expr_v1 import _canonical, _digest, _structural_ast

VERSION = "4.35.0"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write(path: Path, value: bytes) -> None:
    with path.open("xb") as f:
        f.write(value)


def export_source(log: str, source_bytes: bytes) -> bytes:
    checked = _structural_ast(log)
    if checked["theorem_name"] != "historical_claim" or (
        checked["theorem_kind"] != "theorem"
        or checked["theorem_value_ast"] is None
    ):
        raise ValueError("patched source must contain a checked historical theorem")
    if b"theorem historical_claim" not in source_bytes or b"Eq.refl" not in source_bytes:
        raise ValueError("historical source code not identified")
    payload = {
        "schema_version": "rtk.lean_separate_source_proof_payload.v1-development",
        "declaration_name": "historical_claim",
        "claim_ast": checked["theorem_type_ast"],
        "proof_ast": checked["theorem_value_ast"],
        "source_native_log_sha256": _sha(log.encode()),
        "source_checked_file_sha256": _sha(source_bytes),
        "source_proof_expr_ast_sha256": _digest(checked["theorem_value_ast"]),
        "historical_transport_applicability": "UNDETERMINED",
        "target_historical_proof_replay_executed": False,
        "target_claim_established": False,
        "reliance_authorization": False,
    }
    serialized = _canonical(payload) + b"\n"
    _source(serialized)
    return serialized


def make_driver(encoder: str, decoder: str, driver: str,
                *, module: str, target_filename: str | None = None) -> bytes:
    text = separate_native_driver(encoder=encoder, decoder=decoder, driver=driver)
    text = text.replace("import RTKSemanticSupport", f"import {module}", 1)
    if target_filename is None:
        text = text.replace(
            ".rtk-imported-build/rtk_source_proof_payload.json",
            ".rtk-patched-qualification/source_payload.json",
        )
    else:
        text = text.replace(
            ".rtk-imported-build/rtk_source_proof_payload.json",
            ".rtk-patched-qualification/source_payload.json",
        ).replace(
            ".rtk-imported-build/rtk_target_claim_payload.json",
            target_filename,
        )
    if target_filename is not None:
        # Lean 4.35 no longer exposes EnvironmentHeader.quotInit. Do NOT
        # substitute a guessed value or retain the 4.14 receipt schema.
        old = '("quotient_initialized", Json.bool env.header.quotInit)'
        if text.count(old) != 1:
            raise ValueError("patched replay driver quotient probe changed")
        text = text.replace(
            old, '("quotient_initialization_observed", Json.bool false)'
        ).replace(
            "rtk.lean_historical_replay_context.v1-development",
            "rtk.lean_historical_replay_context.v2-development",
        )
    if ".rtk-imported-build/" in text:
        raise ValueError("unsubstituted legacy path in patched driver")
    return text.encode()


def check_observation(raw: str, expected: str) -> None:
    marker = "RTK_HISTORICAL_TARGET_REPLAY_CONTEXT_JSON="
    lines = [x.partition(marker)[2] for x in raw.splitlines() if marker in x]
    if len(lines) != 1:
        raise ValueError("missing or duplicated patched oracle kernel context")
    state = json.loads(lines[0])
    if (
        not isinstance(state, dict)
        or set(state) != {
            "schema_version", "trust_level",
            "quotient_initialization_observed",
            "old_certificate_checked_in_this_process",
            "production_reliance_authorization",
        }
        or state.get("schema_version")
        != "rtk.lean_historical_replay_context.v2-development"
        or type(state.get("trust_level")) is not int
        or state["trust_level"] != 0
        or state.get("quotient_initialization_observed") is not False
        or state.get("old_certificate_checked_in_this_process") is not True
        or state.get("production_reliance_authorization") is not False
    ):
        raise ValueError("patched oracle did not report same-process trust zero")
    if expected not in {"ADMISSIBLE", "INADMISSIBLE"}:
        raise ValueError("unrecognized development verdict")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export")
    e.add_argument("--source-log", type=Path, required=True)
    e.add_argument("--source-file", type=Path, required=True)
    e.add_argument("--output", type=Path, required=True)
    t = sub.add_parser("target")
    t.add_argument("--source-payload", type=Path, required=True)
    t.add_argument("--target-log", type=Path, required=True)
    t.add_argument("--output", type=Path, required=True)
    d = sub.add_parser("driver")
    for key in ("encoder", "decoder", "template", "output"):
        d.add_argument("--" + key, type=Path, required=True)
    d.add_argument("--module", required=True)
    d.add_argument("--target-file", default=None)
    v = sub.add_parser("verify")
    for key in ("source-payload", "target-payload", "driver",
                "module-olean", "oracle-log", "output"):
        v.add_argument("--" + key, type=Path, required=True)
    v.add_argument("--expected", choices=("ADMISSIBLE", "INADMISSIBLE"), required=True)
    a = p.parse_args()
    if a.cmd == "export":
        _write(a.output, export_source(a.source_log.read_text(), a.source_file.read_bytes()))
        print("PATCHED_4_35_ORIGINAL_HISTORICAL_PROOF_SERIALIZED_NO_TARGET_REPLAY")
    elif a.cmd == "target":
        data = export_target_claim(
            source_payload_bytes=a.source_payload.read_bytes(),
            target_native_log=a.target_log.read_text(),
        )
        _write(a.output, _canonical(data) + b"\n")
        print("PATCHED_4_35_UNPROVED_TARGET_CLAIM_RECORDED")
    elif a.cmd == "driver":
        _write(a.output, make_driver(
            a.encoder.read_text(), a.decoder.read_text(),
            a.template.read_text(), module=a.module, target_filename=a.target_file,
        ))
        print("PATCHED_4_35_EXACT_SERIALIZED_EXPR_DRIVER_BUILT")
    else:
        log = a.oracle_log.read_text()
        check_observation(log, a.expected)
        result = verify_target_replay(
            source_payload_bytes=a.source_payload.read_bytes(),
            target_payload_bytes=a.target_payload.read_bytes(),
            driver_bytes=a.driver.read_bytes(),
            module_bytes=a.module_olean.read_bytes(),
            native_log=log, expected_decision=a.expected,
        )
        result.update({
            "patched_lean_version": VERSION,
            "legacy_lean_4_14_artifact_reused": False,
            "patched_kernel_security_qualified_for_relying_policy": False,
            "production_reliance_authorized": False,
            "semantic_transport_soundness_proved": False,
            "source_proof_rebuilt_under_patched_version": True,
            "same_process_target_trust_zero_observed": True,
            "patched_quotient_initialization_observed": False,
        })
        _write(a.output, json.dumps(result, sort_keys=True, indent=2).encode()+b"\n")
        print("PATCHED_4_35_EXACT_HISTORICAL_CERTIFICATE_" + a.expected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
