"""Narrow native Lean proof-term replay pilot for prospective RTK development.

This verifies an *unchanged historical proof-term source* using a pinned Lean 4
kernel against source and target declarations. It is not an independent verifier
of arbitrary software, a general proof-object transporter, or an RTK scorer.

The checker executable is externally supplied. Version checking does NOT
authenticate binary bytes; runner/archive provenance is a separate obligation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

EXPECTED_LEAN_VERSION = "4.14.0"
_VERSION = re.compile("Lean [(]version 4[.]14[.]0(?:,|[)])")
# These are deliberately conservative, not a complete Lean security sandbox.
_PROHIBITED = re.compile("(?<![A-Za-z0-9_])(sorry|admit|axiom|unsafe)(?![A-Za-z0-9_])")
_TYPE_MISMATCH = re.compile(r"(?i)(type mismatch|application type mismatch)")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    if not data or len(data) > 32768 or b"\\x00" in data:
        raise ValueError("invalid or oversize Lean pilot input")
    return data


def _lean_environment() -> dict[str, str]:
    # Explicitly suppress ambient LEAN_PATH and arbitrary user flags.
    result = {key: os.environ[key] for key in ("PATH", "HOME", "ELAN_HOME")
              if key in os.environ}
    result["ELAN_TOOLCHAIN"] = "leanprover/lean4:v4.14.0"
    return result


def _invoke(lean: Path, args: list[str], *, cwd: Path, timeout: int) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [str(lean), *args],
            cwd=cwd,
            env=_lean_environment(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "status": "OPERATIONAL_FAILURE",
            "exit_code": None,
            "stdout_sha256": None,
            "stderr_sha256": None,
            "diagnostic": type(exc).__name__,
        }
    return {
        "status": "ACCEPTED" if result.returncode == 0 else "CHECKER_REJECTED",
        "exit_code": result.returncode,
        "stdout_sha256": _sha256(result.stdout.encode()),
        "stderr_sha256": _sha256(result.stderr.encode()),
        "diagnostic": (result.stdout + "\n" + result.stderr)[-4096:],
    }


def replay_proof_term(
    *,
    lean: Path,
    source_declaration: Path,
    target_declaration: Path,
    historical_proof: Path,
    fresh_target_proof: Path | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """Replay EXACT proof bytes; keep source, target and fresh checks separate.

    The example's statements are self-contained, with no Lean imports or sorry.
    Inadmissibility is reported only on source acceptance and an independently
    inspected type-mismatch rejection under the same pinned checker. All other
    failed checker runs produce UNDETERMINED.
    """

    source = _file_bytes(source_declaration)
    target = _file_bytes(target_declaration)
    old = _file_bytes(historical_proof)
    fresh = _file_bytes(fresh_target_proof) if fresh_target_proof else None

    for role, payload in (("source declaration", source),
                          ("target declaration", target),
                          ("historical proof", old),
                          ("fresh proof", fresh)):
        if payload is not None and _PROHIBITED.search(payload.decode("utf-8")):
            raise ValueError(f"prohibited unsupported construct: {role}")
    # Exact native certificate SOURCE bytes and target statements are retained
    # separately. The only synthesis is declaration + unchanged term source.
    if not source.endswith(b"\n") or not target.endswith(b"\n"):
        raise ValueError("declarations must end in a newline")
    if not old.endswith(b"\n"):
        raise ValueError("historical proof term must end in a newline")

    result: dict[str, Any] = {
        "schema_version": "rtk.native_lean_term_replay.v2-development",
        "checker_family": "Lean4",
        "expected_checker_version": EXPECTED_LEAN_VERSION,
        "source_declaration_sha256": _sha256(source),
        "target_declaration_sha256": _sha256(target),
        "historical_proof_sha256": _sha256(old),
        "fresh_target_proof_sha256": _sha256(fresh) if fresh else None,
        "historical_evidence_applicability": "UNDETERMINED",
        "target_claim_status": "UNKNOWN",
        "source_native_acceptance": "UNKNOWN",
        "target_historical_replay": "NOT_RUN",
        "fresh_target_execution": "NOT_RUN",
        "witness_basis": None,
        "runs": {},
    }

    with tempfile.TemporaryDirectory(prefix="rtk-lean-proofterm-") as temp:
        base = Path(temp)
        version = _invoke(lean, ["--version"], cwd=base, timeout=timeout)
        result["runs"]["version"] = version
        if version["status"] != "ACCEPTED" or not _VERSION.search(
            version["diagnostic"]
        ):
            result["operational_reason"] = "checker_missing_or_wrong_version"
            return result

        source_file = base / "source.lean"
        target_file = base / "target.lean"
        source_bytes = source + old
        target_bytes = target + old
        source_file.write_bytes(source_bytes)
        target_file.write_bytes(target_bytes)
        result["source_checked_bytes_sha256"] = _sha256(source_bytes)
        result["target_replay_bytes_sha256"] = _sha256(target_bytes)
        source_run = _invoke(lean, [str(source_file)], cwd=base, timeout=timeout)
        result["runs"]["source"] = source_run
        result["source_native_acceptance"] = source_run["status"]
        if source_run["status"] != "ACCEPTED":
            result["operational_reason"] = "source_evidence_not_native_accepted"
            return result

        target_run = _invoke(lean, [str(target_file)], cwd=base, timeout=timeout)
        result["runs"]["historical_target_replay"] = target_run
        result["target_historical_replay"] = target_run["status"]
        if target_run["status"] == "ACCEPTED":
            result["historical_evidence_applicability"] = "ADMISSIBLE"
            result["witness_basis"] = "EXACT_PROOF_TERM_SOURCE_REPLAY"
        elif (
            target_run["status"] == "CHECKER_REJECTED"
            and _TYPE_MISMATCH.search(target_run["diagnostic"])
        ):
            # Relative to the pinned Lean elaborator/kernel and this closed
            # fixture. Never generalize checker failure to target falsity.
            result["historical_evidence_applicability"] = "INADMISSIBLE"
            result["witness_basis"] = "NATIVE_PROOF_TERM_TYPE_MISMATCH"
        else:
            result["operational_reason"] = "historical_replay_inconclusive"

        if fresh is not None:
            fresh_file = base / "fresh_target.lean"
            fresh_bytes = target + fresh
            fresh_file.write_bytes(fresh_bytes)
            result["fresh_checked_bytes_sha256"] = _sha256(fresh_bytes)
            fresh_run = _invoke(
                lean, [str(fresh_file)], cwd=base, timeout=timeout
            )
            result["runs"]["fresh_target"] = fresh_run
            result["fresh_target_execution"] = fresh_run["status"]
            if fresh_run["status"] == "ACCEPTED":
                result["target_claim_status"] = "ESTABLISHED"
            # A failed proof attempt is not an authoritative refutation.
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lean", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--fresh", type=Path, default=None)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 120:
        parser.error("timeout must be 1..120 seconds")
    result = replay_proof_term(
        lean=args.lean,
        source_declaration=args.source,
        target_declaration=args.target,
        historical_proof=args.evidence,
        fresh_target_proof=args.fresh,
        timeout=args.timeout,
    )
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps({
        "source": result["source_native_acceptance"],
        "replay": result["historical_evidence_applicability"],
        "target_truth": result["target_claim_status"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
