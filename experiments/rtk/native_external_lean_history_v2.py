"""Development-only native replay of an *actual external Git history*.

Source/target are exact pinned upstream Git objects. The selected source proof
script is replayed unchanged in a different, historical target file revision.
This is an observational positive control, NOT a confirmatory RTK evaluation
and not a claim of serialized Lean kernel-certificate portability.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from experiments.rtk.native_lean_replay_v2 import _invoke

UPSTREAM = "leanprover/lean4"
SOURCE_COMMIT = "410fab7284703f41660ca2454218dcca9b2ec896"
TARGET_COMMIT = "11651562caae0a0b3973811508db2ab8903d3854"
SOURCE_GIT_BLOB = "c6c3cd21a7ef1e1ae0b5bff7625e941cb93379e9"
TARGET_GIT_BLOB = "2b8252f7442fcd860a860a8241752e107096ab01"
REPO_PATH = "doc/examples/tc.lean"
THEOREM_NAME = "HasType.det"
# Closed-world extraction for this named, known example. The theorem ends at
# the immediately following blank line, not at an arbitrary secondary match.
_START = re.compile("(?m)^theorem HasType[.]det(?![A-Za-z0-9_])")
_VERSION = re.compile("Lean [(]version 4[.]14[.]0(?:,|[)])")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError("external Git provenance command failed: " + " ".join(args))
    return completed.stdout.strip()


def _read_exact(repo: Path, expected_commit: str, expected_blob: str) -> bytes:
    if _git(repo, "rev-parse", "HEAD") != expected_commit:
        raise ValueError("wrong external Git revision")
    path = repo / REPO_PATH
    if not path.is_file() or path.is_symlink():
        raise ValueError("external historical source file unavailable")
    if _git(repo, "hash-object", REPO_PATH) != expected_blob:
        raise ValueError("historical file blob identity mismatch")
    raw = path.read_bytes()
    if not raw or len(raw) > 16384 or bytes([0]) in raw:
        raise ValueError("external historical Lean file invalid or too large")
    return raw


def _theorem_bytes(content: bytes) -> bytes:
    """Extract the exact source-native declaration/proof bytes, without edits."""
    text = content.decode("utf-8")
    starts = list(_START.finditer(text))
    if len(starts) != 1:
        raise ValueError("historical theorem identity absent or ambiguous")
    start = starts[0].start()
    next_blank = text.find("\n\n", start)
    if next_blank < 0:
        raise ValueError("theorem ending not found")
    excerpt = text[start:next_blank].encode("utf-8")
    if b":= by\n" not in excerpt:
        raise ValueError("extracted theorem missing tactic proof")
    if b"\n" not in excerpt or len(excerpt) > 1024:
        raise ValueError("extracted theorem shape not supported")
    return excerpt


def replay_external_history(
    *,
    lean: Path,
    source_checkout: Path,
    target_checkout: Path,
    timeout: int = 40,
) -> dict[str, Any]:
    """Check exact preselected upstream commits; do not inspect SUT outputs."""

    source = _read_exact(source_checkout, SOURCE_COMMIT, SOURCE_GIT_BLOB)
    target = _read_exact(target_checkout, TARGET_COMMIT, TARGET_GIT_BLOB)
    historical_term = _theorem_bytes(source)
    target_term = _theorem_bytes(target)

    record: dict[str, Any] = {
        "schema_version": "rtk.external_lean_history.v2-development",
        "upstream": UPSTREAM,
        "path": REPO_PATH,
        "theorem_name": THEOREM_NAME,
        "source_commit": SOURCE_COMMIT,
        "target_commit": TARGET_COMMIT,
        "source_blob": SOURCE_GIT_BLOB,
        "target_blob": TARGET_GIT_BLOB,
        "source_sha256": _sha256(source),
        "target_sha256": _sha256(target),
        "historical_theorem_sha256": _sha256(historical_term),
        "target_theorem_sha256": _sha256(target_term),
        "historical_theorem_identical": historical_term == target_term,
        "file_content_changed": source != target,
        "source_native_acceptance": "UNKNOWN",
        "target_native_acceptance": "UNKNOWN",
        "historical_evidence_applicability": "UNDETERMINED",
        "target_claim_status": "UNKNOWN",
        "witness_basis": None,
        "runs": {},
    }
    if historical_term != target_term:
        record["unresolved_reason"] = "historical_theorem_proof_bytes_changed"
        return record
    if source == target:
        record["unresolved_reason"] = "repository_files_not_changed"
        return record

    # Reject an unverified checker version; path and commit identities above
    # refer to upstream source history, not trusted native executable bytes.
    checker = _invoke(lean, ["--version"], cwd=source_checkout, timeout=timeout)
    record["runs"]["version"] = checker
    if checker["status"] != "ACCEPTED" or not _VERSION.search(checker["diagnostic"]):
        record["unresolved_reason"] = "native_checker_unavailable_or_wrong_version"
        return record

    source_run = _invoke(
        lean,
        [str((source_checkout / REPO_PATH).resolve())],
        cwd=source_checkout,
        timeout=timeout,
    )
    record["runs"]["source"] = source_run
    record["source_native_acceptance"] = source_run["status"]
    if source_run["status"] != "ACCEPTED":
        record["unresolved_reason"] = "historical_source_not_native_accepted"
        return record

    target_run = _invoke(
        lean,
        [str((target_checkout / REPO_PATH).resolve())],
        cwd=target_checkout,
        timeout=timeout,
    )
    record["runs"]["target"] = target_run
    record["target_native_acceptance"] = target_run["status"]
    if target_run["status"] == "ACCEPTED":
        record["historical_evidence_applicability"] = "ADMISSIBLE"
        record["target_claim_status"] = "ESTABLISHED"
        record["witness_basis"] = "UNCHANGED_UPSTREAM_THEOREM_NATIVE_RECHECK"
    else:
        # Full-file native rejection cannot safely be attributed to this
        # particular historical theorem without a separate scoped witness.
        record["unresolved_reason"] = "target_file_native_check_inconclusive"
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lean", type=Path, required=True)
    parser.add_argument("--source-checkout", type=Path, required=True)
    parser.add_argument("--target-checkout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    result = replay_external_history(
        lean=args.lean.resolve(),
        source_checkout=args.source_checkout.resolve(),
        target_checkout=args.target_checkout.resolve(),
    )
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps({
        "historical_evidence_applicability":
            result["historical_evidence_applicability"],
        "source_native_acceptance": result["source_native_acceptance"],
        "target_native_acceptance": result["target_native_acceptance"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
