"""Source-only Lean theorem census for one pinned first-parent transition.

This is a non-oracle discovery stage. It inspects the predecessor's .lean file
bytes and a Git metadata list of changed paths, NEVER target file contents,
target native verifier output, or an RTK prediction. All discovered cases are
PRELIMINARY and require source-native acceptance before cohort qualification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

_SHA40 = re.compile("^[0-9a-f]{40}$")
_REPO = re.compile("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_THEOREM = re.compile("(?m)^theorem ([A-Za-z_][A-Za-z0-9_.']*)")
_DISALLOWED = re.compile(
    "(?<![A-Za-z0-9_])(sorry|admit|axiom|unsafe|import)(?![A-Za-z0-9_])"
)


def _git(repo: Path, *args: str, timeout: int = 25) -> str:
    try:
        run = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=timeout,
            check=False,
        )
    except (OSError, UnicodeError, subprocess.SubprocessError) as error:
        raise ValueError("source Git operation unavailable") from error
    if run.returncode != 0:
        raise ValueError("source Git metadata or object unavailable: " + args[0])
    return run.stdout


def _git_blob(repo: Path, source_sha: str, path: str) -> bytes:
    """Fetch exact historical blob bytes without text-mode newline conversion."""
    try:
        run = subprocess.run(
            ["git", "-C", str(repo), "show", f"{source_sha}:{path}"],
            capture_output=True,
            timeout=25,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("source Git blob unavailable") from error
    if run.returncode != 0 or len(run.stdout) > 65536:
        raise ValueError("source Git blob missing or oversize")
    return run.stdout


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _source_theorems(source: str) -> list[tuple[str, bytes]]:
    """Conservative, order-preserving extractor for development qualification."""
    if _DISALLOWED.search(source):
        return []
    matches = list(_THEOREM.finditer(source))
    result: list[tuple[str, bytes]] = []
    for match in matches:
        cutoff = source.find("\n\n", match.start())
        if cutoff < 0:
            continue
        text = source[match.start():cutoff]
        if ":= by\n" not in text:
            continue
        if len(text.encode("utf-8")) > 4096 or "\n" not in text:
            continue
        result.append((match.group(1), text.encode("utf-8")))
    # Ambiguous repeated names are ineligible, including shadowed declarations.
    names = [name for name, _ in result]
    if len(set(names)) != len(names):
        return []
    return result


def source_only_transition_census(
    *, repo_path: Path, repository: str,
    source_sha: str, target_sha: str, max_cases: int = 32,
) -> dict[str, Any]:
    if not _REPO.fullmatch(repository):
        raise ValueError("invalid repository identity")
    if not _SHA40.fullmatch(source_sha) or not _SHA40.fullmatch(target_sha):
        raise ValueError("source and target must be exact Git commit SHAs")
    if max_cases < 1 or max_cases > 100:
        raise ValueError("max_cases must be 1..100")
    if _git(repo_path, "rev-parse", "--verify", f"{source_sha}^{{commit}}").strip() != source_sha:
        raise ValueError("source commit identity mismatch")
    if _git(repo_path, "rev-parse", "--verify", f"{target_sha}^{{commit}}").strip() != target_sha:
        raise ValueError("target commit identity mismatch")
    if _git(repo_path, "rev-parse", f"{target_sha}^").strip() != source_sha:
        raise ValueError("source is not immediate first parent of target")

    changed_paths = _git(
        repo_path, "diff", "--name-only", "--diff-filter=M",
        source_sha, target_sha, "--", "*.lean",
    ).splitlines()
    candidates: list[dict[str, Any]] = []
    exclusions: list[dict[str, str]] = []
    for path in sorted(set(changed_paths)):
        pieces = path.split("/")
        if (
            not path.endswith(".lean")
            or any(part in ("", ".", "..") for part in pieces)
            or chr(92) in path
        ):
            exclusions.append({"path": path, "reason": "invalid_path"})
            continue
        try:
            source_bytes = _git_blob(repo_path, source_sha, path)
            source = source_bytes.decode("utf-8")
        except (ValueError, UnicodeError):
            exclusions.append({"path": path, "reason": "source_file_unavailable"})
            continue
        if not source_bytes:
            exclusions.append({"path": path, "reason": "source_size_unsupported"})
            continue
        proofs = _source_theorems(source)
        if not proofs:
            exclusions.append({
                "path": path,
                "reason": "no_unambiguous_supported_source_theorem",
            })
            continue
        for theorem, proof in proofs:
            candidates.append({
                "path": path,
                "theorem_name": theorem,
                "source_file_sha256": _sha256(source_bytes),
                "historical_proof_source_sha256": _sha256(proof),
                "source_native_acceptance": "NOT_EXECUTED",
                "target_claim": "NOT_INSPECTED",
                "target_native_oracle": "NOT_EXECUTED",
                "status": "PRELIMINARY_SOURCE_SHAPE_ONLY",
            })
    # Source-native acceptance is a separate qualification requirement; no
    # quota should be silently satisfied by these lexical candidates.
    return {
        "schema_version": "rtk.lean_v2.source_census.preoracle.v1",
        "repository": repository,
        "source_sha": source_sha,
        "target_sha": target_sha,
        "examined_changed_paths": len(changed_paths),
        "candidates": candidates[:max_cases],
        "candidate_truncation": len(candidates) > max_cases,
        "exclusions": exclusions,
        "target_file_bytes_read_by_adapter": False,
        "source_native_checks_executed": False,
        "oracle_checks_executed": False,
        "sut_predictions_executed": False,
        "case_qualification_complete": False,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo-path", type=Path, required=True)
    p.add_argument("--repository", required=True)
    p.add_argument("--source", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    record = source_only_transition_census(
        repo_path=args.repo_path,
        repository=args.repository,
        source_sha=args.source,
        target_sha=args.target,
    )
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(record, output, sort_keys=True, indent=2)
        output.write("\n")
    print("SOURCE_ONLY_PREQUALIFICATION_NO_TARGET_ORACLE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
