"""Shared FIRST_PARENT transition enumeration for expansion_v2 adapters.

This is new v2 machinery. It is not authentic generate_transition_census.py.
Transition identity uses the sealed v0 formula:
  sha256("rtk-transition-v0\\0{repository}\\0{source_sha}\\0{target_sha}").
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import Callable, Sequence

from ..adapter_contract import TransitionEnumerationRecord
from ..reason_codes import ExclusionReasonCode

EligibilityFn = Callable[
    [Path, str, str, tuple[str, ...]],
    tuple[str, str | None],
]


def _git(repo: Path, *args: str, check: bool = True) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"git -C {repo} {' '.join(args)} failed ({proc.returncode}): {proc.stderr}"
        )
    return proc.stdout


def transition_id(repository: str, source_sha: str, target_sha: str) -> str:
    material = "\x00".join(("rtk-transition-v0", repository, source_sha, target_sha))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def classify_changed_paths(paths: Sequence[str]) -> tuple[str, ...]:
    """Best-effort semantic path categories for census retention.

    Not contracted to sealed v0 category byte identity (generator unrecovered).
    """
    cats: set[str] = set()
    for path in paths:
        pl = path.lower()
        name = Path(path).name.lower()
        if pl.startswith(".github/") or "/workflows/" in pl:
            cats.add("ci")
        if pl.startswith("docs/") or name == "readme.md":
            cats.add("docs")
        if (
            "schema" in pl
            or pl.startswith("schemas/")
            or name.endswith(".schema.json")
        ):
            cats.add("schemas")
        if (
            "/tests/" in f"/{pl}"
            or pl.startswith("tests/")
            or name.startswith("test_")
            or name.endswith(".test.ts")
            or name.endswith("_test.py")
        ):
            cats.add("tests")
        if "release" in pl:
            cats.add("release")
        if name in {
            ".gitignore",
            ".editorconfig",
            "justfile",
            "makefile",
            "cargo.toml",
            "cargo.lock",
            "pyproject.toml",
            "package.json",
            "tsconfig.json",
            "pytest.ini",
            "version",
            "rust-toolchain.toml",
        } or name.endswith((".yml", ".yaml", ".toml")):
            cats.add("config")
        if pl.startswith(
            (
                "python/",
                "rust/",
                "typescript/",
                "services/",
                "cli/",
                "src/",
                "templates/",
                "app/",
            )
        ) or (
            name.endswith((".py", ".rs", ".ts", ".tsx", ".go", ".lean"))
            and "tests" not in cats
        ):
            cats.add("source")
        if pl.startswith(("examples/", "scripts/", "fixtures/", "benchmarks/")):
            cats.add("other")
        if not cats:
            cats.add("other")
    return tuple(sorted(cats))


def first_parent_shas(checkout: Path, cutoff_sha: str) -> list[str]:
    """Return FIRST_PARENT commits from root toward cutoff (inclusive)."""
    text = _git(
        checkout,
        "rev-list",
        "--reverse",
        "--first-parent",
        cutoff_sha,
    )
    shas = [line.strip() for line in text.splitlines() if line.strip()]
    if not shas:
        raise RuntimeError(f"no FIRST_PARENT history at {cutoff_sha} in {checkout}")
    if shas[-1] != cutoff_sha and not cutoff_sha.startswith(shas[-1][:12]):
        # Allow abbreviated match; resolve full sha
        full = _git(checkout, "rev-parse", cutoff_sha).strip()
        if shas[-1] != full:
            raise RuntimeError(
                f"cutoff {cutoff_sha} is not the tip of FIRST_PARENT rev-list "
                f"(got {shas[-1]})"
            )
        return shas
    return shas


def commit_timestamp(checkout: Path, sha: str) -> str:
    return _git(checkout, "show", "-s", "--format=%aI", sha).strip()


def changed_paths(checkout: Path, source_sha: str, target_sha: str) -> tuple[str, ...]:
    text = _git(checkout, "diff", "--name-only", source_sha, target_sha)
    paths = sorted({line.strip() for line in text.splitlines() if line.strip()})
    return tuple(paths)


def enumerate_first_parent_transitions(
    checkout: Path,
    *,
    repository: str,
    cutoff_sha: str,
    eligibility_for: EligibilityFn | None = None,
) -> list[TransitionEnumerationRecord]:
    """Enumerate complete FIRST_PARENT transitions up to cutoff.

    Root commit yields no transition. Default eligibility is ELIGIBLE for every
    parent→child edge (matching sealed v0 universe cardinality).
    """
    try:
        shas = first_parent_shas(checkout, cutoff_sha)
    except RuntimeError:
        return [
            TransitionEnumerationRecord(
                transition_id="operational-checkout-failure",
                repository=repository,
                source_sha="",
                target_sha=cutoff_sha,
                source_timestamp=None,
                target_timestamp=None,
                changed_paths=(),
                eligibility="EXCLUDED",
                exclusion_reason=ExclusionReasonCode.OPERATIONAL_CHECKOUT_FAILURE.value,
            )
        ]

    records: list[TransitionEnumerationRecord] = []
    for parent, child in zip(shas, shas[1:]):
        paths = changed_paths(checkout, parent, child)
        cats = classify_changed_paths(paths)
        if eligibility_for is None:
            eligibility = "ELIGIBLE"
            reason = None
        else:
            eligibility, reason = eligibility_for(checkout, parent, child, paths)
        records.append(
            TransitionEnumerationRecord(
                transition_id=transition_id(repository, parent, child),
                repository=repository,
                source_sha=parent,
                target_sha=child,
                source_timestamp=commit_timestamp(checkout, parent),
                target_timestamp=commit_timestamp(checkout, child),
                changed_paths=paths,
                eligibility=eligibility,
                exclusion_reason=reason,
                candidate_semantic_categories=cats,
            )
        )
    return records


def list_tree_paths(checkout: Path, revision: str, prefix: str = "") -> list[str]:
    args = ["ls-tree", "-r", "--name-only", revision]
    if prefix:
        args.extend(["--", prefix])
    text = _git(checkout, *args, check=False)
    return sorted(line.strip() for line in text.splitlines() if line.strip())


def show_file(checkout: Path, revision: str, path: str) -> bytes | None:
    proc = subprocess.run(
        ["git", "-C", str(checkout), "show", f"{revision}:{path}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
