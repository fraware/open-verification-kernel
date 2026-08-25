#!/usr/bin/env python
"""Forbid floating third-party action tags in OVK Action and release paths.

Release paths (OVK-PR6 / OVK-07):
  - action.yml
  - .github/workflows/publish.yml

A ``uses:`` reference is considered pinned when the ref is a full 40-character
lowercase hex commit SHA. Floating tags (``v4``, ``main``, ``release/v1``) fail.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DEFAULT_PATHS = (
    ROOT / "action.yml",
    ROOT / ".github" / "workflows" / "publish.yml",
)

USES_RE = re.compile(
    r"""^\s*(?:-\s*)?uses:\s*['"]?(?P<action>[^'"\s#]+)['"]?\s*(?:#.*)?$""",
    re.MULTILINE,
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
# Local composite / reusable refs are allowed without SHA pins.
LOCAL_PREFIXES = ("./", "../")


def iter_uses(text: str) -> list[str]:
    return [match.group("action") for match in USES_RE.finditer(text)]


def is_local_action(ref: str) -> bool:
    return ref.startswith(LOCAL_PREFIXES) or ref.startswith("docker://")


def is_sha_pinned(ref: str) -> bool:
    if "@" not in ref:
        return False
    _owner_name, pin = ref.rsplit("@", 1)
    return bool(SHA_RE.fullmatch(pin.lower()))


def floating_uses_in_file(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    floating: list[str] = []
    for ref in iter_uses(text):
        if is_local_action(ref):
            continue
        if not is_sha_pinned(ref):
            floating.append(ref)
    return floating


def check_paths(paths: list[Path]) -> list[str]:
    failures: list[str] = []
    for path in paths:
        if not path.exists():
            failures.append(f"missing release path: {path}")
            continue
        for ref in floating_uses_in_file(path):
            failures.append(f"{path.as_posix()}: floating action ref {ref!r} (pin to 40-char commit SHA)")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Require immutable commit SHA pins for third-party actions in Action/release paths"
    )
    parser.add_argument(
        "--path",
        action="append",
        dest="paths",
        type=Path,
        help="YAML path to check (repeatable). Defaults to action.yml and publish.yml.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=ROOT,
        help="Repository root used to resolve relative --path values",
    )
    args = parser.parse_args(argv)
    root = args.repo_root.resolve()
    paths = [p if p.is_absolute() else root / p for p in (args.paths or list(DEFAULT_PATHS))]
    # Normalize DEFAULT_PATHS when --path not given (already absolute).
    if not args.paths:
        paths = list(DEFAULT_PATHS)

    failures = check_paths(paths)
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        print(
            f"pin_action_shas: {len(failures)} floating/unpinned third-party action(s)",
            file=sys.stderr,
        )
        return 1
    print(f"pin_action_shas: ok ({len(paths)} release path(s) SHA-pinned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
