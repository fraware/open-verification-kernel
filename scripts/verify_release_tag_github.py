#!/usr/bin/env python
"""Verify that a release tag is signed, immutable, and bound to one candidate SHA."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Any, Mapping
from urllib.parse import quote


def _gh_json(endpoint: str) -> Mapping[str, Any]:
    try:
        completed = subprocess.run(
            ["gh", "api", endpoint],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"gh api execution failed: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "gh api failed"
        raise RuntimeError(detail)
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("gh api returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("gh api returned a non-object payload")
    return payload


def validate_signed_tag(
    *,
    ref_payload: Mapping[str, Any],
    tag_payload: Mapping[str, Any],
    expected_tag: str,
    expected_candidate_sha: str,
) -> list[str]:
    """Validate GitHub ref + annotated-tag objects without trusting release metadata."""
    failures: list[str] = []
    expected_candidate_sha = expected_candidate_sha.lower()
    if len(expected_candidate_sha) != 40 or any(
        char not in "0123456789abcdef" for char in expected_candidate_sha
    ):
        failures.append("expected_candidate_sha must be 40-hex")
        return failures

    ref_object = ref_payload.get("object")
    if not isinstance(ref_object, Mapping):
        failures.append("tag ref missing object")
        return failures
    if ref_object.get("type") != "tag":
        failures.append("release tag must be an annotated signed tag, not a lightweight tag")

    if str(tag_payload.get("tag") or "") != expected_tag:
        failures.append("annotated tag name mismatch")

    target = tag_payload.get("object")
    if not isinstance(target, Mapping):
        failures.append("annotated tag missing target object")
    else:
        if target.get("type") != "commit":
            failures.append("annotated tag must point directly to a commit")
        if str(target.get("sha") or "").lower() != expected_candidate_sha:
            failures.append("annotated tag target does not match candidate SHA")

    verification = tag_payload.get("verification")
    if not isinstance(verification, Mapping) or verification.get("verified") is not True:
        failures.append("annotated tag signature is not verified by GitHub")

    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify signed release tag provenance")
    parser.add_argument("--repo", required=True, help="Repository in owner/name form")
    parser.add_argument("--tag", required=True)
    parser.add_argument("--expected-candidate-sha", required=True)
    args = parser.parse_args(argv)

    if "/" not in args.repo:
        parser.error("--repo must be owner/name")

    encoded_tag = quote(args.tag, safe="")
    try:
        ref_payload = _gh_json(f"repos/{args.repo}/git/ref/tags/{encoded_tag}")
        ref_object = ref_payload.get("object")
        if not isinstance(ref_object, Mapping) or ref_object.get("type") != "tag":
            tag_payload: Mapping[str, Any] = {}
        else:
            tag_object_sha = str(ref_object.get("sha") or "")
            tag_payload = _gh_json(f"repos/{args.repo}/git/tags/{tag_object_sha}")
    except RuntimeError as exc:
        print(f"release_tag_lookup_failed:{exc}", file=sys.stderr)
        return 1

    failures = validate_signed_tag(
        ref_payload=ref_payload,
        tag_payload=tag_payload,
        expected_tag=args.tag,
        expected_candidate_sha=args.expected_candidate_sha,
    )
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        return 1
    print(
        f"signed release tag verified: {args.tag} -> "
        f"{args.expected_candidate_sha.lower()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
