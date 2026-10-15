"""Construct source-bound Action diff with a separate non-authoritative receipt.

For pull_request events the default checkout is a synthetic merge preview.
An observed base-to-merge diff must match the actual checked-out source.
Caller-provided inputs are explicitly unbound.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


class BindingError(ValueError):
    pass


def git(*args: str) -> bytes:
    result = subprocess.run(
        ["git", *args], capture_output=True, check=False,
    )
    if result.returncode != 0:
        raise BindingError(
            f"git {args[0]} failed ({result.returncode}): "
            f"{result.stderr.decode('utf-8', errors='replace')[:300]}"
        )
    return result.stdout


def sha(value: str, required: bool = False) -> str | None:
    if not value and not required:
        return None
    if not SHA.fullmatch(value):
        raise BindingError("missing or malformed full commit SHA")
    return value


def parents() -> list[str]:
    # Raw commit headers retain parents even on shallow GitHub checkouts.
    header = git("cat-file", "-p", "HEAD").split(b"\n\n", 1)[0]
    result = [
        line.split(b" ", 1)[1].decode("ascii")
        for line in header.splitlines() if line.startswith(b"parent ")
    ]
    if not all(SHA.fullmatch(item) for item in result):
        raise BindingError("malformed parent in checked-out commit")
    return result


def base_available(base: str) -> None:
    test = subprocess.run(
        ["git", "cat-file", "-e", f"{base}^{{commit}}"],
        capture_output=True, check=False,
    )
    if test.returncode != 0:
        git("fetch", "--no-tags", "--depth=1", "origin", base)
    git("cat-file", "-e", f"{base}^{{commit}}")


def prepare(
    *, event_name: str, github_sha: str, base_sha: str = "",
    pr_head_sha: str = "", changed_files: str = "", mode: str = "advisory",
) -> tuple[str, bytes, dict]:
    checkout = git("rev-parse", "HEAD").decode().strip()
    tree = git("rev-parse", "HEAD^{tree}").decode().strip()
    if not SHA.fullmatch(checkout) or not SHA.fullmatch(tree):
        raise BindingError("invalid checked-out Git object")
    if checkout != sha(github_sha, required=True):
        raise BindingError("checked-out commit differs from GITHUB_SHA")
    if event_name == "pull_request_target":
        raise BindingError("privileged pull_request_target is not admitted")
    base = None
    pr_head = None
    if event_name == "pull_request":
        base = sha(base_sha, required=True)
        pr_head = sha(pr_head_sha, required=True)
        if parents() != [base, pr_head]:
            raise BindingError("PR merge parents disagree with event base and head")
        base_available(base)
    elif base_sha or pr_head_sha:
        raise BindingError("PR identity parameters supplied for non-PR event")

    if changed_files:
        if mode == "strict":
            raise BindingError("caller-supplied diff cannot authorize strict review")
        path = Path(changed_files)
        if "\n" in changed_files or "\r" in changed_files or not path.is_file():
            raise BindingError("invalid or missing changed-files input")
        diff = path.read_bytes()
        input_path = str(path)
        comparison = "caller_supplied_unbound"
        bound = False
    elif event_name == "pull_request":
        diff = git("diff", "--no-ext-diff", "--binary", base, checkout)
        input_path = ".ovk-pr.diff"
        comparison = "event_base_to_verified_merge_preview"
        bound = True
    elif parents():
        diff = git("diff", "--no-ext-diff", "--binary", "HEAD^", "HEAD")
        input_path = ".ovk-pr.diff"
        comparison = "checked_out_first_parent_to_head"
        bound = True
    else:
        diff = git("show", "--format=", "--no-ext-diff", "--binary", "HEAD")
        input_path = ".ovk-pr.diff"
        comparison = "checked_out_root_commit"
        bound = True

    receipt = {
        "schema_version": "ovk.pr_source_input_binding.v1-development",
        "event_name": event_name,
        "event_base_sha": base,
        "event_pr_head_sha": pr_head,
        "evaluated_checkout_commit_sha": checkout,
        "evaluated_checkout_tree_sha": tree,
        "evidence_subject_sha": checkout,
        "input_comparison": comparison,
        "input_diff_sha256": hashlib.sha256(diff).hexdigest(),
        "input_structurally_bound_to_checkout": bound,
        "independent_event_authentication": False,
        "bound_into_signed_evidence_envelope": False,
        "production_reliance_authorized": False,
    }
    return input_path, diff, receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--github-sha", required=True)
    parser.add_argument("--base-sha", default="")
    parser.add_argument("--pr-head-sha", default="")
    parser.add_argument("--changed-files", default="")
    parser.add_argument("--mode", default="advisory", choices=("advisory", "strict"))
    parser.add_argument("--input-path-output", type=Path, default=Path(".ovk-effective-input-path"))
    parser.add_argument("--receipt-output", type=Path, default=Path("ovk-source-binding.json"))
    args = parser.parse_args(argv)
    try:
        # These files are generated observations, never reusable input evidence.
        # Clear earlier invocations before validating the current source identity.
        output_paths = (args.input_path_output, args.receipt_output)
        if output_paths[0].resolve() == output_paths[1].resolve():
            raise BindingError("handoff and receipt output paths must differ")
        if args.changed_files:
            input_path = Path(args.changed_files).resolve()
            if any(output.resolve() == input_path for output in output_paths):
                raise BindingError("changed-files input overlaps generated output")
        for output in output_paths:
            if output.is_dir() and not output.is_symlink():
                raise BindingError("generated output path is a directory")
            output.unlink(missing_ok=True)
        path, content, receipt = prepare(
            event_name=args.event_name, github_sha=args.github_sha,
            base_sha=args.base_sha, pr_head_sha=args.pr_head_sha,
            changed_files=args.changed_files, mode=args.mode,
        )
    except (BindingError, OSError, UnicodeError) as exc:
        print(f"OVK source binding rejected: {exc}", file=sys.stderr)
        return 2
    if path == ".ovk-pr.diff":
        Path(path).write_bytes(content)
    # The composite Action reads this file from Bash; a Windows CRLF suffix
    # would become part of the path after command substitution. Emit exact LF.
    args.input_path_output.write_bytes((path + "\n").encode("utf-8"))
    args.receipt_output.write_text(
        json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8",
    )
    print(f"OVK source input: {receipt['input_comparison']} [{receipt['input_diff_sha256']}]")
    if not receipt["input_structurally_bound_to_checkout"]:
        print("OVK warning: caller-supplied input is not bound to checked-out source")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
