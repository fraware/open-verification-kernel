"""Admit a *local observed* merge-preview subject for the OVK check CLI.

The Action's source-input preparer has already checked the current Git checkout
and generated a receipt. This module independently compares that receipt to
the current checkout, the current PR event, and exact diff bytes before the
event-derived PR-head value may be replaced as the evidence subject.

These are local structural checks, not authenticated GitHub provenance or
source-to-IR correctness. Never treat their success as a signed certificate.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any


SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
SCHEMA = "ovk.pr_source_input_binding.v1-development"
COMPARISON = "event_base_to_verified_merge_preview"


class SourceSubjectMismatch(ValueError):
    pass


def _read_object(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SourceSubjectMismatch(f"expected object in {path.name}")
    return data


def _sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or SHA.fullmatch(value) is None:
        raise SourceSubjectMismatch(f"missing or malformed {name}")
    return value


def _git_object(revspec: str) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", revspec],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SourceSubjectMismatch("unable to inspect checked-out Git source") from exc
    if result.returncode != 0:
        raise SourceSubjectMismatch("unable to inspect checked-out Git source")
    return _sha(result.stdout.strip(), "checked-out Git object")


def require_bound_merge_preview_subject(
    *, receipt_path: Path, diff_path: Path, event_path: Path,
    repo: str, head_sha: str, base_sha: str | None,
) -> None:
    """Fail closed unless all locally observed source identities agree."""
    receipt = _read_object(receipt_path)
    event = _read_object(event_path)
    if receipt.get("schema_version") != SCHEMA or receipt.get("event_name") != "pull_request":
        raise SourceSubjectMismatch("unsupported PR source observation contract")
    if receipt.get("input_comparison") != COMPARISON:
        raise SourceSubjectMismatch("input comparison is not bound to PR merge preview")
    if receipt.get("input_structurally_bound_to_checkout") is not True:
        raise SourceSubjectMismatch("change input was not structurally bound to checkout")
    for key in ("independent_event_authentication", "bound_into_signed_evidence_envelope",
                "production_reliance_authorized"):
        if receipt.get(key) is not False:
            raise SourceSubjectMismatch(f"unexpected reliance field: {key}")

    checkout = _sha(receipt.get("evaluated_checkout_commit_sha"), "checkout commit")
    tree = _sha(receipt.get("evaluated_checkout_tree_sha"), "checkout tree")
    subject = _sha(receipt.get("evidence_subject_sha"), "receipt evidence subject")
    event_base = _sha(receipt.get("event_base_sha"), "event base")
    event_head = _sha(receipt.get("event_pr_head_sha"), "event PR head")
    requested = _sha(head_sha, "explicit requested evidence subject")
    if subject != checkout or requested != checkout:
        raise SourceSubjectMismatch("explicit evidence subject is not checked-out merge preview")
    if _git_object("HEAD") != checkout or _git_object("HEAD^{tree}") != tree:
        raise SourceSubjectMismatch("checked-out Git object differs from source receipt")

    pr = event.get("pull_request")
    ev_repo = event.get("repository")
    if not isinstance(pr, dict) or not isinstance(ev_repo, dict):
        raise SourceSubjectMismatch("GitHub pull_request event identity is missing")
    ev_base, ev_head = pr.get("base"), pr.get("head")
    if not isinstance(ev_base, dict) or not isinstance(ev_head, dict):
        raise SourceSubjectMismatch("GitHub event PR parent objects are missing")
    if _sha(ev_base.get("sha"), "GitHub event base") != event_base:
        raise SourceSubjectMismatch("GitHub event base differs from source receipt")
    if _sha(ev_head.get("sha"), "GitHub event head") != event_head:
        raise SourceSubjectMismatch("GitHub event PR head differs from source receipt")
    if ev_repo.get("full_name") != repo:
        raise SourceSubjectMismatch("GitHub event repository differs from requested repository")
    if base_sha is not None and base_sha != event_base:
        raise SourceSubjectMismatch("caller base differs from checked PR base")

    digest = receipt.get("input_diff_sha256")
    if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
        raise SourceSubjectMismatch("missing or malformed exact diff digest")
    if hashlib.sha256(diff_path.read_bytes()).hexdigest() != digest:
        raise SourceSubjectMismatch("actual input diff bytes differ from source receipt")
