#!/usr/bin/env python3
"""Render a read-only GitHub job summary from source-scoped OVK PR observations.

This renderer validates *structural agreement of local observations* only.
It cannot authenticate GitHub events, sign evidence, prove source-to-model
correspondence, or authorize relying on the observed checker decision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


SHA40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST64 = re.compile(r"^[0-9a-f]{64}$")
DECISIONS = frozenset({"allow", "block", "needs_review", "unknown", "error", "skipped"})
COMPARISON = "event_base_to_verified_merge_preview"
SCHEMA = "ovk.pr_source_input_binding.v1-development"


class ObservationError(ValueError):
    """An observed input identity cannot justify this informational summary."""


def _json_object(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ObservationError(f"expected JSON object: {path.name}")
    return payload, raw


def build_summary(evidence: dict[str, Any], receipt: dict[str, Any], evidence_bytes: bytes) -> str:
    """Build a non-authoritative advisory report, rejecting unbound or stale input."""
    if receipt.get("schema_version") != SCHEMA:
        raise ObservationError("unknown source observation contract")
    if receipt.get("event_name") != "pull_request":
        raise ObservationError("this summary is for GitHub PR merge previews only")
    if receipt.get("input_comparison") != COMPARISON:
        raise ObservationError("unrecognized or caller-selected input comparison")
    if receipt.get("input_structurally_bound_to_checkout") is not True:
        raise ObservationError("input was not structurally bound to the checkout")
    if receipt.get("independent_event_authentication") is not False:
        raise ObservationError("unexpected event-authentication status")
    if receipt.get("bound_into_signed_evidence_envelope") is not False:
        raise ObservationError("unexpected signed-envelope status")
    if receipt.get("production_reliance_authorized") is not False:
        raise ObservationError("unexpected reliance status")

    checkout = receipt.get("evaluated_checkout_commit_sha")
    subject = receipt.get("evidence_subject_sha")
    head = receipt.get("event_pr_head_sha")
    base = receipt.get("event_base_sha")
    diff_hash = receipt.get("input_diff_sha256")
    fields = {"checkout": checkout, "subject": subject, "head": head, "base": base}
    if any(not isinstance(v, str) or SHA40.fullmatch(v) is None for v in fields.values()):
        raise ObservationError("missing or malformed source revision")
    if not isinstance(diff_hash, str) or DIGEST64.fullmatch(diff_hash) is None:
        raise ObservationError("missing or malformed diff digest")
    if checkout != subject:
        raise ObservationError("receipt subject does not match evaluated checkout")
    evidence_subject = evidence.get("subject")
    if not isinstance(evidence_subject, dict) or evidence_subject.get("head_sha") != subject:
        raise ObservationError("evidence subject disagrees with the observed checkout")

    decision = evidence.get("decision")
    if not isinstance(decision, dict):
        raise ObservationError("missing evidence decision")
    state = decision.get("decision_state")
    if state is None:
        aliases = {
            "allow": "allow",
            "block": "block",
            "require_human_review": "needs_review",
            "needs_review": "needs_review",
            "unknown": "unknown",
            "error": "error",
            "skipped": "skipped",
        }
        state = aliases.get(decision.get("merge_recommendation"), "unknown")
    if state not in DECISIONS:
        raise ObservationError("unknown evidence decision state")

    evidence_hash = hashlib.sha256(evidence_bytes).hexdigest()
    return (
        "## Open Verification Kernel — advisory PR observation\n\n"
        f"**Recorded scoped decision:** \`{state}\` (advisory; human review controls the PR).\n\n"
        "| Observation | Exact value |\n"
        "| --- | --- |\n"
        f"| Evaluated GitHub merge-preview commit | \`{checkout}\` |\n"
        f"| Original contributor PR head | \`{head}\` |\n"
        f"| Event base revision | \`{base}\` |\n"
        f"| Observed binary diff SHA-256 | \`{diff_hash}\` |\n"
        f"| Local evidence file SHA-256 | \`{evidence_hash}\` |\n\n"
        "**Interpretation:** This is an observation about a configured, bounded checker on "
        "a GitHub merge-preview diff. The source relation was checked structurally in "
        "the runner; neither the event nor the evidence is independently authenticated. "
        "The diff receipt is not signed into the evidence envelope, and the result "
        "does not establish whole-PR correctness, supported-source completeness, "
        "or production relying authority. An \`allow\` is not permission to merge.\n\n"
        "**Review next:** inspect \`ovk-evidence.json\`, \`ovk-evidence-quality.json\`, "
        "and \`ovk-source-binding.json\` in this job's uploaded OVK artifact. "
        "Carry exact source identities and assumptions into any further review.\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, default=Path("ovk-evidence.json"))
    parser.add_argument("--source-binding", type=Path, default=Path("ovk-source-binding.json"))
    parser.add_argument(
        "--output", type=Path,
        default=Path(os.environ["GITHUB_STEP_SUMMARY"]) if os.environ.get("GITHUB_STEP_SUMMARY") else None,
        help="GitHub job summary path or another explicit Markdown file",
    )
    args = parser.parse_args(argv)
    if args.output is None:
        print("no summary output path", file=sys.stderr)
        return 2
    try:
        evidence, evidence_bytes = _json_object(args.evidence)
        receipt, _ = _json_object(args.source_binding)
        summary = build_summary(evidence, receipt, evidence_bytes)
        # The host owns GITHUB_STEP_SUMMARY; append so this Action composes
        # with earlier steps and multiple invocations without clobbering them.
        with args.output.open("a", encoding="utf-8", newline="\n") as output:
            output.write(summary)
            output.write("\n")
    except (ObservationError, OSError, ValueError, TypeError) as exc:
        print(f"OVK refusing unsupported job summary: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
