"""Render an advisory predecessor-bound guarantee review from existing OVK evidence.

This script does not extract source code, authenticate governing manifests, or
authorize historical reuse. Inputs must come from a trusted evidence collection
process and output must be evaluated by a human reviewer.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from ovk.core.guarantee_assurance_state import GuaranteeAssuranceSnapshot
from ovk.core.guarantee_continuity_review import build_guarantee_continuity_review
from ovk.core.guarantee_graph import GuaranteeSpec
from ovk.core.models import VerificationEvidence


def main(argv: Sequence[str] | None = None) -> int:
    """Read six model artifacts plus verification key and write two reports."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-snapshot", required=True, type=Path)
    parser.add_argument("--target-snapshot", required=True, type=Path)
    parser.add_argument("--source-spec", required=True, type=Path)
    parser.add_argument("--target-spec", required=True, type=Path)
    parser.add_argument("--source-evidence", required=True, type=Path)
    parser.add_argument("--target-evidence", required=True, type=Path)
    parser.add_argument("--signature-key-file", required=True, type=Path)
    parser.add_argument("--guarantee-id", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)

    # Inputs are untrusted records until the existing gate validates their
    # exact envelopes. A valid signature alone is not governance authority.
    source = GuaranteeAssuranceSnapshot.model_validate_json(
        args.source_snapshot.read_text(encoding="utf-8")
    )
    target = GuaranteeAssuranceSnapshot.model_validate_json(
        args.target_snapshot.read_text(encoding="utf-8")
    )
    source_spec = GuaranteeSpec.model_validate_json(
        args.source_spec.read_text(encoding="utf-8")
    )
    target_spec = GuaranteeSpec.model_validate_json(
        args.target_spec.read_text(encoding="utf-8")
    )
    source_evidence = VerificationEvidence.model_validate_json(
        args.source_evidence.read_text(encoding="utf-8")
    )
    target_evidence = VerificationEvidence.model_validate_json(
        args.target_evidence.read_text(encoding="utf-8")
    )
    signature_key = args.signature_key_file.read_bytes()
    if not signature_key:
        parser.error("signature key file must not be empty")

    report = build_guarantee_continuity_review(
        source,
        target,
        guarantee_id=args.guarantee_id,
        source_spec=source_spec,
        target_spec=target_spec,
        source_evidence=source_evidence,
        target_evidence=target_evidence,
        signature_key=signature_key,
    )

    # Refuse to overwrite an earlier audit record or follow an existing
    # output-directory symlink. Never write or print the signing key.
    args.output_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
    (args.output_dir / "continuity-review.json").write_text(
        report.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "continuity-review.md").write_text(
        report.to_markdown(), encoding="utf-8"
    )
    print(f"Non-controlling review saved to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
