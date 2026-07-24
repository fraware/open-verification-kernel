"""Digest and validate label-free holdout predictions (Sprint 8).

Predictions are produced from the RC artifact without protected labels, then
digested (and optionally signed) before a separate evaluator consumes them.

Case ids may appear in predictions (needed for scoring). Protected *labels* /
ground-truth fields must not.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

_LABEL_FORBIDDEN_SUBSTRINGS = (
    "expected_status",
    "expected_merge_recommendation",
    "ground_truth_class",
    "true_positive_unsafe",
    "true_negative_safe",
    "corpus/labels",
    "labels_dir",
    "ground_truth",
    "expected_outcome",
)

_TOP_LEVEL_FORBIDDEN = frozenset(
    {
        "labels",
        "expected_status",
        "ground_truth_class",
        "corpus_labels",
        "expected_merge_recommendation",
    }
)

_CASE_FORBIDDEN = frozenset(
    {
        "expected_status",
        "ground_truth_class",
        "label",
        "labels",
        "expected_merge_recommendation",
    }
)


def _fail(msg: str) -> None:
    raise SystemExit(f"fail-closed: {msg}")


def assert_predictions_label_free(payload: Any) -> None:
    """Refuse predictions that embed protected labels or case-ground-truth fields."""
    text = json.dumps(payload, sort_keys=True)
    for token in _LABEL_FORBIDDEN_SUBSTRINGS:
        if token in text:
            _fail(f"predictions contain protected token {token!r}")
    if isinstance(payload, dict):
        for key in _TOP_LEVEL_FORBIDDEN:
            if key in payload:
                _fail(f"predictions must not include top-level key {key!r}")
        cases = payload.get("cases") or payload.get("predictions")
        if isinstance(cases, list):
            for index, item in enumerate(cases):
                if not isinstance(item, dict):
                    continue
                for key in _CASE_FORBIDDEN:
                    if key in item:
                        _fail(f"predictions[{index}] must not include {key!r}")


def digest_predictions_file(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    assert_predictions_label_free(payload)
    digest = hashlib.sha256(raw).hexdigest()
    return {
        "schema_version": "ovk.holdout.predictions_digest.v1",
        "predictions_path": path.as_posix(),
        "sha256": digest,
        "byte_length": len(raw),
        "label_free": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Digest label-free holdout predictions")
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.predictions.is_file():
        _fail(f"predictions file not found: {args.predictions}")
    record = digest_predictions_file(args.predictions)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"predictions digest ok: sha256={record['sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
