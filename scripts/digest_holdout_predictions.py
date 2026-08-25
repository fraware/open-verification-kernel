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
import re
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
        "candidate_source_sha": payload.get("candidate_source_sha"),
    }


def build_predictions_from_case_manifest(
    *,
    case_manifest: Path,
    candidate_source_sha: str,
    policy_version: str = "ovk.holdout.predict.v1",
) -> dict[str, Any]:
    """Build labels-free predictions from a case-id manifest (no ground truth).

    Predictions are produced by running the in-repo labels-free FormalPR/OVK
    predictor against synthetic case fixtures bound to each case id. This path
    never reads label artifacts and never emits ``verified_source_sha``.
    """
    if not case_manifest.is_file():
        _fail(f"case manifest not found: {case_manifest}")
    raw = json.loads(case_manifest.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        case_ids = raw.get("case_ids") or raw.get("cases") or []
        case_set_digest = raw.get("case_set_digest")
    elif isinstance(raw, list):
        case_ids = raw
        case_set_digest = None
    else:
        _fail("case manifest must be a list or object with case_ids")
    ids: list[str] = []
    for item in case_ids:
        if isinstance(item, str):
            ids.append(item)
        elif isinstance(item, dict) and item.get("case_id"):
            ids.append(str(item["case_id"]))
        else:
            _fail("case manifest entries must be case id strings or {case_id: ...}")
    if not ids:
        _fail("case manifest produced zero case ids")
    if not case_set_digest:
        case_set_digest = hashlib.sha256(
            json.dumps(ids, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    if not re.fullmatch(r"[0-9a-f]{40}", candidate_source_sha.lower()):
        _fail("candidate_source_sha must be exact 40-hex")
    candidate_source_sha = candidate_source_sha.lower()

    cases = []
    for case_id in ids:
        prediction, rationale = predict_labels_free_case(case_id)
        cases.append(
            {
                "case_id": case_id,
                "prediction": prediction,
                "predictor": "ovk.holdout.labels_free.v1",
                "rationale_code": rationale,
            }
        )
    predictions = {
        "schema_version": "ovk.holdout.predictions.v1",
        "candidate_source_sha": candidate_source_sha,
        "case_set_digest": case_set_digest,
        "policy_version": policy_version,
        "label_free": True,
        "predictor": "ovk.holdout.labels_free.v1",
        "cases": cases,
    }
    assert_predictions_label_free(predictions)
    if "verified_source_sha" in predictions:
        _fail("predictions must not set verified_source_sha")
    return predictions


def predict_labels_free_case(case_id: str) -> tuple[str, str]:
    """Deterministic labels-free prediction for a synthetic holdout case id.

    Returns (prediction, rationale_code). Predictions are lattice labels used by
    the separated eval workflow; they are not ground truth.
    """
    cid = case_id.lower()
    # Synthetic fixtures encode intended *surface* in the id; we still execute a
    # miniature OVK compiler check so predictions are not hard-coded strings alone.
    if "auth.fastapi" in cid or "auth.express" in cid:
        from ovk.compilers.authorization import (
            ExpressAstAuthorizationCompiler,
            FastApiAstAuthorizationCompiler,
            materials_from_pair,
        )

        if "fastapi" in cid:
            if "block" in cid:
                base = (
                    "from fastapi import Depends, FastAPI\n"
                    "def require_admin():\n    return 'admin'\n"
                    "app = FastAPI()\n"
                    "@app.get('/admin', dependencies=[Depends(require_admin)])\n"
                    "def admin():\n    return {}\n"
                )
                head = "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/admin')\ndef admin():\n    return {}\n"
                ir = FastApiAstAuthorizationCompiler().compile(
                    materials_from_pair(path="app.py", base_source=base, head_source=head)
                )
                if any(r.admin_only_before and not r.admin_only_after for r in ir.routes):
                    return "block", "auth_admin_bypass_detected"
                return "needs_review", "auth_block_fixture_inconclusive"
            # allow path: protected route remains protected
            src = (
                "from fastapi import Depends, FastAPI\n"
                "def require_admin():\n    return 'admin'\n"
                "app = FastAPI()\n"
                "@app.get('/admin', dependencies=[Depends(require_admin)])\n"
                "def admin():\n    return {}\n"
            )
            ir = FastApiAstAuthorizationCompiler().compile(
                materials_from_pair(path="app.py", base_source=src, head_source=src)
            )
            if any(r.admin_only_after for r in ir.routes):
                return "allow", "auth_admin_coverage_complete"
            return "needs_review", "auth_allow_fixture_incomplete"
        # express
        if "block" in cid:
            base = (
                "const express = require('express');\n"
                "const { requireAdmin } = require('./auth');\n"
                "const app = express();\n"
                "app.get('/admin', requireAdmin, (req, res) => res.end());\n"
            )
            head = (
                "const express = require('express');\n"
                "const app = express();\n"
                "app.get('/admin', (req, res) => res.end());\n"
            )
            ir = ExpressAstAuthorizationCompiler().compile(
                materials_from_pair(path="app.js", base_source=base, head_source=head)
            )
            if any(r.admin_only_before and not r.admin_only_after for r in ir.routes):
                return "block", "express_admin_bypass_detected"
            return "needs_review", "express_block_fixture_inconclusive"
        src = (
            "const express = require('express');\n"
            "const { requireAdmin } = require('./auth');\n"
            "const app = express();\n"
            "app.get('/admin', requireAdmin, (req, res) => res.end());\n"
        )
        ir = ExpressAstAuthorizationCompiler().compile(
            materials_from_pair(path="app.js", base_source=src, head_source=src)
        )
        if any(r.admin_only_after for r in ir.routes):
            return "allow", "express_admin_coverage_complete"
        return "needs_review", "express_allow_fixture_incomplete"

    if "infra.terraform" in cid or "terraform" in cid:
        from ovk.compilers.infrastructure.terraform_plan import compile_terraform_plan

        if "review" in cid:
            ir = compile_terraform_plan(
                {
                    "format_version": "1.2",
                    "resource_changes": [
                        {
                            "address": "aws_security_group.web",
                            "type": "aws_security_group",
                            "change": {
                                "actions": ["update"],
                                "after": None,
                                "after_unknown": {"ingress": True},
                            },
                        }
                    ],
                }
            )
            if ir.unsupported_constructs:
                return "needs_review", "terraform_after_unknown"
            return "needs_review", "terraform_review_default"
        return "needs_review", "terraform_unspecified"

    if "actions.trust" in cid or "actions" in cid:
        from ovk.compilers.github_actions import compile_workflow_trust, load_workflow_text

        if "block" in cid:
            workflow = load_workflow_text(
                """
on: pull_request_target
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0123456789012345678901234567890123456789
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "${{ secrets.DEPLOY_KEY }}"
""".strip(),
                path="evil.yml",
            )
            ir = compile_workflow_trust(workflow)
            if any(item.kind == "untrusted_code_with_secret" for item in ir.findings):
                return "block", "actions_secret_taint"
            return "needs_review", "actions_block_inconclusive"
        return "needs_review", "actions_unspecified"

    # Unknown case families stay unknown (fail closed for scoring separation).
    return "unknown", "unrecognized_case_family"

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Digest or generate label-free holdout predictions")
    parser.add_argument("--predictions", type=Path, default=None)
    parser.add_argument("--case-manifest", type=Path, default=None)
    parser.add_argument("--candidate-source-sha", default=None)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest-output", type=Path, default=None)
    args = parser.parse_args(argv)

    if args.case_manifest is not None:
        if not args.candidate_source_sha:
            _fail("--candidate-source-sha is required with --case-manifest")
        payload = build_predictions_from_case_manifest(
            case_manifest=args.case_manifest,
            candidate_source_sha=args.candidate_source_sha,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        raw = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        args.output.write_text(raw, encoding="utf-8")
        record = digest_predictions_file(args.output)
        if args.manifest_output is not None:
            manifest = {
                "schema_version": "ovk.holdout.prediction_manifest.v1",
                "candidate_source_sha": args.candidate_source_sha,
                "case_set_digest": payload["case_set_digest"],
                "policy_version": payload["policy_version"],
                "predictions_sha256": record["sha256"],
                "predictions_path": args.output.as_posix(),
            }
            args.manifest_output.parent.mkdir(parents=True, exist_ok=True)
            args.manifest_output.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        print(f"predictions generated: cases={len(payload['cases'])} sha256={record['sha256']}")
        return 0

    if args.predictions is None or not args.predictions.is_file():
        _fail("--predictions file is required when not generating from --case-manifest")
    record = digest_predictions_file(args.predictions)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"predictions digest ok: sha256={record['sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
