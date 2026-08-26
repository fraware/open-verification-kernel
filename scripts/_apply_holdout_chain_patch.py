#!/usr/bin/env python3
"""One-shot exact-head patch for FormalPR-Holdout chain-of-custody hardening.

This file is committed only to execute a branch-scoped migration workflow. The
workflow removes both this script and itself in the same commit that lands the
semantic changes. Every textual replacement is guarded by an exact-match
precondition so unexpected source drift fails without committing.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(relative: str, old: str, new: str) -> None:
    path = ROOT / relative
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{relative}: expected exactly one replacement site, found {count}")
    path.write_text(text.replace(old, new), encoding="utf-8")


def patch_run_formalpr_holdout() -> None:
    path = "scripts/run_formalpr_holdout.py"
    replace_once(
        path,
        '''_REQUIRED_AGGREGATE_KEYS = (\n    "schema_version",\n    "benchmark",\n    "holdout_release_tag",\n    "ovk_commit_sha",\n    "cases_scored",\n    "lanes",\n    "leakage_guard",\n)''',
        '''_REQUIRED_AGGREGATE_KEYS = (\n    "schema_version",\n    "benchmark",\n    "holdout_release_tag",\n    "ovk_commit_sha",\n    "candidate_source_sha",\n    "predictions_sha256",\n    "holdout_asset_sha256",\n    "cases_scored",\n    "lanes",\n    "leakage_guard",\n)''',
    )
    replace_once(
        path,
        '''    if payload.get("benchmark") != "FormalPR-Holdout":\n        _fail("unexpected aggregate benchmark")\n    lanes = payload.get("lanes")''',
        '''    if payload.get("benchmark") != "FormalPR-Holdout":\n        _fail("unexpected aggregate benchmark")\n    candidate = str(payload.get("candidate_source_sha") or "").lower()\n    ovk_sha = str(payload.get("ovk_commit_sha") or "").lower()\n    if len(candidate) != 40 or any(char not in "0123456789abcdef" for char in candidate):\n        _fail("candidate_source_sha must be exact lowercase 40-hex")\n    if ovk_sha != candidate:\n        _fail("ovk_commit_sha must equal candidate_source_sha exactly")\n    for key in ("predictions_sha256", "holdout_asset_sha256"):\n        digest = str(payload.get(key) or "")\n        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):\n            _fail(f"{key} must be exact lowercase 64-hex")\n    lanes = payload.get("lanes")''',
    )
    replace_once(
        path,
        '''def run_harness(\n    *,\n    release_root: Path,\n    predictions: Path,\n    holdout_tag: str,\n    ovk_sha: str,\n    verified_sha: str | None,\n    output: Path,\n) -> dict[str, Any]:''',
        '''def run_harness(\n    *,\n    release_root: Path,\n    predictions: Path,\n    holdout_tag: str,\n    ovk_sha: str,\n    candidate_source_sha: str,\n    predictions_sha256: str,\n    holdout_asset_sha256: str,\n    verified_sha: str | None,\n    output: Path,\n) -> dict[str, Any]:''',
    )
    replace_once(
        path,
        '''    payload = json.loads(output.read_text(encoding="utf-8"))\n    assert_aggregate_safe(payload)\n    return payload''',
        '''    payload = json.loads(output.read_text(encoding="utf-8"))\n    if not isinstance(payload, dict):\n        _fail("evaluate.py aggregate output must be a JSON object")\n    if "verified_source_sha" in payload:\n        _fail("ordinary holdout evaluator must not emit verified_source_sha")\n    bindings = {\n        "candidate_source_sha": candidate_source_sha,\n        "ovk_commit_sha": candidate_source_sha,\n        "predictions_sha256": predictions_sha256,\n        "holdout_asset_sha256": holdout_asset_sha256,\n    }\n    for key, expected in bindings.items():\n        existing = payload.get(key)\n        if existing is not None and str(existing).lower() != expected:\n            _fail(f"evaluator {key} mismatch: observed={existing!r} expected={expected!r}")\n        payload[key] = expected\n    assert_aggregate_safe(payload)\n    return payload''',
    )
    replace_once(
        path,
        '''        verify_asset_sha256(tarball, expected_digest)\n        release_root = extract_tarball(tarball, tmp_path / "extract")\n        # Predictions must be label-free before the evaluator sees them.\n        pred_payload = json.loads(args.predictions.read_text(encoding="utf-8"))''',
        '''        holdout_asset_sha256 = verify_asset_sha256(tarball, expected_digest).lower()\n        release_root = extract_tarball(tarball, tmp_path / "extract")\n        # Predictions must be label-free before the evaluator sees them.\n        pred_payload = json.loads(args.predictions.read_text(encoding="utf-8"))''',
    )
    replace_once(
        path,
        '''        assert_predictions_label_free(pred_payload)\n        candidate_sha = args.candidate_source_sha or args.ovk_commit_sha\n        if args.verified_source_sha:''',
        '''        assert_predictions_label_free(pred_payload)\n        candidate_sha = str(args.candidate_source_sha or args.ovk_commit_sha).lower()\n        if len(candidate_sha) != 40 or any(\n            char not in "0123456789abcdef" for char in candidate_sha\n        ):\n            _fail("candidate source SHA must be exact lowercase 40-hex")\n        prediction_candidate = str(pred_payload.get("candidate_source_sha") or "").lower()\n        if prediction_candidate and prediction_candidate != candidate_sha:\n            _fail(\n                "prediction candidate_source_sha mismatch: "\n                f"predictions={prediction_candidate} expected={candidate_sha}"\n            )\n        predictions_sha256 = sha256_file(args.predictions).lower()\n        if args.verified_source_sha:''',
    )
    replace_once(
        path,
        '''            holdout_tag=args.tag,\n            ovk_sha=candidate_sha,\n            verified_sha=None,\n            output=tmp_path / "aggregate.json",\n        )\n        # Normalize identity fields for ordinary holdout.\n        if isinstance(payload, dict):\n            payload = dict(payload)\n            payload["candidate_source_sha"] = candidate_sha\n            payload["ovk_commit_sha"] = candidate_sha\n            payload.pop("verified_source_sha", None)''',
        '''            holdout_tag=args.tag,\n            ovk_sha=candidate_sha,\n            candidate_source_sha=candidate_sha,\n            predictions_sha256=predictions_sha256,\n            holdout_asset_sha256=holdout_asset_sha256,\n            verified_sha=None,\n            output=tmp_path / "aggregate.json",\n        )\n        validate_aggregate_schema(payload)''',
    )


def patch_holdout_schema() -> None:
    path = ROOT / "schemas" / "holdout.aggregate_metrics.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    required = schema["required"]
    for key in ("candidate_source_sha", "predictions_sha256", "holdout_asset_sha256"):
        if key not in required:
            required.append(key)
    props = schema["properties"]
    props["ovk_commit_sha"] = {"type": "string", "pattern": "^[0-9a-f]{40}$"}
    props["candidate_source_sha"] = {"type": "string", "pattern": "^[0-9a-f]{40}$"}
    props["predictions_sha256"] = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    props["holdout_asset_sha256"] = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def patch_release_ledger() -> None:
    path = "ovk/core/release_ledger.py"
    replace_once(
        path,
        '''    holdout_payload = holdout or {\n        "candidate_source_sha": candidate_sha,\n        "predictions_sha256": None,\n        "aggregate_sha256": None,\n        "holdout_tag": None,\n    }''',
        '''    holdout_payload = holdout or {\n        "candidate_source_sha": candidate_sha,\n        "predictions_sha256": None,\n        "aggregate_sha256": None,\n        "holdout_asset_sha256": None,\n        "holdout_tag": None,\n    }''',
    )
    replace_once(
        path,
        '''    for key in ("predictions_sha256", "aggregate_sha256"):\n        value = holdout.get(key)''',
        '''    for key in ("predictions_sha256", "aggregate_sha256", "holdout_asset_sha256"):\n        value = holdout.get(key)''',
    )
    replace_once(
        path,
        '''        for key in ("predictions_sha256", "aggregate_sha256"):\n            if not _valid_sha256(holdout.get(key)):\n                failures.append(f"holdout.{key} required")''',
        '''        for key in ("predictions_sha256", "aggregate_sha256", "holdout_asset_sha256"):\n            if not _valid_sha256(holdout.get(key)):\n                failures.append(f"holdout.{key} required")''',
    )
    replace_once(
        path,
        '''            agg_sha = aggregate.get("aggregate_sha256")\n            agg_candidate = str(aggregate.get("candidate_source_sha") or "").lower()\n            holdout_tag = str(aggregate.get("holdout_tag") or "")''',
        '''            agg_sha = aggregate.get("aggregate_sha256")\n            agg_candidate = str(aggregate.get("candidate_source_sha") or "").lower()\n            agg_predictions_sha = aggregate.get("predictions_sha256")\n            holdout_asset_sha = aggregate.get("holdout_asset_sha256")\n            holdout_tag = str(aggregate.get("holdout_tag") or "")''',
    )
    replace_once(
        path,
        '''            if agg_candidate != candidate:\n                failures.append("holdout_aggregate_candidate_mismatch")\n            if not holdout_tag:''',
        '''            if agg_candidate != candidate:\n                failures.append("holdout_aggregate_candidate_mismatch")\n            if not _valid_sha256(agg_predictions_sha):\n                failures.append("holdout_aggregate_predictions_sha256_invalid")\n            if pred_sha is not None and agg_predictions_sha != pred_sha:\n                failures.append("holdout_aggregate_predictions_digest_mismatch")\n            if not _valid_sha256(holdout_asset_sha):\n                failures.append("holdout_asset_sha256_invalid")\n            if not holdout_tag:''',
    )
    replace_once(
        path,
        '''        else:\n            agg_sha = None\n            holdout_tag = ""''',
        '''        else:\n            agg_sha = None\n            agg_predictions_sha = None\n            holdout_asset_sha = None\n            holdout_tag = ""''',
    )
    replace_once(
        path,
        '''            _preclaim_mismatch(\n                failures,\n                name="holdout.aggregate_sha256",\n                claimed=_normalized_optional_digest(claimed.get("aggregate_sha256")),\n                observed=(str(agg_sha).lower() if _valid_sha256(agg_sha) else agg_sha),\n            )\n            _preclaim_mismatch(\n                failures,\n                name="holdout.holdout_tag",''',
        '''            _preclaim_mismatch(\n                failures,\n                name="holdout.aggregate_sha256",\n                claimed=_normalized_optional_digest(claimed.get("aggregate_sha256")),\n                observed=(str(agg_sha).lower() if _valid_sha256(agg_sha) else agg_sha),\n            )\n            _preclaim_mismatch(\n                failures,\n                name="holdout.holdout_asset_sha256",\n                claimed=_normalized_optional_digest(claimed.get("holdout_asset_sha256")),\n                observed=(\n                    str(holdout_asset_sha).lower()\n                    if _valid_sha256(holdout_asset_sha)\n                    else holdout_asset_sha\n                ),\n            )\n            _preclaim_mismatch(\n                failures,\n                name="holdout.holdout_tag",''',
    )
    replace_once(
        path,
        '''            holdout_out = {\n                "candidate_source_sha": candidate,\n                "predictions_sha256": str(pred_sha).lower(),\n                "aggregate_sha256": str(agg_sha).lower(),\n                "holdout_tag": holdout_tag,\n            }\n            provenance["holdout"] = {\n                "predict_run_id": rows["FormalPR-Holdout predict"]["run_id"],\n                "eval_run_id": rows["FormalPR-Holdout eval"]["run_id"],\n                "predictions_sha256": str(pred_sha).lower(),\n                "prediction_manifest_sha256": str(manifest_file_sha).lower(),\n                "aggregate_sha256": str(agg_sha).lower(),\n                "holdout_tag": holdout_tag,\n            }''',
        '''            holdout_out = {\n                "candidate_source_sha": candidate,\n                "predictions_sha256": str(pred_sha).lower(),\n                "aggregate_sha256": str(agg_sha).lower(),\n                "holdout_asset_sha256": str(holdout_asset_sha).lower(),\n                "holdout_tag": holdout_tag,\n            }\n            provenance["holdout"] = {\n                "predict_run_id": rows["FormalPR-Holdout predict"]["run_id"],\n                "eval_run_id": rows["FormalPR-Holdout eval"]["run_id"],\n                "predictions_sha256": str(pred_sha).lower(),\n                "aggregate_predictions_sha256": str(agg_predictions_sha).lower(),\n                "prediction_manifest_sha256": str(manifest_file_sha).lower(),\n                "aggregate_sha256": str(agg_sha).lower(),\n                "holdout_asset_sha256": str(holdout_asset_sha).lower(),\n                "holdout_tag": holdout_tag,\n            }''',
    )


def patch_release_ledger_schema() -> None:
    path = ROOT / "schemas" / "release.ledger.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    holdout = schema["properties"]["holdout"]
    holdout["properties"]["holdout_asset_sha256"] = {
        "anyOf": [
            {"type": "null"},
            {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
        ]
    }
    if "holdout_asset_sha256" not in holdout["required"]:
        holdout["required"].append("holdout_asset_sha256")
    path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def patch_live_resolver() -> None:
    path = "scripts/verify_release_ledger_github.py"
    replace_once(
        path,
        '''        "aggregate_sha256": _sha256(aggregate_path),\n        "candidate_source_sha": str(aggregate.get("ovk_commit_sha") or "").lower(),\n        "holdout_tag": str(aggregate.get("holdout_release_tag") or ""),''',
        '''        "aggregate_sha256": _sha256(aggregate_path),\n        "candidate_source_sha": str(aggregate.get("candidate_source_sha") or "").lower(),\n        "predictions_sha256": str(aggregate.get("predictions_sha256") or "").lower(),\n        "holdout_asset_sha256": str(aggregate.get("holdout_asset_sha256") or "").lower(),\n        "holdout_tag": str(aggregate.get("holdout_release_tag") or ""),''',
    )


def patch_tests() -> None:
    path = "tests/test_release_ledger_artifact_provenance.py"
    replace_once(
        path,
        '''AGG_SHA = "3" * 64\nWHEEL_SHA = "4" * 64''',
        '''AGG_SHA = "3" * 64\nHOLDOUT_ASSET_SHA = "a" * 64\nWHEEL_SHA = "4" * 64''',
    )
    replace_once(
        path,
        '''            "aggregate_sha256": AGG_SHA,\n            "candidate_source_sha": SHA,\n            "holdout_tag": HOLDOUT_TAG,''',
        '''            "aggregate_sha256": AGG_SHA,\n            "candidate_source_sha": SHA,\n            "predictions_sha256": PRED_SHA,\n            "holdout_asset_sha256": HOLDOUT_ASSET_SHA,\n            "holdout_tag": HOLDOUT_TAG,''',
    )
    replace_once(
        path,
        '''        "predictions_sha256": PRED_SHA,\n        "aggregate_sha256": AGG_SHA,\n        "holdout_tag": HOLDOUT_TAG,''',
        '''        "predictions_sha256": PRED_SHA,\n        "aggregate_sha256": AGG_SHA,\n        "holdout_asset_sha256": HOLDOUT_ASSET_SHA,\n        "holdout_tag": HOLDOUT_TAG,''',
    )
    replace_once(
        path,
        '''        "holdout_release_tag": HOLDOUT_TAG,\n        "ovk_commit_sha": SHA,\n        "generated_at_unix_ms": 1,''',
        '''        "holdout_release_tag": HOLDOUT_TAG,\n        "ovk_commit_sha": SHA,\n        "candidate_source_sha": SHA,\n        "predictions_sha256": PRED_SHA,\n        "holdout_asset_sha256": HOLDOUT_ASSET_SHA,\n        "generated_at_unix_ms": 1,''',
    )
    replace_once(
        path,
        '''    assert observed["candidate_source_sha"] == SHA\n    assert observed["holdout_tag"] == HOLDOUT_TAG\n    assert observed["schema_valid"] is True''',
        '''    assert observed["candidate_source_sha"] == SHA\n    assert observed["predictions_sha256"] == PRED_SHA\n    assert observed["holdout_asset_sha256"] == HOLDOUT_ASSET_SHA\n    assert observed["holdout_tag"] == HOLDOUT_TAG\n    assert observed["schema_valid"] is True''',
    )
    append = '''\n\ndef test_aggregate_prediction_digest_mismatch_cannot_authorize() -> None:\n    def mismatched_artifacts(repository: str, run_id: int, workflow: str) -> dict[str, Any]:\n        payload = dict(_workflow_artifact_resolver(repository, run_id, workflow))\n        if workflow == "FormalPR-Holdout eval":\n            payload["predictions_sha256"] = "f" * 64\n        return payload\n\n    ok, failures, checked = verify_release_ledger(\n        _draft(),\n        repo_root=REPO,\n        workflow_run_resolver=_live_run_resolver,\n        workflow_artifact_resolver=mismatched_artifacts,\n        release_artifact_resolver=_release_artifact_resolver,\n        expected_repository=REPOSITORY,\n        expected_candidate_sha=SHA,\n    )\n    assert ok is False\n    assert "holdout_aggregate_predictions_digest_mismatch" in failures\n    assert checked["release_state"]["authorized"] is False\n    assert checked["release_state"]["verified_source_sha"] is None\n'''
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    if "def test_aggregate_prediction_digest_mismatch_cannot_authorize" in text:
        raise SystemExit(f"{path}: mismatch regression test already exists")
    target.write_text(text.rstrip() + append + "\n", encoding="utf-8")


def main() -> int:
    patch_run_formalpr_holdout()
    patch_holdout_schema()
    patch_release_ledger()
    patch_release_ledger_schema()
    patch_live_resolver()
    patch_tests()
    print("holdout chain-of-custody patch applied with all preconditions satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
