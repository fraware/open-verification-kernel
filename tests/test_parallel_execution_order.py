"""Regression tests for deterministic ordering under parallel execution."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import ovk.core.adapter_runtime as adapter_runtime
from ovk.core.adapter_runtime import execute_obligations
from ovk.core.bundle import make_bundle
from ovk.core.json_io import read_json_file
import ovk.core.multi_lane as multi_lane
from ovk.core.multi_lane import load_verification_manifest, run_verification_manifest


def _intent_ids_from_manifest(manifest: dict) -> list[str]:
    lane_to_intent = {
        "self_protection": "agent-cannot-disable-own-ci-gate",
        "authorization": "no-admin-route-bypass",
        "infrastructure": "no-public-sensitive-resource",
        "ci_secrets": "no-secrets-in-untrusted-context",
        "deployment": "no-skipped-approval-state",
    }
    return [
        lane_to_intent[str(entry["lane"])]
        for entry in manifest["lanes"]
        if isinstance(entry, dict) and entry.get("lane")
    ]


def test_run_verification_manifest_preserves_lane_order_under_parallelism() -> None:
    manifest_path = Path("examples/verification_manifests/full_mvp.json")
    manifest = load_verification_manifest(manifest_path)
    expected_intents = _intent_ids_from_manifest(manifest)
    real_evaluate = multi_lane._evaluate_manifest_entry

    def _slow_first_entry(entry, **kwargs):
        if str(entry.get("lane")) == "self_protection":
            time.sleep(0.15)
        return real_evaluate(entry, **kwargs)

    with patch.object(multi_lane, "_evaluate_manifest_entry", side_effect=_slow_first_entry):
        bundle = run_verification_manifest(
            manifest,
            repo="test/repo",
            head_sha="abc",
            root=manifest_path.parent,
            parallel=True,
        )

    observed = [item.intent["intent_id"] for item in bundle.evidence]
    assert observed == expected_intents


def test_execute_obligations_preserves_order_and_bundle_id_under_parallelism() -> None:
    ci_input = read_json_file(Path("examples/ci_secrets/input_secrets_safe.json"))
    auth_input = read_json_file(Path("examples/auth_regression/input_admin_protected.json"))
    obligations = [
        {
            "lane": "ci_secrets",
            "intent_id": "no-secrets-in-untrusted-context",
            "input": ci_input,
            "input_format": "infra",
        },
        {
            "lane": "authorization",
            "intent_id": "no-admin-route-bypass",
            "input": auth_input,
            "input_format": "infra",
        },
    ]

    real_evaluate = adapter_runtime._evaluate_obligation

    def _slow_first(obligation, **kwargs):
        if obligation["lane"] == "ci_secrets":
            time.sleep(0.15)
        return real_evaluate(obligation, **kwargs)

    with patch.object(adapter_runtime, "_evaluate_obligation", side_effect=_slow_first):
        first = execute_obligations(
            obligations,
            {},
            repo="test/repo",
            head_sha="abc",
            use_cache=False,
            parallel=True,
        )
        second = execute_obligations(
            obligations,
            {},
            repo="test/repo",
            head_sha="abc",
            use_cache=False,
            parallel=True,
        )

    assert [item.intent["intent_id"] for item in first] == [
        "no-secrets-in-untrusted-context",
        "no-admin-route-bypass",
    ]
    assert make_bundle(first).bundle_id == make_bundle(second).bundle_id
