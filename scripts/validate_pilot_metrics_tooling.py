#!/usr/bin/env python
"""Dry-run validation for pilot metrics collection and adoption summary rendering."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from ovk.core.json_io import read_json_file
from ovk.core.schema_validation import require_schema_valid
from ovk.paths import ensure_repo_on_path, schema_path

ROOT = Path(__file__).resolve().parents[1]
PILOT_DOGFOOD_WORKFLOW = ROOT / ".github/workflows/pilot-dogfood.yml"
EXTERNAL_MANIFEST = ROOT / "examples/pilot_repos/external_oss_ci_secrets.json"
ADOPTION_SUMMARY = ROOT / "docs/benchmarks/adoption-summary.json"


def validate_pilot_dogfood_workflow() -> list[str]:
    failures: list[str] = []
    if not PILOT_DOGFOOD_WORKFLOW.exists():
        return ["missing .github/workflows/pilot-dogfood.yml"]
    text = PILOT_DOGFOOD_WORKFLOW.read_text(encoding="utf-8")
    for needle in ("OVK_PACKAGE_VERSION", "collect_pilot_metrics.py", "workflow_dispatch", "schedule:"):
        if needle not in text:
            failures.append(f"pilot-dogfood workflow missing required wiring: {needle}")
    if "external_oss_ci_secrets.json" not in text:
        failures.append("pilot-dogfood workflow should reference external_oss_ci_secrets manifest")
    return failures


def validate_pilot_metrics_dry_run() -> list[str]:
    ensure_repo_on_path()
    failures: list[str] = []
    failures.extend(validate_pilot_dogfood_workflow())

    if not EXTERNAL_MANIFEST.exists():
        failures.append("missing examples/pilot_repos/external_oss_ci_secrets.json")

    metrics_schema = schema_path("pilot.metrics.schema.json")
    adoption_schema = schema_path("adoption.summary.schema.json")
    if not metrics_schema.exists():
        failures.append("missing schemas/pilot.metrics.schema.json")
    if not adoption_schema.exists():
        failures.append("missing schemas/adoption.summary.schema.json")

    from scripts.collect_pilot_metrics import collect_pilot_metrics, validate_metrics

    metrics = collect_pilot_metrics(source="local")
    try:
        validate_metrics(metrics)
    except ValueError as exc:
        failures.append(str(exc))

    if ADOPTION_SUMMARY.exists():
        try:
            require_schema_valid(
                read_json_file(ADOPTION_SUMMARY),
                read_json_file(adoption_schema),
                context="adoption summary template",
            )
        except ValueError as exc:
            failures.append(str(exc))
    else:
        failures.append("missing docs/benchmarks/adoption-summary.json")

    render = subprocess.run(
        [sys.executable, str(ROOT / "scripts/render_pilot_metrics.py"), "--dry-run"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if render.returncode != 0:
        failures.append(f"render_pilot_metrics dry-run failed: {render.stderr or render.stdout}")
    else:
        try:
            summary = json.loads(render.stdout)
            require_schema_valid(summary, read_json_file(adoption_schema), context="rendered adoption summary")
        except (json.JSONDecodeError, ValueError) as exc:
            failures.append(f"render_pilot_metrics dry-run output invalid: {exc}")

    collect = subprocess.run(
        [sys.executable, str(ROOT / "scripts/collect_pilot_metrics.py"), "--dry-run", "--source", "local"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if collect.returncode != 0:
        failures.append(f"collect_pilot_metrics dry-run failed: {collect.stderr or collect.stdout}")
    else:
        try:
            payload = json.loads(collect.stdout)
            validate_metrics(payload)
        except (json.JSONDecodeError, ValueError) as exc:
            failures.append(f"collect_pilot_metrics dry-run output invalid: {exc}")

    return failures


def main() -> int:
    failures = validate_pilot_metrics_dry_run()
    for failure in failures:
        print(failure)
    if failures:
        return 1
    print("pilot metrics tooling dry-run passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
