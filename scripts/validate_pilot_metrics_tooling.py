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
UPDATE_ADOPTION_SUMMARY_WORKFLOW = ROOT / ".github/workflows/update-adoption-summary.yml"
EXTERNAL_MANIFEST = ROOT / "examples/pilot_repos/external_oss_ci_secrets.json"
ADOPTION_SUMMARY = ROOT / "docs/benchmarks/adoption-summary.json"
EXTERNAL_PILOTS_REGISTRY = ROOT / "docs/benchmarks/external-pilots-registry.json"
EXTERNAL_PILOT_REPORT_TEMPLATE = ROOT / "docs/templates/external_pilot_report.template.json"


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


def validate_external_pilots_registry() -> list[str]:
    failures: list[str] = []
    registry_schema = schema_path("external.pilots.registry.schema.json")
    pilot_schema = schema_path("external.pilot.schema.json")
    if not registry_schema.exists():
        failures.append("missing schemas/external.pilots.registry.schema.json")
    if not pilot_schema.exists():
        failures.append("missing schemas/external.pilot.schema.json")
    if not EXTERNAL_PILOTS_REGISTRY.exists():
        failures.append("missing docs/benchmarks/external-pilots-registry.json")
        return failures
    if not EXTERNAL_PILOT_REPORT_TEMPLATE.exists():
        failures.append("missing docs/templates/external_pilot_report.template.json")
    try:
        registry = read_json_file(EXTERNAL_PILOTS_REGISTRY)
        require_schema_valid(registry, read_json_file(registry_schema), context="external pilots registry")
    except ValueError as exc:
        failures.append(str(exc))
    return failures


def validate_registry_merge_behavior() -> list[str]:
    failures: list[str] = []
    from scripts.collect_pilot_metrics import collect_pilot_metrics
    from scripts.render_pilot_metrics import load_external_pilots_registry, render_adoption_summary

    registry_rows = load_external_pilots_registry(EXTERNAL_PILOTS_REGISTRY)
    if not registry_rows:
        failures.append("external pilots registry must contain at least one recruiting placeholder row")
    metrics = collect_pilot_metrics(source="local")
    summary = render_adoption_summary(metrics, registry_path=EXTERNAL_PILOTS_REGISTRY)
    summary_rows = summary.get("external_pilots", [])
    if len(summary_rows) < len(registry_rows):
        failures.append("render_pilot_metrics dropped external_pilots rows from registry")
    for row in registry_rows:
        repo = str(row.get("repository", ""))
        if repo and not any(str(item.get("repository")) == repo for item in summary_rows):
            failures.append(f"render_pilot_metrics missing registry row for {repo}")
    return failures


def validate_pilot_metrics_dry_run() -> list[str]:
    ensure_repo_on_path()
    failures: list[str] = []
    failures.extend(validate_pilot_dogfood_workflow())
    failures.extend(validate_external_pilots_registry())
    failures.extend(validate_registry_merge_behavior())

    if not UPDATE_ADOPTION_SUMMARY_WORKFLOW.exists():
        failures.append("missing .github/workflows/update-adoption-summary.yml")
    else:
        text = UPDATE_ADOPTION_SUMMARY_WORKFLOW.read_text(encoding="utf-8")
        for needle in ("workflow_dispatch", "render_pilot_metrics.py", "external-pilots-registry.json"):
            if needle not in text:
                failures.append(f"update-adoption-summary workflow missing required wiring: {needle}")

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
        [
            sys.executable,
            str(ROOT / "scripts/render_pilot_metrics.py"),
            "--dry-run",
            "--registry",
            str(EXTERNAL_PILOTS_REGISTRY),
        ],
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
            if not summary.get("external_pilots"):
                failures.append("render_pilot_metrics dry-run wiped external_pilots")
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

    ingest = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/ingest_external_pilot_metrics.py"),
            "--repo",
            "example/validation-dry-run",
            "--dry-run",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if ingest.returncode != 0:
        failures.append(f"ingest_external_pilot_metrics dry-run failed: {ingest.stderr or ingest.stdout}")

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
