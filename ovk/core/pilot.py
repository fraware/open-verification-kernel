"""Pilot program runner for OVK verification manifests."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from ovk.core.multi_lane import load_verification_manifest, run_verification_manifest


PILOT_DIR = Path("examples/pilot_repos")


def run_pilot_manifest(
    manifest_path: Path,
    *,
    repo: str = "pilot/repo",
    head_sha: str = "pilot-head",
) -> dict[str, Any]:
    """Execute one pilot manifest and return structured metrics."""
    started = time.perf_counter()
    manifest = load_verification_manifest(manifest_path)
    bundle = run_verification_manifest(
        manifest,
        repo=repo,
        head_sha=head_sha,
        root=manifest_path.parent,
    )
    elapsed_ms = (time.perf_counter() - started) * 1000
    recommendation = str(bundle.decision.get("merge_recommendation", "require_human_review"))
    return {
        "manifest": str(manifest_path),
        "name": str(manifest.get("name", manifest_path.stem)),
        "description": manifest.get("description", ""),
        "lane_count": len(manifest.get("lanes", [])),
        "evidence_count": len(bundle.evidence),
        "merge_recommendation": recommendation,
        "elapsed_ms": elapsed_ms,
        "passed": recommendation == "allow",
    }


def run_pilot_program(
    pilot_dir: Path = PILOT_DIR,
    *,
    repo: str = "pilot/repo",
    head_sha: str = "pilot-head",
) -> dict[str, Any]:
    """Run all pilot manifests under a directory."""
    manifests = sorted(pilot_dir.glob("*.json"))
    if not manifests:
        raise FileNotFoundError(f"no pilot manifests found in {pilot_dir}")
    results = [run_pilot_manifest(path, repo=repo, head_sha=head_sha) for path in manifests]
    passed = sum(1 for item in results if item["passed"])
    return {
        "schema_version": "ovk.pilot_report.v1",
        "pilot_dir": str(pilot_dir),
        "manifests_total": len(results),
        "manifests_passed": passed,
        "results": results,
    }
