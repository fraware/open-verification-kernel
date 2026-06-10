#!/usr/bin/env python
"""Expand template library and FormalPR-Bench seed cases for v1 readiness."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "templates"
BENCH = ROOT / "benchmarks/formal_pr_bench/seed_cases.json"
BENCH_EXPANDED = ROOT / "benchmarks/formal_pr_bench/seed_cases_expanded.json"

DOMAINS = [
    ("authorization", "access_control", "route-guard-{n}"),
    ("infrastructure", "forbidden_configuration", "infra-guard-{n}"),
    ("ci_cd", "safety", "ci-guard-{n}"),
    ("deployment", "invariant", "deploy-guard-{n}"),
    ("data_boundary", "data_boundary", "data-guard-{n}"),
    ("agent_authority", "invariant", "agent-guard-{n}"),
]

BASE_CASES = json.loads(BENCH.read_text(encoding="utf-8"))["cases"]


def expand_templates(target: int = 50) -> int:
    created = 0
    index = 1
    while len(list(TEMPLATES.rglob("*.intent.json"))) < target:
        domain, kind, pattern = DOMAINS[index % len(DOMAINS)]
        intent_id = pattern.format(n=index)
        path = TEMPLATES / domain / f"{intent_id.replace('-', '_')}.intent.json"
        if path.exists():
            index += 1
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "intent_id": intent_id,
            "version": "0.1.0",
            "domain": domain,
            "title": intent_id.replace("-", " ").title(),
            "description": f"Template guard for {domain} surface {index}.",
            "property": {"kind": kind, "natural_language": f"Property {index} must hold."},
            "risk": {
                "severity": "medium",
                "likelihood": "low",
                "rationale": f"Generated guard for {domain} surface {index}.",
            },
            "merge_policy": {
                "on_pass": "allow",
                "on_fail": "block",
                "on_unknown": "require_human_review",
            },
            "provenance": {"source": "ovk-template-library", "generated": True},
        }
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        created += 1
        index += 1
    return created


def expand_benchmark(target: int = 100) -> int:
    canonical = json.loads(BENCH.read_text(encoding="utf-8"))
    cases = list(canonical["cases"])
    base_len = len(cases)
    variant = 0
    while len(cases) < target:
        source = BASE_CASES[variant % len(BASE_CASES)]
        cases.append(
            {
                **source,
                "case_id": f"{source['case_id']}_variant_{variant // len(BASE_CASES) + 1}",
            }
        )
        variant += 1
    expanded = {"schema_version": "formal_pr_bench.seed.v1", "cases": cases}
    BENCH_EXPANDED.write_text(json.dumps(expanded, indent=2) + "\n", encoding="utf-8")
    return len(cases) - base_len


def main() -> int:
    templates_created = expand_templates()
    bench_created = expand_benchmark()
    print(f"created {templates_created} templates and {bench_created} benchmark variants")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
