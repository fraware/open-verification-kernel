#!/usr/bin/env python
"""Generate FormalPR-Bench provenance artifacts (OVK-PR5 / OVK-06).

Writes partitions, licenses, provenance records, rationales, mutations,
held-out descriptors, adversarial fixtures, duplication report, and
manifest.v1.json under benchmarks/formal_pr_bench/.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.formal_pr_bench.provenance_kit import (  # noqa: E402
    ADVERSARIAL_DIR,
    BENCH_DIR,
    BENCHMARK_VERSION,
    DUPLICATION_REPORT_PATH,
    HELD_OUT_DIR,
    LICENSES_PATH,
    MANIFEST_PATH,
    MUTATIONS_DIR,
    PARTITIONS,
    PARTITIONS_PATH,
    PROVENANCE_DIR,
    RATIONALES_DIR,
    TEMPLATE_DEV_PATH,
    build_version_manifest,
    load_all_cases,
    load_json,
    sha256_hex,
)

SEED_CASES = BENCH_DIR / "seed_cases.json"
REAL_DIFFS_MANIFEST = ROOT / "benchmarks" / "real_diffs" / "manifest.json"
REAL_DIFF_CASES = BENCH_DIR / "real_diff_cases.json"

# Explicit held-out set: never overlaps seed/template-dev fixtures.
HELD_OUT_CASE_IDS = (
    "rd_cbmc_use_after_free_auth_cache",
    "rd_cbmc_integer_overflow_quota",
    "rd_docs_only_change",
    "alloy_fail_variant_1",
    "auth_bypass_variant_2",
    "cedar_malformed_variant_2",
    "kani_unknown_variant_2",
    "lean_fail_variant_1",
    "tla_unknown_variant_2",
    "verus_fail_variant_1",
)

# Development partition: extended categories + selected expanded variants.
DEVELOPMENT_PREFERRED = (
    "route_cedar_iam",
    "route_kani_rust",
    "route_alloy_model",
    "route_dafny_proof",
    "adversarial_forged_allow",
    "adversarial_sha_mismatch",
    "repair_loop_infra_exposure",
    "repair_loop_deployment_skip",
    "repair_loop_ci_secrets",
    "repair_loop_auth_bypass",
    "recall_ci_secrets_workflow_diff",
    "recall_infra_terraform_diff",
    "recall_multi_surface_combined",
    "multi_surface_combined_pr",
    "auth_bypass_variant_1",
    "ci_secrets_exposed_variant_1",
    "infra_public_sensitive_variant_1",
    "deployment_skipped_approval_variant_1",
    "control_removed_variant_1",
    "cbmc_fail_variant_1",
)


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def sync_real_diff_cases() -> int:
    """Regenerate real_diff_cases.json from benchmarks/real_diffs/manifest.json."""
    manifest = load_json(REAL_DIFFS_MANIFEST)
    cases = [
        {
            "case_id": item["case_id"],
            "category": "real_diff",
            "input_fixture": f"benchmarks/real_diffs/{item['diff']}",
            "expected_lanes": item["expected_lanes"],
            "expected_intents": item.get("expected_intents", []),
            "expected_merge_recommendation": item["expected_recommendation"],
        }
        for item in manifest["cases"]
    ]
    _write_json(REAL_DIFF_CASES, {"schema_version": "formal_pr_bench.real_diff.v1", "cases": cases})
    return len(cases)


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def build_duplication_report(cases: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Near-duplicate detection over fixture paths and expected-outcome fingerprints."""
    by_fixture: dict[str, list[str]] = defaultdict(list)
    by_fingerprint: dict[str, list[str]] = defaultdict(list)
    for case_id, case in cases.items():
        fixture = str(case.get("input_fixture") or case.get("changed_files") or "")
        if fixture:
            by_fixture[fixture].append(case_id)
        fingerprint = sha256_hex(
            {
                "category": case.get("category"),
                "expected_status": case.get("expected_status"),
                "expected_merge_recommendation": case.get("expected_merge_recommendation"),
                "expected_intents": case.get("expected_intents"),
                "expected_lanes": case.get("expected_lanes"),
                "expected_backend": case.get("expected_backend"),
                "fixture": fixture,
            }
        )
        by_fingerprint[fingerprint].append(case_id)

    fixture_dups = [
        {"fixture": fixture, "case_ids": sorted(ids)}
        for fixture, ids in sorted(by_fixture.items())
        if len(ids) > 1
    ]
    outcome_near_dups = [
        {"fingerprint": digest, "case_ids": sorted(ids)}
        for digest, ids in sorted(by_fingerprint.items())
        if len(ids) > 1
    ]

    # Textual near-duplicates among real_diff fixtures.
    real_diff_texts: dict[str, str] = {}
    for case_id, case in cases.items():
        if case.get("category") != "real_diff":
            continue
        fixture = case.get("input_fixture")
        if not fixture:
            continue
        path = ROOT / str(fixture)
        if path.is_file():
            real_diff_texts[case_id] = _normalize_text(path.read_text(encoding="utf-8"))

    text_pairs: list[dict[str, Any]] = []
    ids = sorted(real_diff_texts)
    for i, left in enumerate(ids):
        left_tokens = set(real_diff_texts[left].split())
        if not left_tokens:
            continue
        for right in ids[i + 1 :]:
            right_tokens = set(real_diff_texts[right].split())
            if not right_tokens:
                continue
            jaccard = len(left_tokens & right_tokens) / len(left_tokens | right_tokens)
            if jaccard >= 0.85:
                text_pairs.append(
                    {
                        "case_ids": [left, right],
                        "jaccard": round(jaccard, 4),
                        "threshold": 0.85,
                    }
                )

    return {
        "schema_version": "formal_pr_bench.duplication_report.v1",
        "benchmark_version": BENCHMARK_VERSION,
        "method": {
            "fixture_path_collision": "exact",
            "outcome_fingerprint": "sha256 over selected expectation fields",
            "real_diff_text": "token Jaccard >= 0.85 on normalized unified diffs",
        },
        "fixture_path_duplicates": fixture_dups,
        "outcome_near_duplicates": outcome_near_dups,
        "real_diff_text_near_duplicates": text_pairs,
        "summary": {
            "fixture_path_duplicate_groups": len(fixture_dups),
            "outcome_near_duplicate_groups": len(outcome_near_dups),
            "real_diff_text_near_duplicate_pairs": len(text_pairs),
        },
    }


def assign_partitions(cases: dict[str, dict[str, Any]], template_dev: set[str]) -> dict[str, list[str]]:
    all_ids = sorted(cases)
    held_out = [case_id for case_id in HELD_OUT_CASE_IDS if case_id in cases]
    held_set = set(held_out)
    if held_set & template_dev:
        raise SystemExit(f"held_out overlaps template_dev: {sorted(held_set & template_dev)}")

    remaining = [case_id for case_id in all_ids if case_id not in held_set]
    development = [case_id for case_id in DEVELOPMENT_PREFERRED if case_id in remaining]
    development_set = set(development)
    rest = [case_id for case_id in remaining if case_id not in development_set]

    # Prefer seed/template-dev and most lane cases in train; real_diff (non-held) + leftover variants in test.
    train: list[str] = []
    test: list[str] = []
    for case_id in rest:
        case = cases[case_id]
        category = str(case.get("category", "lane"))
        if case_id in template_dev or category == "lane":
            # Keep ~15% of non-seed lane variants in test for generalization.
            if case_id not in template_dev and case_id.endswith("_variant_2"):
                test.append(case_id)
            else:
                train.append(case_id)
        elif category == "real_diff":
            test.append(case_id)
        else:
            development.append(case_id)

    partitions = {
        "train": sorted(train),
        "development": sorted(set(development)),
        "test": sorted(test),
        "held_out": sorted(held_out),
    }
    covered = set().union(*(partitions[name] for name in PARTITIONS))
    missing = sorted(set(all_ids) - covered)
    if missing:
        partitions["train"] = sorted(set(partitions["train"]) | set(missing))
    overlap_check: set[str] = set()
    for name in PARTITIONS:
        for case_id in partitions[name]:
            if case_id in overlap_check:
                raise SystemExit(f"partition overlap involving {case_id}")
            overlap_check.add(case_id)
    if overlap_check != set(all_ids):
        raise SystemExit("partition assignment does not cover the full corpus")
    return partitions


def provenance_record(case_id: str, case: dict[str, Any], *, template_dev: bool, partition: str) -> dict[str, Any]:
    source_file = str(case.get("_source_file", ""))
    fixture = case.get("input_fixture")
    derivation = "seed_fixture"
    if case_id.endswith(("_variant_1", "_variant_2")):
        derivation = "expanded_variant"
    elif str(case.get("category")) == "real_diff":
        derivation = "sanitized_real_diff"
    elif str(case.get("category")) in {"routing", "adversarial", "repair_loop", "intent_recall", "multi_backend"}:
        derivation = "extended_category"
    return {
        "schema_version": "formal_pr_bench.case_provenance.v1",
        "case_id": case_id,
        "source": source_file or "benchmarks/formal_pr_bench",
        "author": "fraware",
        "date": "2026-07-25",
        "derivation": derivation,
        "partition": partition,
        "template_dev": template_dev,
        "fixture": fixture,
        "category": case.get("category", "lane"),
        "license": "Apache-2.0",
        "notes": (
            "Case used during property-template development; forbidden from held-out scoring."
            if template_dev
            else "Evaluation/regression case; cite benchmark_version + partition when publishing scores."
        ),
    }


def rationale_markdown(case_id: str, case: dict[str, Any], *, partition: str) -> str:
    expected = (
        case.get("expected_merge_recommendation")
        or case.get("expected_status")
        or case.get("expected_backend")
        or case.get("expected_quality_passed")
    )
    lines = [
        f"# Rationale: `{case_id}`",
        "",
        f"- Partition: `{partition}`",
        f"- Category: `{case.get('category', 'lane')}`",
        f"- Expected decision signal: `{expected}`",
        "",
        "## Why this expectation",
        "",
    ]
    category = str(case.get("category", "lane"))
    if category == "real_diff":
        lines.append(
            "End-to-end `ovk check` on a sanitized agent-style PR diff must recall the listed "
            "intents/lanes and emit the expected merge recommendation."
        )
    elif category == "routing":
        lines.append("Changed-file surfaces must select the expected backend from the capability registry.")
    elif category == "adversarial":
        lines.append("Tampered or inconsistent evidence bundles must fail the evidence-quality gate.")
    elif category == "repair_loop":
        lines.append("Failing input must block with a useful repair hint; the passing fixture must allow.")
    elif category == "intent_recall":
        lines.append("The planner must recall every expected intent from the diff fixture.")
    elif category == "multi_backend":
        lines.append("Multi-surface PRs must exercise multiple lanes and match the merge recommendation.")
    else:
        lines.append(
            "Lane fixture status and merge recommendation must match the declared expectations, "
            "including counterexample class when present."
        )
    lines.extend(["", "## Non-claims", "", "This case does not claim complete application security or solver completeness.", ""])
    return "\n".join(lines)


def write_mutations(cases: dict[str, dict[str, Any]]) -> list[str]:
    """Emit a small controlled mutation set derived from seed fixtures."""
    MUTATIONS_DIR.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    specs = [
        ("control_removed", "flip_merge_to_allow", {"expected_merge_recommendation": "allow"}),
        ("auth_bypass", "drop_counterexample", {"expected_counterexample_class": None}),
        ("ci_secrets_exposed", "status_to_pass", {"expected_status": "pass", "expected_merge_recommendation": "allow"}),
    ]
    for base_id, mutation_id, overrides in specs:
        if base_id not in cases:
            continue
        base = dict(cases[base_id])
        base.pop("_source_file", None)
        mutated = {
            "schema_version": "formal_pr_bench.mutation.v1",
            "mutation_id": f"{base_id}__{mutation_id}",
            "base_case_id": base_id,
            "mutation": mutation_id,
            "description": "Controlled expectation mutation for contamination/robustness tests; not a scored corpus member.",
            "base_case": base,
            "overrides": overrides,
            "mutated_expectations": {**{k: base.get(k) for k in overrides}, **overrides},
        }
        path = MUTATIONS_DIR / f"{base_id}__{mutation_id}.json"
        _write_json(path, mutated)
        written.append(path.name)
    return written


def write_adversarial() -> list[str]:
    """Emit misleading diffs that look documentation-only or safe but should not be treated as held-out truth."""
    ADVERSARIAL_DIR.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    misleading_docs = """diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1,3 +1,4 @@
 # Example Repo
 
 Documentation update only.
+Also tweaks CI below (see workflow).
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -10,6 +10,8 @@ jobs:
     steps:
       - uses: actions/checkout@v4
+      - name: Preview
+        run: echo ${{ secrets.PROD_TOKEN }}
"""
    path = ADVERSARIAL_DIR / "misleading_docs_hides_secret.diff"
    path.write_text(misleading_docs, encoding="utf-8")
    written.append(path.name)

    meta = {
        "schema_version": "formal_pr_bench.adversarial.v1",
        "adversarial_id": "misleading_docs_hides_secret",
        "diff": "misleading_docs_hides_secret.diff",
        "intended_trap": "Looks like a docs-only PR in the commit message/path mix but injects an untrusted secret use.",
        "expected_merge_recommendation": "block",
        "expected_lanes": ["ci_secrets", "self_protection"],
        "not_held_out": True,
        "notes": "Adversarial fixture for robustness; must not be counted as held-out evaluation.",
    }
    meta_path = ADVERSARIAL_DIR / "misleading_docs_hides_secret.json"
    _write_json(meta_path, meta)
    written.append(meta_path.name)

    forged_allow = {
        "schema_version": "formal_pr_bench.adversarial.v1",
        "adversarial_id": "forged_allow_label",
        "description": "Case metadata claims allow while pointing at a known-failing auth bypass fixture.",
        "input_fixture": "examples/auth_regression/input_admin_bypass.json",
        "claimed_expected_merge_recommendation": "allow",
        "actual_expected_merge_recommendation": "block",
        "intended_trap": "Trusting attacker-supplied expected labels without fixture evaluation.",
        "not_held_out": True,
    }
    forged_path = ADVERSARIAL_DIR / "forged_allow_label.json"
    _write_json(forged_path, forged_allow)
    written.append(forged_path.name)
    return written


def write_held_out_descriptors(cases: dict[str, dict[str, Any]], held_out_ids: list[str]) -> None:
    HELD_OUT_DIR.mkdir(parents=True, exist_ok=True)
    for case_id in held_out_ids:
        case = dict(cases[case_id])
        case.pop("_source_file", None)
        _write_json(
            HELD_OUT_DIR / f"{case_id}.json",
            {
                "schema_version": "formal_pr_bench.held_out.v1",
                "case_id": case_id,
                "forbidden_from_template_dev_scoring": True,
                "case": case,
            },
        )
    readme = HELD_OUT_DIR / "README.md"
    readme.write_text(
        "\n".join(
            [
                "# FormalPR-Bench held-out cases",
                "",
                "Cases in this directory belong to the `held_out` partition.",
                "They must not be used during property-template development scoring.",
                "",
                "Contamination between `template_dev_cases.json` and this partition fails CI.",
                "See [docs/HOLDOUT_LABEL_SEPARATION.md](../../../docs/HOLDOUT_LABEL_SEPARATION.md) and",
                "[docs/FORMALPR_HOLDOUT_GOVERNANCE.md](../../../docs/FORMALPR_HOLDOUT_GOVERNANCE.md).",
                "",
            ]
        ),
        encoding="utf-8",
    )


def generate() -> dict[str, Any]:
    real_diff_count = sync_real_diff_cases()
    cases = load_all_cases()
    seed_ids = {
        str(case["case_id"])
        for case in load_json(SEED_CASES).get("cases", [])
    }
    template_dev_payload = {
        "schema_version": "formal_pr_bench.template_dev.v1",
        "benchmark_version": BENCHMARK_VERSION,
        "description": (
            "Cases whose fixtures informed property-template development. "
            "These must never be counted as held-out evaluation."
        ),
        "case_ids": sorted(seed_ids),
    }
    _write_json(TEMPLATE_DEV_PATH, template_dev_payload)

    partitions_map = assign_partitions(cases, seed_ids)
    membership = {case_id: name for name, ids in partitions_map.items() for case_id in ids}
    partitions_payload = {
        "schema_version": "formal_pr_bench.partitions.v1",
        "benchmark_version": BENCHMARK_VERSION,
        "partitions": partitions_map,
        "counts": {name: len(partitions_map[name]) for name in PARTITIONS},
    }
    _write_json(PARTITIONS_PATH, partitions_payload)

    licenses_payload = {
        "schema_version": "formal_pr_bench.licenses.v1",
        "benchmark_version": BENCHMARK_VERSION,
        "corpus_license": "Apache-2.0",
        "corpus_license_file": "LICENSE",
        "default_case_license": "Apache-2.0",
        "cases": {
            case_id: {
                "license": "Apache-2.0",
                "copyright": "Copyright 2026 fraware",
                "source": case.get("_source_file"),
            }
            for case_id, case in sorted(cases.items())
        },
    }
    _write_json(LICENSES_PATH, licenses_payload)

    duplication = build_duplication_report(cases)
    _write_json(DUPLICATION_REPORT_PATH, duplication)

    PROVENANCE_DIR.mkdir(parents=True, exist_ok=True)
    RATIONALES_DIR.mkdir(parents=True, exist_ok=True)
    for case_id, case in cases.items():
        partition = membership[case_id]
        record = provenance_record(case_id, case, template_dev=case_id in seed_ids, partition=partition)
        _write_json(PROVENANCE_DIR / f"{case_id}.json", record)
        (RATIONALES_DIR / f"{case_id}.md").write_text(
            rationale_markdown(case_id, case, partition=partition),
            encoding="utf-8",
        )

    write_held_out_descriptors(cases, partitions_map["held_out"])
    mutations = write_mutations(cases)
    adversarial = write_adversarial()

    manifest = build_version_manifest(
        partitions=partitions_payload,
        case_count=len(cases),
        licenses_digest=sha256_hex(licenses_payload),
        duplication_digest=sha256_hex(duplication),
    )
    manifest["real_diff_case_count"] = real_diff_count
    manifest["mutation_files"] = mutations
    manifest["adversarial_files"] = adversarial
    _write_json(MANIFEST_PATH, manifest)
    return {
        "case_count": len(cases),
        "real_diff_case_count": real_diff_count,
        "counts": partitions_payload["counts"],
        "manifest": str(MANIFEST_PATH.relative_to(ROOT)).replace("\\", "/"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate FormalPR-Bench provenance artifacts")
    parser.parse_args()
    summary = generate()
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
