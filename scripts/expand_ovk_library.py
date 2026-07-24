#!/usr/bin/env python
"""Expand template library and FormalPR-Bench seed cases for v1 readiness."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "templates"
BENCH = ROOT / "benchmarks/formal_pr_bench/seed_cases.json"
BENCH_EXPANDED = ROOT / "benchmarks/formal_pr_bench/seed_cases_expanded.json"

DOMAIN_CONFIG: dict[str, dict[str, Any]] = {
    "authorization": {
        "kinds": ["access_control", "safety", "invariant"],
        "failure_modes": [
            "middleware_skipped",
            "route_group_unprotected",
            "policy_default_allow",
            "role_check_removed",
        ],
        "evidence": [
            {"kind": "policy_check", "minimum_confidence": "medium"},
            {"kind": "smt_counterexample", "minimum_confidence": "medium"},
        ],
        "severity": "high",
    },
    "infrastructure": {
        "kinds": ["forbidden_configuration", "data_boundary", "invariant"],
        "failure_modes": ["public_exposure", "missing_encryption", "overly_permissive_sg"],
        "evidence": [
            {"kind": "policy_check", "minimum_confidence": "medium"},
            {"kind": "topology_model", "minimum_confidence": "medium"},
        ],
        "severity": "high",
    },
    "ci_cd": {
        "kinds": ["safety", "forbidden_configuration", "data_boundary"],
        "failure_modes": ["secret_in_untrusted_context", "workflow_permission_escalation"],
        "evidence": [
            {"kind": "policy_check", "minimum_confidence": "medium"},
            {"kind": "generated_regression_test", "minimum_confidence": "medium"},
        ],
        "severity": "critical",
    },
    "deployment": {
        "kinds": ["invariant", "liveness", "safety"],
        "failure_modes": ["skipped_approval", "invalid_state_transition", "rollback_bypass"],
        "evidence": [
            {"kind": "model_check", "minimum_confidence": "medium"},
            {"kind": "trace", "minimum_confidence": "medium"},
        ],
        "severity": "high",
    },
    "data_boundary": {
        "kinds": ["data_boundary", "safety", "invariant"],
        "failure_modes": ["cross_tenant_leak", "buffer_overflow", "type_escape"],
        "evidence": [
            {"kind": "smt_counterexample", "minimum_confidence": "medium"},
            {"kind": "memory_model", "minimum_confidence": "medium"},
        ],
        "severity": "high",
    },
    "agent_authority": {
        "kinds": ["invariant", "access_control", "runtime_monitorable"],
        "failure_modes": ["self_approval", "gate_removal", "bot_bypass"],
        "evidence": [
            {"kind": "policy_check", "minimum_confidence": "high"},
            {"kind": "generated_regression_test", "minimum_confidence": "medium"},
        ],
        "severity": "critical",
    },
}

DOMAINS = list(DOMAIN_CONFIG.keys())

CURATED_TEMPLATES: list[dict[str, Any]] = [
    {
        "path": "authorization/rust_kani_bounds_check.intent.json",
        "payload": {
            "intent_id": "rust-kani-bounds-check",
            "version": "0.1.0",
            "domain": "authorization",
            "title": "Rust Kani bounds check",
            "description": "Unsafe Rust changes must not introduce out-of-bounds memory access on privileged paths.",
            "scope": {"files": ["**/*.rs", "**/Cargo.toml"]},
            "property": {
                "kind": "safety",
                "natural_language": "Array and pointer accesses in changed Rust code remain within declared bounds.",
                "formal_hint": "forall i. 0 <= i < len(arr) implies safe_access(arr, i)",
            },
            "failure_modes": ["buffer_overflow", "unchecked_index", "raw_pointer_deref"],
            "acceptable_evidence": [
                {"kind": "model_check", "minimum_confidence": "high"},
                {"kind": "smt_counterexample", "minimum_confidence": "medium"},
            ],
            "risk": {
                "severity": "critical",
                "likelihood": "medium",
                "rationale": "Memory safety regressions in auth paths are exploitable.",
            },
            "merge_policy": {"on_pass": "allow", "on_fail": "block", "on_unknown": "require_human_review"},
            "provenance": {"source": "ovk-template-library", "canonical": True},
        },
    },
    {
        "path": "authorization/cedar_iam_admin_deny.intent.json",
        "payload": {
            "intent_id": "cedar-iam-admin-deny",
            "version": "0.1.0",
            "domain": "authorization",
            "title": "Cedar IAM admin deny",
            "description": "IAM policy changes must not grant admin actions to unprivileged principals.",
            "scope": {"files": ["**/*policy*", "**/iam/**", "**/*.cedar"]},
            "property": {
                "kind": "access_control",
                "natural_language": "Non-admin principals must not be permitted admin IAM actions after the change.",
            },
            "failure_modes": ["policy_default_allow", "wildcard_principal", "privilege_escalation"],
            "acceptable_evidence": [{"kind": "policy_check", "minimum_confidence": "high"}],
            "risk": {
                "severity": "critical",
                "likelihood": "medium",
                "rationale": "IAM regressions expose cloud control planes.",
            },
            "merge_policy": {"on_pass": "allow", "on_fail": "block", "on_unknown": "require_human_review"},
            "provenance": {"source": "ovk-template-library", "canonical": True},
        },
    },
    {
        "path": "infrastructure/alloy_topology_reachability.intent.json",
        "payload": {
            "intent_id": "alloy-topology-reachability",
            "version": "0.1.0",
            "domain": "infrastructure",
            "title": "Alloy topology reachability",
            "description": "Network topology changes must not create unintended paths from public ingress to sensitive tiers.",
            "scope": {"files": ["**/*.alloy", "**/network/**", "**/*.tf"]},
            "property": {
                "kind": "invariant",
                "natural_language": "No public ingress may reach a sensitive data tier without explicit policy.",
            },
            "failure_modes": ["public_exposure", "lateral_movement_path"],
            "acceptable_evidence": [{"kind": "topology_model", "minimum_confidence": "medium"}],
            "risk": {
                "severity": "high",
                "likelihood": "medium",
                "rationale": "Topology regressions enable data exfiltration.",
            },
            "merge_policy": {"on_pass": "allow", "on_fail": "block", "on_unknown": "require_human_review"},
            "provenance": {"source": "ovk-template-library", "canonical": True},
        },
    },
    {
        "path": "deployment/tla_approval_state_machine.intent.json",
        "payload": {
            "intent_id": "tla-approval-state-machine",
            "version": "0.1.0",
            "domain": "deployment",
            "title": "TLA approval state machine",
            "description": "Deployment workflows must preserve required approval states before production promotion.",
            "scope": {"files": ["**/*.tla", "**/deploy/**", "**/.github/workflows/**"]},
            "property": {
                "kind": "invariant",
                "natural_language": "Production promotion is unreachable without passing through required approval states.",
            },
            "failure_modes": ["skipped_approval", "invalid_state_transition"],
            "acceptable_evidence": [{"kind": "model_check", "minimum_confidence": "high"}],
            "risk": {
                "severity": "high",
                "likelihood": "medium",
                "rationale": "Skipped approvals enable unreviewed production changes.",
            },
            "merge_policy": {"on_pass": "allow", "on_fail": "block", "on_unknown": "require_human_review"},
            "provenance": {"source": "ovk-template-library", "canonical": True},
        },
    },
    {
        "path": "data_boundary/cbmc_buffer_bounds.intent.json",
        "payload": {
            "intent_id": "cbmc-buffer-bounds",
            "version": "0.1.0",
            "domain": "data_boundary",
            "title": "CBMC buffer bounds",
            "description": "Native code touching sensitive buffers must remain within allocated bounds.",
            "scope": {"files": ["**/*.c", "**/*.h", "**/*.cpp"]},
            "property": {
                "kind": "data_boundary",
                "natural_language": "Buffer reads and writes stay within allocated memory for sensitive data paths.",
            },
            "failure_modes": ["buffer_overflow", "use_after_free"],
            "acceptable_evidence": [{"kind": "memory_model", "minimum_confidence": "high"}],
            "risk": {
                "severity": "critical",
                "likelihood": "low",
                "rationale": "Memory corruption can leak cross-tenant data.",
            },
            "merge_policy": {"on_pass": "allow", "on_fail": "block", "on_unknown": "require_human_review"},
            "provenance": {"source": "ovk-template-library", "canonical": True},
        },
    },
    {
        "path": "agent_authority/opa_self_approval_block.intent.json",
        "payload": {
            "intent_id": "opa-self-approval-block",
            "version": "0.1.0",
            "domain": "agent_authority",
            "title": "OPA self-approval block",
            "description": "Bot-authored PRs must not remove or bypass required verification gates.",
            "scope": {"files": ["**/.github/**", "**/CODEOWNERS"]},
            "property": {
                "kind": "runtime_monitorable",
                "natural_language": "Required branch protection checks remain enforced for bot actors.",
            },
            "failure_modes": ["self_approval", "gate_removal", "bot_bypass"],
            "acceptable_evidence": [{"kind": "policy_check", "minimum_confidence": "high"}],
            "risk": {
                "severity": "critical",
                "likelihood": "high",
                "rationale": "Agents must not weaken their own verification gates.",
            },
            "merge_policy": {"on_pass": "allow", "on_fail": "block", "on_unknown": "require_human_review"},
            "provenance": {"source": "ovk-template-library", "canonical": True},
        },
    },
    {
        "path": "ci_cd/z3_secret_flow_check.intent.json",
        "payload": {
            "intent_id": "z3-secret-flow-check",
            "version": "0.1.0",
            "domain": "ci_cd",
            "title": "Z3 secret flow check",
            "description": "CI workflow changes must not route secrets into untrusted execution contexts.",
            "scope": {"files": ["**/.github/workflows/**", "**/gitlab-ci.yml"]},
            "property": {
                "kind": "data_boundary",
                "natural_language": "Secrets are not reachable from untrusted workflow triggers or fork PR contexts.",
            },
            "failure_modes": ["secret_in_untrusted_context", "workflow_permission_escalation"],
            "acceptable_evidence": [{"kind": "smt_counterexample", "minimum_confidence": "medium"}],
            "risk": {
                "severity": "critical",
                "likelihood": "medium",
                "rationale": "Secret exposure in CI is a common agent regression.",
            },
            "merge_policy": {"on_pass": "allow", "on_fail": "block", "on_unknown": "require_human_review"},
            "provenance": {"source": "ovk-template-library", "canonical": True},
        },
    },
    {
        "path": "authorization/cedar_cross_account_deny.intent.json",
        "payload": {
            "intent_id": "cedar-cross-account-deny",
            "version": "0.1.0",
            "domain": "authorization",
            "title": "Cedar cross-account deny",
            "description": "Policy changes must not allow cross-account access to protected resources.",
            "property": {
                "kind": "access_control",
                "natural_language": "External accounts cannot access protected resources without explicit trust.",
            },
            "failure_modes": ["cross_account_trust", "resource_policy_wildcard"],
            "acceptable_evidence": [{"kind": "policy_check", "minimum_confidence": "high"}],
            "risk": {
                "severity": "high",
                "likelihood": "medium",
                "rationale": "Cross-account leaks expand blast radius.",
            },
            "merge_policy": {"on_pass": "allow", "on_fail": "block", "on_unknown": "require_human_review"},
            "provenance": {"source": "ovk-template-library", "canonical": True},
        },
    },
    {
        "path": "infrastructure/memory_safe_config.intent.json",
        "payload": {
            "intent_id": "memory-safe-config",
            "version": "0.1.0",
            "domain": "infrastructure",
            "title": "Memory-safe configuration",
            "description": "Infrastructure config must not disable memory or encryption safeguards on sensitive tiers.",
            "property": {
                "kind": "forbidden_configuration",
                "natural_language": "Sensitive tiers retain required encryption and isolation settings.",
            },
            "failure_modes": ["missing_encryption", "overly_permissive_sg"],
            "acceptable_evidence": [{"kind": "policy_check", "minimum_confidence": "medium"}],
            "risk": {"severity": "high", "likelihood": "low", "rationale": "Misconfiguration can expose data at rest."},
            "merge_policy": {"on_pass": "allow", "on_fail": "block", "on_unknown": "require_human_review"},
            "provenance": {"source": "ovk-template-library", "canonical": True},
        },
    },
    {
        "path": "deployment/tla_rollback_safety.intent.json",
        "payload": {
            "intent_id": "tla-rollback-safety",
            "version": "0.1.0",
            "domain": "deployment",
            "title": "TLA rollback safety",
            "description": "Rollback paths must not skip safety checks or leave the system in an invalid state.",
            "property": {
                "kind": "safety",
                "natural_language": "Rollback transitions preserve deployment safety invariants.",
            },
            "failure_modes": ["rollback_bypass", "invalid_state_transition"],
            "acceptable_evidence": [{"kind": "model_check", "minimum_confidence": "medium"}],
            "risk": {
                "severity": "high",
                "likelihood": "low",
                "rationale": "Unsafe rollbacks can reintroduce known failures.",
            },
            "merge_policy": {"on_pass": "allow", "on_fail": "block", "on_unknown": "require_human_review"},
            "provenance": {"source": "ovk-template-library", "canonical": True},
        },
    },
    {
        "path": "data_boundary/lean_type_safety.intent.json",
        "payload": {
            "intent_id": "lean-type-safety",
            "version": "0.1.0",
            "domain": "data_boundary",
            "title": "Lean type safety",
            "description": "Proof-bearing code changes must preserve type-level data boundary invariants.",
            "property": {
                "kind": "invariant",
                "natural_language": "Sensitive data types remain separated at the type level after the change.",
            },
            "failure_modes": ["type_escape", "unsound_cast"],
            "acceptable_evidence": [{"kind": "proof", "minimum_confidence": "high"}],
            "risk": {"severity": "high", "likelihood": "low", "rationale": "Type escapes can void formal guarantees."},
            "merge_policy": {"on_pass": "allow", "on_fail": "block", "on_unknown": "require_human_review"},
            "provenance": {"source": "ovk-template-library", "canonical": True},
        },
    },
    {
        "path": "agent_authority/dafny_authority_invariant.intent.json",
        "payload": {
            "intent_id": "dafny-authority-invariant",
            "version": "0.1.0",
            "domain": "agent_authority",
            "title": "Dafny authority invariant",
            "description": "Agent authority modules must preserve non-escalation invariants across changes.",
            "property": {
                "kind": "invariant",
                "natural_language": "Agent actions cannot escalate authority beyond the declared envelope.",
            },
            "failure_modes": ["privilege_escalation", "self_approval"],
            "acceptable_evidence": [{"kind": "proof", "minimum_confidence": "high"}],
            "risk": {
                "severity": "critical",
                "likelihood": "medium",
                "rationale": "Authority escalation enables autonomous harm.",
            },
            "merge_policy": {"on_pass": "allow", "on_fail": "block", "on_unknown": "require_human_review"},
            "provenance": {"source": "ovk-template-library", "canonical": True},
        },
    },
    {
        "path": "ci_cd/verus_build_integrity.intent.json",
        "payload": {
            "intent_id": "verus-build-integrity",
            "version": "0.1.0",
            "domain": "ci_cd",
            "title": "Verus build integrity",
            "description": "CI changes must not weaken verified-build gates for release artifacts.",
            "property": {
                "kind": "safety",
                "natural_language": "Release pipelines retain verified-build requirements for protected artifacts.",
            },
            "failure_modes": ["gate_removal", "unsigned_artifact_publish"],
            "acceptable_evidence": [{"kind": "proof", "minimum_confidence": "medium"}],
            "risk": {
                "severity": "high",
                "likelihood": "medium",
                "rationale": "Weakened build gates enable supply-chain regressions.",
            },
            "merge_policy": {"on_pass": "allow", "on_fail": "block", "on_unknown": "require_human_review"},
            "provenance": {"source": "ovk-template-library", "canonical": True},
        },
    },
    {
        "path": "authorization/no_privilege_escalation_cedar.intent.json",
        "payload": {
            "intent_id": "no-privilege-escalation-cedar",
            "version": "0.1.0",
            "domain": "authorization",
            "title": "No privilege escalation (Cedar)",
            "description": "Authorization policy edits must not grant new privileges without explicit intent.",
            "property": {
                "kind": "access_control",
                "natural_language": "Principals cannot gain permissions they did not hold before the change.",
            },
            "failure_modes": ["privilege_escalation", "policy_default_allow"],
            "acceptable_evidence": [{"kind": "policy_check", "minimum_confidence": "high"}],
            "risk": {
                "severity": "critical",
                "likelihood": "medium",
                "rationale": "Privilege escalation is a primary auth regression class.",
            },
            "merge_policy": {"on_pass": "allow", "on_fail": "block", "on_unknown": "require_human_review"},
            "provenance": {"source": "ovk-template-library", "canonical": True},
        },
    },
    {
        "path": "infrastructure/no_public_egress_alloy.intent.json",
        "payload": {
            "intent_id": "no-public-egress-alloy",
            "version": "0.1.0",
            "domain": "infrastructure",
            "title": "No public egress (Alloy)",
            "description": "Sensitive workloads must not gain unrestricted public egress without review.",
            "property": {
                "kind": "forbidden_configuration",
                "natural_language": "Sensitive tiers do not route traffic to unrestricted public egress.",
            },
            "failure_modes": ["public_exposure", "lateral_movement_path"],
            "acceptable_evidence": [{"kind": "topology_model", "minimum_confidence": "medium"}],
            "risk": {
                "severity": "high",
                "likelihood": "medium",
                "rationale": "Public egress from sensitive tiers enables exfiltration.",
            },
            "merge_policy": {"on_pass": "allow", "on_fail": "block", "on_unknown": "require_human_review"},
            "provenance": {"source": "ovk-template-library", "canonical": True},
        },
    },
]

BASE_CASES = json.loads(BENCH.read_text(encoding="utf-8"))["cases"]


def write_curated_templates(*, dry_run: bool = False) -> int:
    """Write hand-authored curated templates that do not yet exist."""
    created = 0
    for entry in CURATED_TEMPLATES:
        path = TEMPLATES / entry["path"]
        if path.exists():
            continue
        if dry_run:
            created += 1
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(entry["payload"], indent=2) + "\n", encoding="utf-8")
        created += 1
    return created


def expand_templates(target: int = 100, *, dry_run: bool = False) -> int:
    """Expand generated templates until the library reaches *target*."""
    write_curated_templates(dry_run=dry_run)
    created = 0
    index = 1
    while len(list(TEMPLATES.rglob("*.intent.json"))) < target:
        domain = DOMAINS[index % len(DOMAINS)]
        config = DOMAIN_CONFIG[domain]
        kind = config["kinds"][index % len(config["kinds"])]
        intent_id = f"{domain.replace('_', '-')}-guard-{index}"
        filename = intent_id.replace("-", "_") + ".intent.json"
        path = TEMPLATES / domain / filename
        if path.exists():
            index += 1
            continue
        payload = {
            "intent_id": intent_id,
            "version": "0.1.0",
            "domain": domain,
            "title": intent_id.replace("-", " ").title(),
            "description": f"Generated guard for {domain} surface {index} covering {kind} properties.",
            "property": {
                "kind": kind,
                "natural_language": f"Changed {domain} artifacts must preserve {kind} obligations for surface {index}.",
            },
            "failure_modes": list(config["failure_modes"]),
            "acceptable_evidence": list(config["evidence"]),
            "risk": {
                "severity": config["severity"],
                "likelihood": "low" if index % 3 else "medium",
                "rationale": f"Generated guard for {domain} surface {index}.",
            },
            "merge_policy": {
                "on_pass": "allow",
                "on_fail": "block",
                "on_unknown": "require_human_review",
            },
            "provenance": {"source": "ovk-template-library", "generated": True},
        }
        if dry_run:
            created += 1
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
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
    parser = argparse.ArgumentParser(description="Expand OVK template library and benchmark seeds")
    parser.add_argument("--template-target", type=int, default=100, help="Target template count")
    parser.add_argument("--dry-run", action="store_true", help="Report counts without writing files")
    args = parser.parse_args()
    templates_created = expand_templates(target=args.template_target, dry_run=args.dry_run)
    bench_created = 0 if args.dry_run else expand_benchmark()
    print(f"created {templates_created} templates and {bench_created} benchmark variants")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
