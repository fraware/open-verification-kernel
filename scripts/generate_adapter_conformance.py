#!/usr/bin/env python
"""One-shot generator for OVK-PR4 adapter conformance fixtures and manifests.

Safe to re-run: overwrites generated conformance trees and missing example fixtures.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKENDS = ROOT / "examples" / "adapters_backends_placeholder"
EXAMPLES = ROOT / "examples" / "backends"

# Formal backend fixture specs: intent_id + case payloads.
FORMAL = {
    "opa": {
        "checker_id": "opa",
        "dir": "opa",
        "pass": {"intent_id": "opa-policy-check", "status": "pass", "violations": []},
        "fail": {
            "intent_id": "opa-policy-check",
            "status": "fail",
            "violations": ["required ovk gate removed from branch protection"],
        },
        "malformed": {"intent_id": "opa-policy-check", "malformed": True},
        "timeout": {"intent_id": "opa-policy-check", "timeout": True},
        "unavailable": {"intent_id": "opa-policy-check", "binary_unavailable": True},
        "pass_establishes": (
            "The supplied structured input satisfies the selected OPA/Rego policy "
            "under the adapter's data model for this fixture."
        ),
        "outside_claim": (
            "Does not prove correctness of arbitrary program execution, workflow "
            "semantics beyond the policy, or properties outside the selected Rego rules."
        ),
    },
    "z3": {
        "checker_id": "z3",
        "dir": "z3",
        "pass_path": "examples/auth_regression/input_admin_protected.json",
        "fail_path": "examples/auth_regression/input_admin_bypass.json",
        "malformed_path": "examples/auth_regression/input_malformed_missing_routes.json",
        "timeout": {"timeout": True, "author_type": "ai_agent", "agent": "codex", "task": "timeout"},
        "unavailable": {
            "binary_unavailable": True,
            "author_type": "ai_agent",
            "agent": "codex",
            "task": "unavailable",
        },
        "pass_establishes": (
            "No counterexample was found for the encoded authorization obligation "
            "(or the query polarity recorded in the obligation was satisfied)."
        ),
        "outside_claim": (
            "Does not prove properties outside the finite abstraction, unsupported "
            "theories, or middleware behavior absent from the route encoding."
        ),
    },
    "cbmc": {
        "checker_id": "cbmc",
        "dir": "cbmc",
        "pass_path": "examples/backends/cbmc_pass.json",
        "fail_path": "examples/backends/cbmc_fail.json",
        "malformed": {"intent_id": "cbmc-harness-check", "malformed": True},
        "timeout": {"intent_id": "cbmc-harness-check", "timeout": True},
        "unavailable": {"intent_id": "cbmc-harness-check", "binary_unavailable": True},
        "pass_establishes": (
            "Bounded model checking of the supplied harness found no assertion "
            "violations within the stated unwind and memory bounds."
        ),
        "outside_claim": (
            "Bounded only; does not prove unbounded safety, and synthetic harnesses "
            "do not compile changed project source into the checked model unless "
            "an explicit harness is supplied."
        ),
    },
    "cedar": {
        "checker_id": "cedar",
        "dir": "cedar",
        "pass_path": "examples/backends/cedar_pass.json",
        "fail_path": "examples/backends/cedar_fail.json",
        "malformed_path": "examples/backends/cedar_malformed.json",
        "timeout": {"intent_id": "cedar-policy-check", "timeout": True},
        "unavailable": {"intent_id": "cedar-policy-check", "binary_unavailable": True},
        "pass_establishes": (
            "The deterministic Cedar-shaped policy oracle reported no violations "
            "for the supplied authorization fixture."
        ),
        "outside_claim": (
            "Native Cedar policy evaluation is not implemented; does not verify "
            "runtime middleware behavior."
        ),
    },
    "tla+": {
        "checker_id": "tla+",
        "dir": "tla",
        "pass_path": "examples/backends/tla_pass.json",
        "fail_path": "examples/backends/tla_fail.json",
        "malformed_path": "examples/backends/tla_malformed.json",
        "timeout": {"intent_id": "tla-state-check", "timeout": True},
        "unavailable": {"intent_id": "tla-state-check", "binary_unavailable": True},
        "pass_establishes": (
            "The deterministic TLA+/state-machine oracle found no skipped required "
            "approval states for the supplied fixture."
        ),
        "outside_claim": (
            "TLC execution is not implemented; does not prove liveness or properties "
            "outside the supplied finite state machine."
        ),
    },
    "kani": {
        "checker_id": "kani",
        "dir": "kani",
        "pass_path": "examples/backends/kani_pass.json",
        "fail_path": "examples/backends/kani_fail.json",
        "malformed_path": "examples/backends/kani_malformed.json",
        "timeout": {"intent_id": "kani-harness-check", "timeout": True},
        "unavailable": {"intent_id": "kani-harness-check", "binary_unavailable": True},
        "pass_establishes": (
            "The deterministic Kani-shaped harness oracle reported no memory-safety "
            "or policy violations for the supplied fixture."
        ),
        "outside_claim": (
            "Native Kani execution is not implemented; does not verify arbitrary Rust "
            "beyond the fixture oracle."
        ),
    },
    "dafny": {
        "checker_id": "dafny",
        "dir": "dafny",
        "pass_path": "examples/backends/dafny_pass.json",
        "fail_path": "examples/backends/dafny_fail.json",
        "malformed": {"intent_id": "dafny-obligation-check", "malformed": True},
        "timeout": {"intent_id": "dafny-obligation-check", "timeout": True},
        "unavailable": {"intent_id": "dafny-obligation-check", "binary_unavailable": True},
        "pass_establishes": (
            "The deterministic Dafny obligation oracle reported all listed obligations "
            "as proved for the supplied fixture."
        ),
        "outside_claim": (
            "Native Dafny verification is not implemented; does not establish proofs "
            "for code outside the fixture obligations."
        ),
    },
    "verus": {
        "checker_id": "verus",
        "dir": "verus",
        "pass_path": "examples/backends/verus_pass.json",
        "fail_path": "examples/backends/verus_fail.json",
        "malformed": {"intent_id": "verus-harness-check", "malformed": True},
        "timeout": {"intent_id": "verus-harness-check", "timeout": True},
        "unavailable": {"intent_id": "verus-harness-check", "binary_unavailable": True},
        "pass_establishes": (
            "The deterministic Verus harness oracle reported all listed obligations "
            "as proved for the supplied fixture."
        ),
        "outside_claim": (
            "Native Verus verification is not implemented; does not prove properties "
            "outside the fixture harness."
        ),
    },
    "lean": {
        "checker_id": "lean",
        "dir": "lean",
        "pass_path": "examples/backends/lean_pass.json",
        "fail_path": "examples/backends/lean_fail.json",
        "malformed": {"intent_id": "lean-proof-check", "malformed": True},
        "timeout": {"intent_id": "lean-proof-check", "timeout": True},
        "unavailable": {"intent_id": "lean-proof-check", "binary_unavailable": True},
        "pass_establishes": (
            "The deterministic Lean proof oracle reported all listed obligations as "
            "proved for the supplied fixture."
        ),
        "outside_claim": (
            "Native Lean checking is not implemented; does not establish theorems "
            "outside the fixture obligations."
        ),
    },
    "alloy": {
        "checker_id": "alloy",
        "dir": "alloy",
        "pass_path": "examples/backends/alloy_pass.json",
        "fail_path": "examples/backends/alloy_fail.json",
        "malformed": {"intent_id": "alloy-model-check", "malformed": True},
        "timeout": {"intent_id": "alloy-model-check", "timeout": True},
        "unavailable": {"intent_id": "alloy-model-check", "binary_unavailable": True},
        "pass_establishes": (
            "The deterministic Alloy model oracle reported no counterexample instances "
            "for the supplied fixture."
        ),
        "outside_claim": (
            "Native Alloy analysis is not implemented; does not prove properties "
            "outside the fixture model scope."
        ),
    },
}

LANES = {
    "lane-self-protection": {
        "pass_path": "examples/no_agent_self_approval/input_gate_preserved.json",
        "fail_path": "examples/no_agent_self_approval/input_gate_removed.json",
        "malformed": {
            "malformed": True,
            "actor": {"type": "ai_agent", "id": "codex"},
            "task": "malformed",
            "ovk_gate_name": "ovk-verify",
            "changed_files": [],
            "before": {"required_checks": []},
            "after": {"required_checks": []},
        },
        "timeout": {"timeout": True},
        "unavailable": {"binary_unavailable": True},
        "capability": {
            "capability_id": "lane-self-protection-v1",
            "checker_id": "lane-self-protection",
            "version": "0.1.0",
            "implementation": "ovk-adapter-lane-self-protection",
            "input_contract": "Self-protection lane input (actor/before/after required checks).",
            "output_contract": "ovk.evidence via self_protection lane evaluator",
            "claim_class": "policy_evaluation",
            "tool": {
                "name": "lane-self-protection",
                "adapter": "ovk-adapter-lane-self-protection",
                "adapter_version": "0.1.0",
            },
            "backend_class": "policy_engine",
            "supported_domains": ["ci_cd", "agent_authority"],
            "supported_property_kinds": ["safety", "forbidden_configuration"],
            "guarantee": {
                "type": "policy_evaluation",
                "meaning_of_pass": "Required OVK gate remains in branch protection after the change.",
                "meaning_of_fail": "The change removes or weakens the required OVK gate.",
                "meaning_of_unknown": "Materials were incomplete or the checker could not decide.",
            },
            "assumptions": [
                "Branch-protection metadata faithfully represents repository policy.",
            ],
            "trusted_components": [
                "self-protection lane evaluator",
                "optional OPA native path",
            ],
            "limits": ["Does not prove semantic correctness of unrelated workflow steps."],
            "failure_semantics": "Missing or malformed materials map to unknown; evaluator errors map to error.",
            "timeout_semantics": "unknown",
            "unsupported_semantics": "Does not analyze checks outside the declared OVK gate name.",
            "determinism_status": "deterministic",
            "release_status": "experimental",
            "owner": "ovk-maintainers",
            "native_execution": False,
        },
        "pass_establishes": (
            "The self-protection lane reported that the required OVK verification gate "
            "remains present after the change."
        ),
        "outside_claim": (
            "Does not prove correctness of other required checks, workflow step semantics, "
            "or protections outside the declared gate name."
        ),
    },
    "lane-authorization": {
        "pass_path": "examples/auth_regression/input_admin_protected.json",
        "fail_path": "examples/auth_regression/input_admin_bypass.json",
        "malformed_path": "examples/auth_regression/input_malformed_missing_routes.json",
        "timeout": {"timeout": True},
        "unavailable": {"binary_unavailable": True},
        "capability": {
            "capability_id": "lane-authorization-v1",
            "checker_id": "lane-authorization",
            "version": "0.1.0",
            "implementation": "ovk-adapter-lane-authorization",
            "input_contract": "Authorization route/role abstraction JSON.",
            "output_contract": "ovk.evidence via authorization lane evaluator",
            "claim_class": "smt_refutation_search",
            "tool": {
                "name": "lane-authorization",
                "adapter": "ovk-adapter-lane-authorization",
                "adapter_version": "0.1.0",
            },
            "backend_class": "smt_solver",
            "supported_domains": ["authorization"],
            "supported_property_kinds": ["access_control", "safety", "invariant"],
            "guarantee": {
                "type": "smt_refutation_search",
                "meaning_of_pass": "No unauthorized reachability counterexample was found.",
                "meaning_of_fail": "An unauthorized role can reach a protected route.",
                "meaning_of_unknown": "Encoding incomplete, solver unknown, or binary unavailable.",
            },
            "assumptions": [
                "Route and role abstractions faithfully represent the change under review.",
            ],
            "trusted_components": [
                "authorization lane evaluator",
                "optional Z3 solver",
            ],
            "limits": [
                "Native Z3 availability is optional; deterministic fallback is weaker.",
            ],
            "failure_semantics": "Validation failures and solver errors map to unknown/error.",
            "timeout_semantics": "unknown",
            "unsupported_semantics": "Does not reconstruct frameworks beyond the supplied route abstraction.",
            "determinism_status": "tool_dependent",
            "release_status": "experimental",
            "owner": "ovk-maintainers",
            "native_execution": False,
        },
        "pass_establishes": (
            "The authorization lane found no unauthorized reachability counterexample "
            "for the supplied route abstraction."
        ),
        "outside_claim": (
            "Does not reconstruct frameworks beyond the supplied abstraction or prove "
            "properties outside the encoded obligation polarity."
        ),
    },
    "lane-infrastructure": {
        "pass_path": "examples/infrastructure_exposure/input_private_sensitive_resource.json",
        "fail_path": "examples/infrastructure_exposure/input_public_sensitive_resource.json",
        "malformed": {
            "malformed": True,
            "author_type": "ai_agent",
            "agent": "codex",
            "task": "malformed",
            "resources": "not-a-list",
        },
        "timeout": {"timeout": True},
        "unavailable": {"binary_unavailable": True},
        "capability": {
            "capability_id": "lane-infrastructure-v1",
            "checker_id": "lane-infrastructure",
            "version": "0.1.0",
            "implementation": "ovk-adapter-lane-infrastructure",
            "input_contract": "Infrastructure exposure graph / resource abstraction JSON.",
            "output_contract": "ovk.evidence via infrastructure lane evaluator",
            "claim_class": "deterministic_witness",
            "tool": {
                "name": "lane-infrastructure",
                "adapter": "ovk-adapter-lane-infrastructure",
                "adapter_version": "0.1.0",
            },
            "backend_class": "static_analyzer",
            "supported_domains": ["infrastructure"],
            "supported_property_kinds": ["data_boundary", "forbidden_configuration", "safety"],
            "guarantee": {
                "type": "deterministic_witness",
                "meaning_of_pass": "No sensitive resource is publicly exposed in the abstraction.",
                "meaning_of_fail": "A sensitive resource has a public exposure path.",
                "meaning_of_unknown": "The infrastructure abstraction was missing or malformed.",
            },
            "assumptions": [
                "Resource sensitivity and exposure edges faithfully represent planned state.",
            ],
            "trusted_components": ["infrastructure lane evaluator"],
            "limits": ["Does not execute Terraform/Kubernetes; evaluates the supplied abstraction only."],
            "failure_semantics": "Malformed abstractions map to unknown; evaluator errors map to error.",
            "timeout_semantics": "unknown",
            "unsupported_semantics": "Does not prove runtime cloud configurations beyond the abstraction.",
            "determinism_status": "deterministic",
            "release_status": "experimental",
            "owner": "ovk-maintainers",
            "native_execution": False,
        },
        "pass_establishes": (
            "The infrastructure lane found no public exposure path to a sensitive resource "
            "in the supplied abstraction."
        ),
        "outside_claim": (
            "Does not execute Terraform or Kubernetes APIs; does not prove live cloud "
            "configuration beyond the supplied graph."
        ),
    },
    "lane-ci-secrets": {
        "pass_path": "examples/ci_secrets/input_secrets_safe.json",
        "fail_path": "examples/ci_secrets/input_secrets_exposed.json",
        "malformed": {
            "malformed": True,
            "author_type": "ai_agent",
            "agent": "codex",
            "task": "malformed",
            "trust_context": "untrusted_fork_pr",
            "workflows": "not-a-list",
        },
        "timeout": {"timeout": True},
        "unavailable": {"binary_unavailable": True},
        "capability": {
            "capability_id": "lane-ci-secrets-v1",
            "checker_id": "lane-ci-secrets",
            "version": "0.1.0",
            "implementation": "ovk-adapter-lane-ci-secrets",
            "input_contract": "CI workflow secret exposure abstraction JSON.",
            "output_contract": "ovk.evidence via ci_secrets lane evaluator",
            "claim_class": "deterministic_witness",
            "tool": {
                "name": "lane-ci-secrets",
                "adapter": "ovk-adapter-lane-ci-secrets",
                "adapter_version": "0.1.0",
            },
            "backend_class": "static_analyzer",
            "supported_domains": ["ci_cd"],
            "supported_property_kinds": ["data_boundary", "forbidden_configuration", "safety"],
            "guarantee": {
                "type": "deterministic_witness",
                "meaning_of_pass": "Secrets are not exposed on untrusted workflow triggers.",
                "meaning_of_fail": "A secret is reachable from an untrusted trigger context.",
                "meaning_of_unknown": "Workflow abstraction missing or malformed.",
            },
            "assumptions": ["Workflow triggers and env bindings faithfully represent the change."],
            "trusted_components": ["ci_secrets lane evaluator"],
            "limits": ["Does not execute GitHub Actions; evaluates the supplied abstraction only."],
            "failure_semantics": "Malformed workflows map to unknown; evaluator errors map to error.",
            "timeout_semantics": "unknown",
            "unsupported_semantics": "Does not analyze composite actions beyond the supplied steps.",
            "determinism_status": "deterministic",
            "release_status": "experimental",
            "owner": "ovk-maintainers",
            "native_execution": False,
        },
        "pass_establishes": (
            "The ci_secrets lane found no secret exposure on untrusted workflow triggers "
            "in the supplied abstraction."
        ),
        "outside_claim": (
            "Does not execute GitHub Actions runners or analyze composite actions beyond "
            "the supplied workflow steps."
        ),
    },
    "lane-deployment": {
        "pass_path": "examples/deployment_state/input_valid_approval_path.json",
        "fail_path": "examples/deployment_state/input_skipped_approval.json",
        "malformed": {
            "malformed": True,
            "author_type": "ai_agent",
            "agent": "codex",
            "task": "malformed",
            "states": "not-a-list",
            "transitions": [],
        },
        "timeout": {"timeout": True},
        "unavailable": {"binary_unavailable": True},
        "capability": {
            "capability_id": "lane-deployment-v1",
            "checker_id": "lane-deployment",
            "version": "0.1.0",
            "implementation": "ovk-adapter-lane-deployment",
            "input_contract": "Deployment state-machine abstraction JSON.",
            "output_contract": "ovk.evidence via deployment lane evaluator",
            "claim_class": "deterministic_witness",
            "tool": {
                "name": "lane-deployment",
                "adapter": "ovk-adapter-lane-deployment",
                "adapter_version": "0.1.0",
            },
            "backend_class": "model_checker",
            "supported_domains": ["deployment"],
            "supported_property_kinds": ["safety", "invariant", "forbidden_configuration"],
            "guarantee": {
                "type": "deterministic_witness",
                "meaning_of_pass": "Production states are unreachable without required approvals.",
                "meaning_of_fail": "A path skips a required approval state before production.",
                "meaning_of_unknown": "State machine missing or malformed.",
            },
            "assumptions": ["States and transitions faithfully represent the deployment pipeline."],
            "trusted_components": ["deployment lane evaluator"],
            "limits": ["Does not execute Argo/GitHub Environments; evaluates the supplied machine only."],
            "failure_semantics": "Malformed machines map to unknown; evaluator errors map to error.",
            "timeout_semantics": "unknown",
            "unsupported_semantics": "Does not prove runtime orchestrator behavior beyond the abstraction.",
            "determinism_status": "deterministic",
            "release_status": "experimental",
            "owner": "ovk-maintainers",
            "native_execution": False,
        },
        "pass_establishes": (
            "The deployment lane found no path that reaches a production state while "
            "skipping required approval states."
        ),
        "outside_claim": (
            "Does not execute Argo Rollouts or GitHub Environments; does not prove "
            "orchestrator behavior beyond the supplied state machine."
        ),
    },
}


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def write_claims(path: Path, *, pass_establishes: str, outside_claim: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "# Adapter conformance claims\n\n"
        "## Pass establishes\n\n"
        f"{pass_establishes}\n\n"
        "## Outside the claim\n\n"
        f"{outside_claim}\n",
        encoding="utf-8",
    )


def ensure_example(name: str, payload: dict) -> str:
    path = EXAMPLES / name
    write_json(path, payload)
    return f"examples/backends/{name}"


def build_formal() -> None:
    for adapter_id, spec in FORMAL.items():
        fixtures: dict[str, dict[str, str]] = {}
        dir_name = spec["dir"]
        conf = ROOT / "adapters" / dir_name / "conformance"

        def add_case(case: str, path: str) -> None:
            fixtures[case] = {"path": path}

        if "pass_path" in spec:
            add_case("pass", spec["pass_path"])
        else:
            add_case("pass", ensure_example(f"{dir_name}_pass.json", spec["pass"]))

        if "fail_path" in spec:
            add_case("fail", spec["fail_path"])
        else:
            add_case("fail", ensure_example(f"{dir_name}_fail.json", spec["fail"]))

        if "malformed_path" in spec:
            add_case("malformed", spec["malformed_path"])
        else:
            add_case("malformed", ensure_example(f"{dir_name}_malformed.json", spec["malformed"]))

        add_case("timeout", ensure_example(f"{dir_name}_timeout.json", spec["timeout"]))
        add_case("unavailable", ensure_example(f"{dir_name}_unavailable.json", spec["unavailable"]))

        write_json(
            conf / "manifest.json",
            {
                "adapter_id": adapter_id,
                "kind": "formal_backend",
                "schema_version": "ovk.adapter_conformance.v1",
                "fixtures": fixtures,
                "docs": {
                    "pass_establishes": "CLAIMS.md#pass-establishes",
                    "outside_claim": "CLAIMS.md#outside-the-claim",
                },
            },
        )
        write_claims(
            conf / "CLAIMS.md",
            pass_establishes=spec["pass_establishes"],
            outside_claim=spec["outside_claim"],
        )

        # Registry pointer on capability.json
        cap_path = ROOT / "adapters" / dir_name / "capability.json"
        cap = json.loads(cap_path.read_text(encoding="utf-8"))
        cap["conformance"] = {"suite": "conformance/manifest.json"}
        write_json(cap_path, cap)
        print(f"formal: {adapter_id}")


def build_lanes() -> None:
    for adapter_id, spec in LANES.items():
        conf = ROOT / "adapters" / adapter_id / "conformance"
        fixtures: dict[str, dict[str, str]] = {}

        fixtures["pass"] = {"path": spec["pass_path"]}
        fixtures["fail"] = {"path": spec["fail_path"]}
        if "malformed_path" in spec:
            fixtures["malformed"] = {"path": spec["malformed_path"]}
        else:
            local = conf / "fixtures" / "malformed.json"
            write_json(local, spec["malformed"])
            fixtures["malformed"] = {"path": "fixtures/malformed.json"}

        for case in ("timeout", "unavailable"):
            local = conf / "fixtures" / f"{case}.json"
            write_json(local, spec[case])
            fixtures[case] = {"path": f"fixtures/{case}.json"}

        write_json(
            conf / "manifest.json",
            {
                "adapter_id": adapter_id,
                "kind": "lane_adapter",
                "schema_version": "ovk.adapter_conformance.v1",
                "fixtures": fixtures,
                "docs": {
                    "pass_establishes": "CLAIMS.md#pass-establishes",
                    "outside_claim": "CLAIMS.md#outside-the-claim",
                },
            },
        )
        write_claims(
            conf / "CLAIMS.md",
            pass_establishes=spec["pass_establishes"],
            outside_claim=spec["outside_claim"],
        )
        cap = dict(spec["capability"])
        cap["conformance"] = {"suite": "conformance/manifest.json"}
        write_json(ROOT / "adapters" / adapter_id / "capability.json", cap)
        print(f"lane: {adapter_id}")


def main() -> None:
    EXAMPLES.mkdir(parents=True, exist_ok=True)
    build_formal()
    build_lanes()
    print("done")


if __name__ == "__main__":
    main()
