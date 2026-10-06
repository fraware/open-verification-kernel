"""Authorize and run expansion_v2 materialization for the five frozen candidates.

Pre-oracle only. No RTK / oracle / baseline / unblind.
Requires v0 compatibility to have passed (enforced by --require-v0-compat).
"""

from __future__ import annotations

import argparse
import json
import sys
import unittest
from pathlib import Path
from typing import Any

from .generate_transition_census_v2 import GENERATOR_ROLE
from .pipeline import process_repository, write_json
from .registry import EXPANSION_IDENTITIES, build_default_registry

REPO_ROOT = Path(__file__).resolve().parents[4]

DEFAULT_CHECKOUTS = {
    "fraware/pcs-bench": Path("/tmp/rtk-cand/pcs-bench"),
    "fraware/ovk-consumer-fastapi-terraform": Path(
        "/tmp/rtk-cand/ovk-consumer-fastapi-terraform"
    ),
    "fraware/ovk-consumer-express-actions": Path(
        "/tmp/rtk-cand/ovk-consumer-express-actions"
    ),
    "fraware/environment-assurance-compiler": Path(
        "/tmp/rtk-cand/environment-assurance-compiler"
    ),
    "fraware/lean-project-evidence": Path("/tmp/rtk-cand/lean-project-evidence"),
}

TARGET_TIER_A = 20
V0_TIER_A_TRANSITIONS = 3


def _run_v0_compat() -> unittest.TestResult:
    loader = unittest.TestLoader()
    suite = loader.discover(
        str(Path(__file__).resolve().parent / "tests"),
        pattern="test_v0_compatibility.py",
    )
    runner = unittest.TextTestRunner(verbosity=2)
    return runner.run(suite)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--authorize-materialization",
        action="store_true",
        required=True,
        help="Required explicit authorization after human methodology gate.",
    )
    parser.add_argument(
        "--require-v0-compat",
        action="store_true",
        default=True,
        help="Run v0 compatibility tests before expansion (default on).",
    )
    parser.add_argument(
        "--skip-v0-compat",
        action="store_true",
        help="Skip embedded v0 compat run (only if already verified).",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=REPO_ROOT
        / "experiments/rtk/sealed/expansion_v2_outputs",
    )
    parser.add_argument("--timeout-sec", type=int, default=300)
    args = parser.parse_args(argv)

    if not args.authorize_materialization:
        print("refusing: --authorize-materialization required", file=sys.stderr)
        return 2

    if not args.skip_v0_compat:
        print("Running v0 compatibility gate...", flush=True)
        result = _run_v0_compat()
        if not result.wasSuccessful():
            print("BLOCKED: v0 compatibility failed; not processing five.", flush=True)
            return 3

    registry = build_default_registry()
    out_root = args.out_dir
    out_root.mkdir(parents=True, exist_ok=True)

    per_repo: list[dict[str, Any]] = []
    tier_a_total = V0_TIER_A_TRANSITIONS
    stop_reason = "CANDIDATE_LIST_EXHAUSTED"

    for identity in EXPANSION_IDENTITIES:
        if tier_a_total >= TARGET_TIER_A:
            stop_reason = "FEASIBILITY_GATE_MET"
            break
        adapter = registry[identity.repository]
        checkout = DEFAULT_CHECKOUTS.get(identity.repository)
        repo_out = out_root / identity.repository.replace("/", "__")
        if checkout is None or not checkout.is_dir():
            per_repo.append(
                {
                    "repository": identity.repository,
                    "cutoff_sha": identity.cutoff_sha,
                    "outcome": "OPERATIONAL_CHECKOUT_FAILURE",
                    "tier_a_replay_verified": {"transition_count": 0, "anchor_count": 0},
                    "notes": [f"missing checkout for {identity.repository}"],
                }
            )
            continue
        print(f"Processing {identity.repository} ...", flush=True)
        result = process_repository(
            adapter,
            checkout,
            repo_out,
            timeout_sec=args.timeout_sec,
            materialize_v0_via_authentic=False,
        )
        per_repo.append(result.as_dict())
        tier_a_total += result.tier_a_transitions
        if tier_a_total >= TARGET_TIER_A:
            stop_reason = "FEASIBILITY_GATE_MET"
            # Continue? Protocol: stop early if gate met while walking.
            # Record remaining as not processed? "Stop early if the gate is met"
            break

    processed = {row["repository"] for row in per_repo}
    for identity in EXPANSION_IDENTITIES:
        if identity.repository not in processed and stop_reason == "FEASIBILITY_GATE_MET":
            per_repo.append(
                {
                    "repository": identity.repository,
                    "cutoff_sha": identity.cutoff_sha,
                    "outcome": "NOT_PROCESSED_GATE_ALREADY_MET",
                    "tier_a_replay_verified": {"transition_count": 0, "anchor_count": 0},
                }
            )
        elif identity.repository not in processed:
            # Should not happen: protocol requires processing every candidate.
            pass

    # Protocol: process every candidate including zero-admissible. If we stopped
    # early for gate, that is allowed. If list exhausted below 20, mark status.
    expansion_tier_a = sum(
        int(row.get("tier_a_replay_verified", {}).get("transition_count", 0))
        for row in per_repo
    )
    total_tier_a = V0_TIER_A_TRANSITIONS + expansion_tier_a
    if total_tier_a >= TARGET_TIER_A:
        gate = "MET"
        expansion_status = "STOPPED_GATE_MET"
    else:
        # Ensure all five were attempted
        attempted = {
            row["repository"]
            for row in per_repo
            if row.get("outcome") not in {"NOT_PROCESSED_GATE_ALREADY_MET"}
        }
        expected = {i.repository for i in EXPANSION_IDENTITIES}
        if attempted != expected:
            # Process any missing before declaring exhausted.
            for identity in EXPANSION_IDENTITIES:
                if identity.repository in attempted:
                    continue
                adapter = registry[identity.repository]
                checkout = DEFAULT_CHECKOUTS[identity.repository]
                repo_out = out_root / identity.repository.replace("/", "__")
                print(f"Processing remaining {identity.repository} ...", flush=True)
                result = process_repository(
                    adapter,
                    checkout,
                    repo_out,
                    timeout_sec=args.timeout_sec,
                    materialize_v0_via_authentic=False,
                )
                per_repo.append(result.as_dict())
                expansion_tier_a += result.tier_a_transitions
            total_tier_a = V0_TIER_A_TRANSITIONS + expansion_tier_a
        gate = "MET" if total_tier_a >= TARGET_TIER_A else "EXHAUSTED_BELOW_20"
        expansion_status = (
            "STOPPED_GATE_MET"
            if gate == "MET"
            else "STOPPED_CANDIDATE_LIST_EXHAUSTED"
        )

    walk = {
        "schema_version": "source_universe_v2_expansion_walk.v0",
        "status": expansion_status,
        "generator_role": GENERATOR_ROLE,
        "authentic_v0_claim": False,
        "protocol_path": "experiments/rtk/SOURCE_UNIVERSE_EXPANSION_PROTOCOL.v2.md",
        "candidates_path": "experiments/rtk/SOURCE_REPOSITORY_CANDIDATES.v1.json",
        "v0_tier_a_transitions": V0_TIER_A_TRANSITIONS,
        "expansion_tier_a_transitions": expansion_tier_a,
        "total_tier_a_transitions": total_tier_a,
        "target_feasibility_gate": TARGET_TIER_A,
        "gate_status": gate,
        "stop_reason": stop_reason if gate == "MET" else "CANDIDATE_LIST_EXHAUSTED",
        "repos_processed_in_order": per_repo,
        "prohibitions_honored": [
            "NO_ORACLE",
            "NO_RTK_PREDICTION",
            "NO_BASELINE_EXECUTION",
            "NO_UNBLINDING",
            "NO_V0_REWRITE",
            "NO_TIER_A_WEAKENING",
            "NO_TIER_B_PROMOTION",
            "NO_CARDINALITY_TUNING",
            "NO_INDEFINITE_REPO_SEARCH",
        ],
    }
    walk_path = REPO_ROOT / "experiments/rtk/SOURCE_UNIVERSE_V2_EXPANSION_WALK.json"
    walk_sha = write_json(walk_path, walk)

    binding = {
        "schema_version": "source_universe_v2_binding.v0",
        "status": gate,
        "expansion_status": expansion_status,
        "source_universe_v0": {
            "immutable": True,
            "sealed_census_sha256": (
                "b1816276176297adf345981fe5d9c8271cf00f5b71653d59a21d8261d64a6b11"
            ),
            "tier_a_replay_verified_transitions": V0_TIER_A_TRANSITIONS,
        },
        "source_universe_v1": {
            "immutable_exhaustion_record": True,
            "binding": "experiments/rtk/SOURCE_UNIVERSE_V1_BINDING.json",
            "replay_verified_transitions_added": 0,
        },
        "source_universe_v2": {
            "protocol": "experiments/rtk/SOURCE_UNIVERSE_EXPANSION_PROTOCOL.v2.md",
            "adapter_package": "experiments/p05_formalpr_bench/rtk_eval/expansion_v2/",
            "expansion_walk": "experiments/rtk/SOURCE_UNIVERSE_V2_EXPANSION_WALK.json",
            "expansion_walk_sha256": walk_sha,
            "outputs_dir": str(out_root.relative_to(REPO_ROOT)),
            "replay_verified_transitions_added": expansion_tier_a,
            "census_module_role": GENERATOR_ROLE,
            "authentic_v0_claim": False,
        },
        "independent_replay_verified_transitions": {
            "source_universe_v0": V0_TIER_A_TRANSITIONS,
            "source_universe_v1": 0,
            "source_universe_v2": expansion_tier_a,
            "total": total_tier_a,
            "target_feasibility_gate": TARGET_TIER_A,
        },
        "feasibility_gate": {
            "status": gate,
            "expansion_status": expansion_status,
        },
        "oracle_status": "BLOCKED_UNTIL_HUMAN_CHECKPOINT",
        "prohibitions_honored": walk["prohibitions_honored"],
    }
    binding_path = REPO_ROOT / "experiments/rtk/SOURCE_UNIVERSE_V2_BINDING.json"
    binding_sha = write_json(binding_path, binding)

    summary = {
        "gate_status": gate,
        "total_tier_a_transitions": total_tier_a,
        "expansion_tier_a_transitions": expansion_tier_a,
        "walk_path": str(walk_path),
        "walk_sha256": walk_sha,
        "binding_path": str(binding_path),
        "binding_sha256": binding_sha,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
