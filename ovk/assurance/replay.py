"""Assurance invocation replay (distinct from ordinary cache replay)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ovk.assurance.errors import ReplayError
from ovk.assurance.pcs_export import (
    build_replay_report,
    invocation_ref_from_record,
    profile_ref_from_profile,
)
from ovk.assurance.pcs_hash import sha256_digest
from ovk.assurance.pcs_validate import require_valid_pcs_artifact
from ovk.assurance.runner import run_assurance
from ovk.assurance.snapshot import ConfigurationSnapshot


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ReplayError(f"expected JSON object: {path}")
    return data


def replay_invocation(
    invocation: Mapping[str, Any] | Path | str,
    *,
    adapter: Any,
    evidence_dir: Path | str | None = None,
    input_data: Mapping[str, Any] | None = None,
    config: Mapping[str, Any] | None = None,
    profile: Mapping[str, Any] | None = None,
    claim_matched: bool = False,
) -> dict[str, Any]:
    """Replay a prior invocation against an assurance-capable adapter.

    Fail closed on configuration drift when claiming ``matched``. Stochastic
    backends cannot claim matched.
    """
    if isinstance(invocation, (str, Path)):
        original = _load_json(Path(invocation))
    else:
        original = dict(invocation)
    require_valid_pcs_artifact(original, artifact_type="VerifierInvocationRecord.v1")

    evidence_root = Path(evidence_dir) if evidence_dir is not None else None
    sealed_profile = dict(profile) if profile is not None else None
    if sealed_profile is None and evidence_root is not None:
        profile_path = evidence_root / "verifier_profile.pcs.json"
        if profile_path.is_file():
            sealed_profile = _load_json(profile_path)

    if sealed_profile is None:
        raise ReplayError("replay requires a sealed verifier profile (pass profile= or evidence-dir)")

    require_valid_pcs_artifact(sealed_profile, artifact_type="VerifierProfile.v1")

    # Detect profile drift against invocation binding.
    expected_profile_digest = original["profile_ref"]["profile_digest"]
    actual_profile_digest = sealed_profile["integrity"]["artifact_digest"]
    environment_drift: list[str] = []
    missing_dependencies: list[str] = []
    if expected_profile_digest != actual_profile_digest:
        environment_drift.append(
            f"profile_digest drift: invocation={expected_profile_digest} current={actual_profile_digest}"
        )

    determinism = str(
        sealed_profile.get("mechanism", {}).get("determinism")
        or getattr(getattr(adapter, "manifest")().assurance, "determinism", "deterministic")
    )

    # Resolve input for rerun.
    resolved_input = dict(input_data or {})
    if not resolved_input and evidence_root is not None:
        obligation_path = evidence_root / "compiled_obligation.json"
        if obligation_path.is_file():
            obligation = _load_json(obligation_path)
            if isinstance(obligation.get("input"), dict):
                resolved_input = dict(obligation["input"])
    if not resolved_input:
        raise ReplayError("replay requires input_data or compiled_obligation.json with input")

    # Detect missing external dependencies advertised on the profile.
    for dep in sealed_profile.get("external_dependencies") or []:
        if not isinstance(dep, dict):
            continue
        if dep.get("optional"):
            continue
        identity = str(dep.get("identity") or "")
        kind = str(dep.get("kind") or "")
        if kind == "binary" and identity:
            from shutil import which

            if which(identity) is None:
                missing_dependencies.append(identity)

    original_raw = original["raw_backend_result_digest"]
    original_normalized = original["normalized_result_digest"]

    if missing_dependencies:
        report = build_replay_report(
            replay_id=f"replay-{original['invocation_id']}",
            original_invocation_ref=invocation_ref_from_record(original),
            profile_ref=profile_ref_from_profile(sealed_profile),
            replay_status="indeterminate",
            determinism=determinism,
            original_raw_digest=original_raw,
            replay_raw_digest=sha256_digest({"missing": missing_dependencies}),
            original_normalized_digest=original_normalized,
            replay_normalized_digest=sha256_digest({"missing": missing_dependencies}),
            drift={
                "raw_digest_match": False,
                "normalized_digest_match": False,
                "missing_dependencies": missing_dependencies,
                "environment_drift": environment_drift,
                "notes": "missing required dependencies; replay not executed",
            },
            indeterminate_reason="missing_checker",
        )
        if claim_matched:
            raise ReplayError("cannot claim matched when dependencies are missing")
        return report

    if environment_drift and claim_matched:
        raise ReplayError(f"configuration drift; refuse matched claim: {environment_drift}")

    if determinism == "stochastic":
        report = build_replay_report(
            replay_id=f"replay-{original['invocation_id']}",
            original_invocation_ref=invocation_ref_from_record(original),
            profile_ref=profile_ref_from_profile(sealed_profile),
            replay_status="indeterminate",
            determinism=determinism,
            original_raw_digest=original_raw,
            replay_raw_digest=original_raw,
            original_normalized_digest=original_normalized,
            replay_normalized_digest=original_normalized,
            drift={
                "raw_digest_match": False,
                "normalized_digest_match": False,
                "missing_dependencies": [],
                "environment_drift": environment_drift,
                "notes": "stochastic verifier cannot claim bit-identical matched replay",
            },
            indeterminate_reason="declared_nondeterminism",
        )
        if claim_matched:
            raise ReplayError("stochastic verifier cannot claim matched replay")
        return report

    # Deterministic rerun
    snapshot = None
    if hasattr(adapter, "snapshot_config"):
        snap = adapter.snapshot_config(config or sealed_profile.get("canonical_configuration") or {})
        snapshot = snap if isinstance(snap, ConfigurationSnapshot) else ConfigurationSnapshot.model_validate(snap)

    outcome = run_assurance(
        adapter,
        input_data=resolved_input,
        config=config or sealed_profile.get("canonical_configuration") or {},
        profile=sealed_profile,
        evidence_dir=None,
    )
    replay_invocation = outcome.invocation
    replay_raw = replay_invocation["raw_backend_result_digest"]
    replay_normalized = replay_invocation["normalized_result_digest"]
    raw_match = replay_raw == original_raw
    normalized_match = replay_normalized == original_normalized

    if environment_drift:
        status = "drifted"
    elif raw_match and normalized_match:
        status = "matched"
    else:
        status = "drifted"

    if claim_matched and status != "matched":
        raise ReplayError(
            f"replay drifted (raw_match={raw_match}, normalized_match={normalized_match}, "
            f"env_drift={environment_drift}); refuse matched claim"
        )

    report = build_replay_report(
        replay_id=f"replay-{original['invocation_id']}",
        original_invocation_ref=invocation_ref_from_record(original),
        profile_ref=profile_ref_from_profile(sealed_profile),
        replay_status=status,
        determinism=determinism,
        original_raw_digest=original_raw,
        replay_raw_digest=replay_raw,
        original_normalized_digest=original_normalized,
        replay_normalized_digest=replay_normalized,
        drift={
            "raw_digest_match": raw_match,
            "normalized_digest_match": normalized_match,
            "missing_dependencies": missing_dependencies,
            "environment_drift": environment_drift,
            **(
                {"notes": f"snapshot_digest={snapshot.content_digest}"}
                if snapshot is not None
                else {}
            ),
        },
        replay_invocation_ref=invocation_ref_from_record(replay_invocation),
    )

    if evidence_root is not None:
        evidence_root.mkdir(parents=True, exist_ok=True)
        (evidence_root / "replay_report.pcs.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return report
