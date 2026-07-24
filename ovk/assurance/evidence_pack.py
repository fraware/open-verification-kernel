"""Evidence pack layout writer and validator for assurance runs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ovk.assurance.errors import EvidenceError
from ovk.assurance.pcs_hash import sha256_digest
from ovk.assurance.pcs_validate import require_valid_pcs_artifact

REQUIRED_FILES = (
    "invocation.json",
    "verifier_profile.pcs.json",
    "verification_result.pcs.json",
    "compiled_obligation.json",
)

REQUIRED_DIRS = ("raw", "normalized", "provenance")


def _write_json(path: Path, payload: Mapping[str, Any] | list[Any] | Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_evidence_pack(
    evidence_dir: Path | str,
    *,
    invocation: Mapping[str, Any],
    profile: Mapping[str, Any],
    result: Mapping[str, Any],
    compiled_obligation: Mapping[str, Any] | None = None,
    raw_result: Mapping[str, Any] | None = None,
    normalized_result: Mapping[str, Any] | None = None,
    provenance: Mapping[str, Any] | None = None,
    stdout: str | None = None,
    stderr: str | None = None,
    validate: bool = True,
) -> Path:
    """Write the standard assurance evidence pack layout and optionally validate."""
    root = Path(evidence_dir)
    root.mkdir(parents=True, exist_ok=True)
    for name in REQUIRED_DIRS:
        (root / name).mkdir(parents=True, exist_ok=True)

    clean_invocation = dict(invocation)
    if "_ovk_working" in clean_invocation:
        raise EvidenceError(
            "invocation must be a sealed OVK invocation record; "
            "sidecar fields such as _ovk_working are forbidden"
        )

    obligation = dict(compiled_obligation or {"kind": "assurance_input", "note": "no compiled obligation"})
    raw = dict(raw_result or {})
    normalized = dict(normalized_result or {})
    prov = dict(
        provenance
        or {
            "producer": clean_invocation.get("producer"),
            "producer_version": clean_invocation.get("producer_version"),
            "input_digest": clean_invocation.get("input_digest"),
            "profile_digest": clean_invocation.get("profile_ref", {}).get("profile_digest"),
            "raw_digest": clean_invocation.get("raw_backend_result_digest"),
            "normalized_digest": clean_invocation.get("normalized_result_digest"),
        }
    )

    _write_json(root / "invocation.json", clean_invocation)
    _write_json(root / "verifier_profile.pcs.json", profile)
    _write_json(root / "verification_result.pcs.json", result)
    _write_json(root / "compiled_obligation.json", obligation)
    _write_json(root / "raw" / "backend_result.json", raw)
    if stdout is not None:
        (root / "raw" / "stdout.txt").write_text(str(stdout), encoding="utf-8")
    if stderr is not None:
        (root / "raw" / "stderr.txt").write_text(str(stderr), encoding="utf-8")
    _write_json(root / "normalized" / "result.json", normalized)
    _write_json(root / "provenance" / "digests.json", prov)

    if validate:
        validate_evidence_dir(root)
    return root


def validate_evidence_dir(evidence_dir: Path | str) -> dict[str, Any]:
    """Validate evidence pack layout and PCS artifacts. Fail closed on errors."""
    root = Path(evidence_dir)
    if not root.is_dir():
        raise EvidenceError(f"evidence directory does not exist: {root}")

    missing = [name for name in REQUIRED_FILES if not (root / name).is_file()]
    missing_dirs = [name for name in REQUIRED_DIRS if not (root / name).is_dir()]
    if missing or missing_dirs:
        raise EvidenceError(
            "evidence pack incomplete: "
            + ", ".join([*(f"missing file {m}" for m in missing), *(f"missing dir {d}" for d in missing_dirs)])
        )

    profile = json.loads((root / "verifier_profile.pcs.json").read_text(encoding="utf-8"))
    result = json.loads((root / "verification_result.pcs.json").read_text(encoding="utf-8"))
    invocation = json.loads((root / "invocation.json").read_text(encoding="utf-8"))

    require_valid_pcs_artifact(profile, artifact_type="VerifierProfile.v1")
    require_valid_pcs_artifact(result, artifact_type="VerificationResult.v1")
    require_valid_pcs_artifact(invocation, artifact_type="VerifierInvocationRecord.v1")

    # Cross-binding checks
    profile_digest = profile["integrity"]["artifact_digest"]
    if invocation["profile_ref"]["profile_digest"] != profile_digest:
        raise EvidenceError("invocation.profile_ref.profile_digest does not match sealed profile")
    if result["verifier_profile"]["profile_digest"] != profile_digest:
        raise EvidenceError("result.verifier_profile.profile_digest does not match sealed profile")

    declared = result.get("declared_input_guarantee_class")
    result_class = result.get("guarantee_class")
    if isinstance(declared, str) and isinstance(result_class, str):
        from ovk.assurance.guarantee import assert_no_guarantee_upgrade

        assert_no_guarantee_upgrade(declared, result_class)

    return {
        "valid": True,
        "evidence_dir": str(root),
        "profile_digest": profile_digest,
        "result_digest": result["integrity"]["artifact_digest"],
        "invocation_digest": invocation["integrity"]["artifact_digest"],
        "obligation_digest": sha256_digest(
            json.loads((root / "compiled_obligation.json").read_text(encoding="utf-8"))
        ),
    }
