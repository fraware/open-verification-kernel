"""InvocationRecord builder for assurance evidence packs."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from ovk.assurance.pcs_export import build_invocation_record_artifact
from ovk.assurance.pcs_hash import sha256_digest
from ovk.assurance.snapshot import ConfigurationSnapshot


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_invocation_record(
    *,
    snapshot: ConfigurationSnapshot,
    profile: Mapping[str, Any],
    input_data: Mapping[str, Any] | Any,
    command_argv: list[str],
    cwd: str,
    started_at: str,
    completed_at: str,
    exit_kind: str,
    exit_code: int | None = None,
    exit_message: str | None = None,
    stdout: str | bytes | None = "",
    stderr: str | bytes | None = "",
    raw_result: Mapping[str, Any] | None = None,
    normalized_result: Mapping[str, Any] | None = None,
    guarantee_class: str | None = None,
    assumptions: list[dict[str, Any]] | None = None,
    limits: list[dict[str, Any]] | None = None,
    indeterminate_reason: str | None = None,
    compiled_obligation: Mapping[str, Any] | None = None,
    timeout_ms: int | None = None,
    env_digest: str | None = None,
    result_ref: dict[str, Any] | None = None,
    normalizer_version: str = "ovk.normalize.v1",
    seal: bool = True,
) -> dict[str, Any]:
    """Build a VerifierInvocationRecord.v1 from run artifacts."""
    profile_digest = profile.get("integrity", {}).get("artifact_digest")
    if not isinstance(profile_digest, str):
        raise ValueError("profile must be sealed before building invocation record")

    input_digest = sha256_digest(dict(input_data) if isinstance(input_data, Mapping) else input_data)
    stdout_text = stdout.decode("utf-8") if isinstance(stdout, bytes) else (stdout or "")
    stderr_text = stderr.decode("utf-8") if isinstance(stderr, bytes) else (stderr or "")
    raw = dict(raw_result or {})
    normalized = dict(normalized_result or {})

    # When normalization is applied, digests must differ (PCS semantic rule).
    raw_digest = sha256_digest(raw)
    normalized_digest = sha256_digest(normalized)
    if raw_digest == normalized_digest:
        normalized = {**normalized, "_normalization_marker": "ovk.normalize.v1"}
        normalized_digest = sha256_digest(normalized)

    resolved_timeout = timeout_ms or snapshot.timeout_ms or 30_000
    env = env_digest or snapshot.redacted_environment.get("environment_digest")
    if not isinstance(env, str):
        env = sha256_digest(snapshot.redacted_environment.get("entries") or {})

    exit_obj: dict[str, Any] = {"kind": exit_kind}
    if exit_code is not None:
        exit_obj["code"] = int(exit_code)
    if exit_message:
        exit_obj["message"] = exit_message

    invocation_id = f"vi-{snapshot.backend_id}-{input_digest[7:15]}"
    record: dict[str, Any] = {
        "schema_version": "v1",
        "artifact_type": "VerifierInvocationRecord.v1",
        "canonicalization_version": "v1",
        "invocation_id": invocation_id,
        "profile_ref": {
            "artifact_type": "VerifierProfile.v1",
            "verifier_profile_id": profile["verifier_profile_id"],
            "profile_digest": profile_digest,
        },
        "input_digest": input_digest,
        "command": {
            "argv": list(command_argv) or [snapshot.adapter_id, "run"],
            "cwd": cwd or ".",
            "env_digest": env,
            "limits": {"timeout_ms": int(resolved_timeout)},
        },
        "started_at": started_at or _utc_now_iso(),
        "completed_at": completed_at or _utc_now_iso(),
        "exit": exit_obj,
        "stdout_digest": sha256_digest(stdout_text),
        "stderr_digest": sha256_digest(stderr_text),
        "raw_backend_result_digest": raw_digest,
        "normalizer_version": normalizer_version,
        "normalized_result_digest": normalized_digest,
        "assumptions": list(assumptions or []),
        "limits": list(limits or []),
        "guarantee_class": guarantee_class or snapshot.guarantee_class,
    }
    if compiled_obligation is not None:
        obligation_digest = sha256_digest(dict(compiled_obligation))
        record["compiled_obligation"] = {
            "digest": obligation_digest,
            "path": "compiled_obligation.json",
            "media_type": "application/json",
        }
    if indeterminate_reason is not None:
        record["indeterminate_reason"] = indeterminate_reason
    if result_ref is not None:
        record["result_ref"] = dict(result_ref)

    return build_invocation_record_artifact(record, seal=seal)
