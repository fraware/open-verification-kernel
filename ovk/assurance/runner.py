"""Assurance-mode runner (does not touch ordinary ovk check / MCP paths)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from ovk.assurance.capability import is_assurance_capable
from ovk.assurance.errors import AssuranceError
from ovk.assurance.evidence_pack import write_evidence_pack
from ovk.assurance.guarantee import clamp_guarantee_class
from ovk.assurance.indeterminate import (
    DECISION_ACCEPT,
    DECISION_REJECT,
    decision_for_indeterminate_reason,
    execution_status_for_reason,
    indeterminate_outcome,
    indeterminate_reason_for_termination,
)
from ovk.assurance.invocation import build_invocation_record
from ovk.assurance.pcs_export import build_verification_result, snapshot_to_verifier_profile
from ovk.assurance.pcs_hash import sha256_digest
from ovk.assurance.snapshot import ConfigurationSnapshot, snapshot_from_adapter


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class AssuranceRunOutcome:
    """Result of an assurance-mode run including evidence pack paths."""

    decision: str
    execution_status: str
    indeterminate_reason: str | None
    profile: dict[str, Any]
    result: dict[str, Any]
    invocation: dict[str, Any]
    snapshot: ConfigurationSnapshot
    evidence_dir: Path | None = None
    raw_result: dict[str, Any] = field(default_factory=dict)
    normalized_result: dict[str, Any] = field(default_factory=dict)


def _require_assurance_adapter(adapter: Any) -> None:
    if not hasattr(adapter, "manifest") or not callable(adapter.manifest):
        raise AssuranceError("adapter must expose manifest()")
    manifest = adapter.manifest()
    if not is_assurance_capable(manifest):
        raise AssuranceError(
            f"backend {getattr(adapter, 'backend_id', '?')!r} is not assurance_capable; "
            "snapshot-config/run require an assurance-capable adapter"
        )
    if not hasattr(adapter, "snapshot_config") or not callable(adapter.snapshot_config):
        raise AssuranceError(
            f"backend {getattr(adapter, 'backend_id', '?')!r} claims assurance but "
            "does not implement snapshot_config()"
        )


def _status_to_decision(status: str) -> str:
    normalized = str(status or "").strip().lower()
    if normalized in {"pass", "passed", "accept", "allow", "success"}:
        return DECISION_ACCEPT
    if normalized in {"fail", "failed", "reject", "deny"}:
        return DECISION_REJECT
    return decision_for_indeterminate_reason(indeterminate_reason_for_termination(normalized))


def run_assurance(
    adapter: Any,
    *,
    input_data: Mapping[str, Any],
    config: Mapping[str, Any] | None = None,
    environment: Mapping[str, str] | None = None,
    evidence_dir: Path | str | None = None,
    profile: Mapping[str, Any] | None = None,
    cwd: str | None = None,
) -> AssuranceRunOutcome:
    """Execute an assurance-capable adapter and optionally write an evidence pack.

    Ordinary ``ovk check`` / MCP paths are not invoked.
    """
    _require_assurance_adapter(adapter)
    manifest = adapter.manifest()
    assurance = manifest.assurance
    assert assurance is not None

    snapshot: ConfigurationSnapshot
    if hasattr(adapter, "snapshot_config"):
        snap = adapter.snapshot_config(config, environment=environment)
        snapshot = snap if isinstance(snap, ConfigurationSnapshot) else ConfigurationSnapshot.model_validate(snap)
    else:
        snapshot = snapshot_from_adapter(adapter, config, environment=environment)

    sealed_profile = dict(profile) if profile is not None else snapshot_to_verifier_profile(snapshot)

    started = _utc_now_iso()
    exit_kind = "exited"
    exit_code: int | None = 0
    exit_message: str | None = None
    stdout = ""
    stderr = ""
    raw_result: dict[str, Any] = {}
    normalized_result: dict[str, Any] = {}
    decision = decision_for_indeterminate_reason("other")
    execution_status = "error"
    indeterminate_reason: str | None = None
    declared_guarantee = assurance.decision_semantics.guarantee_class
    guarantee_class = declared_guarantee
    command_argv = [snapshot.adapter_id, "assurance-run"]

    try:
        if hasattr(adapter, "run_assurance") and callable(adapter.run_assurance):
            outcome = adapter.run_assurance(
                input_data=dict(input_data),
                snapshot=snapshot,
                config=dict(config or {}),
            )
            if not isinstance(outcome, Mapping):
                raise AssuranceError("run_assurance must return a mapping")
            exit_kind = str(outcome.get("exit_kind") or "exited")
            exit_code = outcome.get("exit_code")
            exit_message = outcome.get("message")
            stdout = str(outcome.get("stdout") or "")
            stderr = str(outcome.get("stderr") or "")
            raw_result = dict(outcome.get("raw_result") or {})
            normalized_result = dict(outcome.get("normalized_result") or {})
            indeterminate_reason = outcome.get("indeterminate_reason")
            if outcome.get("decision"):
                decision = str(outcome["decision"])
            elif indeterminate_reason:
                decision = decision_for_indeterminate_reason(str(indeterminate_reason))
            else:
                decision = _status_to_decision(str(outcome.get("status") or exit_kind))
            execution_status = str(
                outcome.get("execution_status")
                or (
                    execution_status_for_reason(str(indeterminate_reason))
                    if indeterminate_reason
                    else "completed"
                )
            )
            if outcome.get("guarantee_class"):
                guarantee_class = clamp_guarantee_class(declared_guarantee, str(outcome["guarantee_class"]))
            if outcome.get("command_argv"):
                command_argv = list(outcome["command_argv"])
        else:
            raise AssuranceError(
                f"backend {adapter.backend_id!r} does not implement run_assurance(); "
                "assurance run requires an explicit assurance execution path"
            )
    except AssuranceError:
        raise
    except FileNotFoundError as exc:
        ind = indeterminate_outcome(reason="missing_checker", message=str(exc))
        decision = ind["decision"]
        execution_status = ind["execution_status"]
        indeterminate_reason = ind["indeterminate_reason"]
        exit_kind = "missing_checker"
        exit_code = None
        exit_message = str(exc)
        raw_result = {"error": "missing_checker", "message": str(exc)}
        normalized_result = {"decision": decision, "indeterminate_reason": indeterminate_reason}
    except TimeoutError as exc:
        ind = indeterminate_outcome(reason="timeout", message=str(exc))
        decision = ind["decision"]
        execution_status = ind["execution_status"]
        indeterminate_reason = ind["indeterminate_reason"]
        exit_kind = "timeout"
        exit_code = None
        exit_message = str(exc)
        raw_result = {"error": "timeout", "message": str(exc)}
        normalized_result = {"decision": decision, "indeterminate_reason": indeterminate_reason}

    # Hard invariant: missing checker / timeout never become accept.
    if indeterminate_reason in {"missing_checker", "timeout"} and decision == DECISION_ACCEPT:
        decision = decision_for_indeterminate_reason(indeterminate_reason)

    completed = _utc_now_iso()
    claim_ids = list(assurance.decision_semantics.supported_claim_ids) or [
        f"claim.{snapshot.backend_id}"
    ]

    check_status = "passed" if decision == DECISION_ACCEPT else ("failed" if decision == DECISION_REJECT else "skipped")
    check_groups: list[dict[str, Any]] = [
        {
            "kind": "authority",
            "checks": [
                {
                    "check_id": f"{snapshot.backend_id}-predicate",
                    "mandatory": True,
                    "status": check_status if check_status != "skipped" else "skipped",
                    **({"reason_code": indeterminate_reason} if check_status == "skipped" and indeterminate_reason else {}),
                }
            ],
        }
    ]
    if check_status == "skipped" and not indeterminate_reason:
        check_groups[0]["checks"][0]["reason_code"] = "other"

    invocation = build_invocation_record(
        snapshot=snapshot,
        profile=sealed_profile,
        input_data=input_data,
        command_argv=command_argv,
        cwd=cwd or os.getcwd(),
        started_at=started,
        completed_at=completed,
        exit_kind=exit_kind,
        exit_code=exit_code if isinstance(exit_code, int) else None,
        exit_message=exit_message,
        stdout=stdout,
        stderr=stderr,
        raw_result=raw_result,
        normalized_result=normalized_result,
        guarantee_class=guarantee_class,
        indeterminate_reason=indeterminate_reason,
        compiled_obligation={"backend_id": snapshot.backend_id, "input": dict(input_data)},
        timeout_ms=snapshot.timeout_ms,
    )

    result = build_verification_result(
        verification_result_id=f"vr-{snapshot.backend_id}-{sha256_digest(dict(input_data))[7:15]}",
        profile=sealed_profile,
        decision=decision,
        execution_status=execution_status,
        claim_ids=claim_ids,
        raw_backend_output_digest=invocation["raw_backend_result_digest"],
        normalized_result_digest=invocation["normalized_result_digest"],
        check_groups=check_groups,
        resource_limits={"wall_time_ms": 0},
        guarantee_class=guarantee_class,
        declared_input_guarantee_class=declared_guarantee,
        invocation_ref={
            "invocation_id": invocation["invocation_id"],
            "invocation_digest": invocation["integrity"]["artifact_digest"],
        },
        input_bundle_digest=invocation["input_digest"],
        created_at=completed,
    )

    evidence_path: Path | None = None
    if evidence_dir is not None:
        evidence_path = write_evidence_pack(
            evidence_dir,
            invocation=invocation,
            profile=sealed_profile,
            result=result,
            compiled_obligation={"backend_id": snapshot.backend_id, "input": dict(input_data)},
            raw_result=raw_result,
            normalized_result=normalized_result,
            stdout=stdout,
            stderr=stderr,
        )

    return AssuranceRunOutcome(
        decision=decision,
        execution_status=execution_status,
        indeterminate_reason=indeterminate_reason,
        profile=sealed_profile,
        result=result,
        invocation=invocation,
        snapshot=snapshot,
        evidence_dir=evidence_path,
        raw_result=raw_result,
        normalized_result=normalized_result,
    )


def load_json_mapping(path: Path | str) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise AssuranceError(f"expected JSON object in {path}")
    return data
