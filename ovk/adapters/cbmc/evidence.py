"""CBMC bounded model checking adapter with deterministic fallback."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ovk.adapters.cbmc.adapter import ADAPTER
from ovk.adapters.cbmc.deterministic import evaluate_cbmc_input
from ovk.adapters.cbmc.harness_compiler import compile_cbmc_harness, obligation_has_runnable_harness
from ovk.adapters.cbmc.optional_runner import run_cbmc_harness
from ovk.core.models import BackendClaim, VerificationEvidence, VerificationStatus


def evaluate_cbmc_harness(
    data: dict[str, Any],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None = None,
) -> VerificationEvidence:
    """Produce OVK evidence with honest native, synthetic, and fallback labeling."""
    payload = {**data, "intent_id": data.get("intent_id", "cbmc-harness-check")}
    intent_id = str(payload["intent_id"])
    limits = list(ADAPTER.capability_manifest.get("limits", []))

    native: dict[str, Any] | None = None
    compiled = payload
    if obligation_has_runnable_harness(payload):
        compiled = compile_cbmc_harness(payload)
        native = run_cbmc_harness(
            harness_path=Path(str(compiled["harness_path"])),
            entry_function=str(compiled.get("entry_function", "harness")),
            unwind=int(compiled["unwind"]) if compiled.get("unwind") is not None else None,
            failure_mode=str(compiled.get("failure_mode", "cbmc_assertion_failed")),
        )

    harness_origin = str(compiled.get("harness_origin", "none"))
    if native is not None and native.get("native_attempted"):
        status = VerificationStatus(str(native.get("status", "unknown")))
        counterexamples = list(native.get("counterexamples", []))
        assumptions = [
            f"{ADAPTER.backend_name} adapter contract evaluation.",
            f"{ADAPTER.binary_name} native harness execution was attempted within stated unwind and memory bounds.",
        ]
        if harness_origin == "explicit":
            guarantee_type = "bounded_model_checking"
            assumptions.append("The harness was explicitly supplied by the caller and is the verified program model.")
        else:
            guarantee_type = "template_harness_model_check"
            assumptions.append(
                "The executed harness is a reusable OVK template model selected or generated from extracted risk hints."
            )
            limits.append(
                "Template harness results do not establish that the changed project source was compiled into the checked model."
            )
        if native.get("reason"):
            assumptions.append(str(native["reason"]))
    else:
        status_raw, counterexamples = evaluate_cbmc_input(payload)
        status = VerificationStatus(status_raw)
        assumptions = [
            f"{ADAPTER.backend_name} adapter contract evaluation.",
            f"{ADAPTER.backend_name} adapter uses deterministic fallback when native execution is unavailable.",
            f"{ADAPTER.binary_name} deterministic oracle result used.",
            "The deterministic oracle classifies supplied findings and does not model-check changed project source.",
        ]
        if obligation_has_runnable_harness(payload) and native is not None:
            assumptions.append(str(native.get("reason", "cbmc binary unavailable.")))
        guarantee_type = "deterministic_fallback"

    merge_by_status = {
        VerificationStatus.PASS: "allow",
        VerificationStatus.FAIL: "block",
        VerificationStatus.UNKNOWN: "require_human_review",
        VerificationStatus.ERROR: "require_human_review",
        VerificationStatus.SKIPPED: "require_human_review",
    }
    recommendation = merge_by_status.get(status, "require_human_review")
    subject: dict[str, Any] = {"repo": repo, "head_sha": head_sha}
    if base_sha is not None:
        subject["base_sha"] = base_sha

    generated_artifacts: list[dict[str, Any]] = []
    if native is not None and native.get("native_attempted"):
        generated_artifacts.append(
            {
                "kind": "backend_provenance",
                "backend": ADAPTER.backend_name,
                "native_attempted": True,
                "used_native_binary": bool(native.get("used_native_binary")),
                "native_status": native.get("status"),
                "native_reason": native.get("reason"),
                "harness_path": compiled.get("harness_path"),
                "harness_origin": harness_origin,
                "source_path": payload.get("source_path"),
                "entry_function": compiled.get("entry_function"),
                "unwind": compiled.get("unwind"),
                "tool_version": native.get("tool_version"),
            }
        )

    return VerificationEvidence(
        evidence_id=f"{ADAPTER.backend_name}-{head_sha[:8]}",
        subject=subject,
        intent={
            "intent_id": intent_id,
            "title": intent_id.replace("-", " ").title(),
            "risk": {"severity": "medium"},
        },
        backend_claims=[
            BackendClaim(
                backend=ADAPTER.backend_name,
                guarantee_type=guarantee_type,
                status=status,
                assumptions=assumptions,
                limits=limits,
                tool_version=native.get("tool_version") if native else None,
                adapter_version=ADAPTER.adapter_version,
            )
        ],
        counterexamples=counterexamples,
        generated_artifacts=generated_artifacts,
        decision={
            "merge_recommendation": recommendation,
            "human_review_required": recommendation in {"require_human_review", "require_stronger_check"},
        },
    )
