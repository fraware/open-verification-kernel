"""Deployment state compiler with explicit trust injection.

Untrusted ``approved=true`` JSON cannot authorize. Strict compilation requires
a caller-supplied authentication result from a protected acquisition verifier;
material fields inside the deployment document can never assert their own trust.
"""

from __future__ import annotations

from typing import Any

from ovk.compilers.deployment.ir import DeploymentIR, DeploymentState, DeploymentTransition

_SCHEMA = "ovk.deployment_state.v1"
_REQUIRED_FIELDS = (
    "system_identity",
    "environment",
    "revision",
    "events",
)


def compile_deployment_state(
    data: dict[str, Any],
    *,
    acquisition_trusted: bool = False,
) -> DeploymentIR:
    """Compile a deployment_state.v1 document into DeploymentIR.

    ``acquisition_trusted`` is deliberately not derivable from ``data``. It may
    be set only by a caller that authenticated a subject-bound acquisition
    artifact against an external trust root. The default therefore fails closed.
    """
    unsupported: list[str] = []
    warnings: list[str] = []

    schema = str(data.get("schema_version") or data.get("schema") or "")
    if schema != _SCHEMA:
        unsupported.append("missing_or_invalid_deployment_state_schema")

    if not acquisition_trusted:
        unsupported.append("untrusted_deployment_state_acquisition")
        if data.get("approved") is True:
            unsupported.append("untrusted_approved_true_json")

    for field in _REQUIRED_FIELDS:
        if field not in data:
            unsupported.append(f"missing_field:{field}")

    revision = data.get("revision") or data.get("image_digest")
    if not revision:
        unsupported.append("missing_revision_or_image_digest")

    # Presence of a signature-like field is never authentication. Keep the
    # diagnostic because authenticated collectors are expected to expose an
    # attestation reference, but trust comes solely from acquisition_trusted.
    acquisition = data.get("_ovk_acquisition") if isinstance(data.get("_ovk_acquisition"), dict) else None
    if not data.get("signature") and not (acquisition and acquisition.get("signature_ref")):
        warnings.append("signature_or_attestation_reference_not_exposed")

    events = data.get("events") if isinstance(data.get("events"), list) else []
    states: list[DeploymentState] = []
    transitions: list[DeploymentTransition] = []
    seen_states: set[str] = set()
    required = [str(item) for item in (data.get("required_gates") or data.get("required_states") or [])]
    production = [str(item) for item in (data.get("production_states") or ["production"])]

    previous: str | None = str(data.get("prior_state") or "prior") if data.get("prior_state") or events else None
    if previous:
        seen_states.add(previous)
        states.append(DeploymentState(name=previous, production=False, required=False))

    for index, event in enumerate(events):
        if not isinstance(event, dict):
            unsupported.append(f"events[{index}]_not_object")
            continue
        target = str(event.get("to") or event.get("state") or f"event-{index}")
        actor = event.get("actor")
        approvals = event.get("approvals") if isinstance(event.get("approvals"), list) else []
        if target not in seen_states:
            states.append(
                DeploymentState(
                    name=target,
                    production=target in production,
                    required=target in required,
                )
            )
            seen_states.add(target)
        if previous:
            transitions.append(
                DeploymentTransition(
                    source=previous,
                    target=target,
                    label=str(event.get("label") or event.get("type") or "transition"),
                )
            )
        if target in production and required and not approvals and not actor:
            unsupported.append(f"events[{index}]:production_transition_missing_actor_or_approvals")
        previous = target

    if not events:
        warnings.append("events missing")
    if unsupported:
        warnings.append("strict_requires_authenticated_deployment_state_v1")

    return DeploymentIR(
        source="deployment_state.v1",
        initial_state=str(data.get("prior_state")) if data.get("prior_state") else None,
        states=states,
        transitions=transitions,
        required_states=required,
        production_states=production,
        warnings=warnings,
        unsupported_constructs=sorted(set(unsupported)),
    )


def is_trusted_deployment_state(
    data: dict[str, Any],
    *,
    acquisition_trusted: bool = False,
) -> bool:
    """Return whether a valid deployment schema also has external authentication."""
    return (
        acquisition_trusted
        and str(data.get("schema_version") or data.get("schema") or "") == _SCHEMA
    )
