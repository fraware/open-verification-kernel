"""OPA-style self-protection adapter.

This module implements the first end-to-end OVK policy check.

Policy intent:
An AI-authored pull request must preserve the verification controls that govern
its own merge.

The implementation deliberately returns OVK evidence, not a bare boolean.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ovk.core.models import BackendClaim, VerificationEvidence, VerificationStatus


DEFAULT_GATE_NAME = "ovk-verify"
INTENT_ID = "agent-cannot-disable-own-ci-gate"
INTENT_TITLE = "Agent-authored PR cannot weaken its own verification gate"
HIGH_RISK_PREFIXES = (".github/workflows/", ".github/rulesets/", ".verification/")
HIGH_RISK_FILES = {"CODEOWNERS"}


@dataclass(frozen=True)
class SelfProtectionViolation:
    """A concrete self-protection policy violation."""

    failure_mode: str
    summary: str
    affected_file: str | None = None

    def as_counterexample(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "summary": self.summary,
            "failure_mode": self.failure_mode,
        }
        if self.affected_file:
            data["affected_file"] = self.affected_file
        return data


@dataclass(frozen=True)
class SelfProtectionUnknown:
    """A reason the self-protection check cannot make a passing claim."""

    reason: str
    affected_file: str | None = None

    def as_counterexample(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "summary": self.reason,
            "failure_mode": "missing_required_metadata",
        }
        if self.affected_file:
            data["affected_file"] = self.affected_file
        return data


def _phase(data: dict[str, Any], phase: str) -> dict[str, Any]:
    value = data.get(phase, {})
    return value if isinstance(value, dict) else {}


def _required_checks(data: dict[str, Any], phase: str) -> set[str]:
    checks = _phase(data, phase).get("required_checks", [])
    if not isinstance(checks, list):
        return set()
    return {str(check) for check in checks}


def _has_required_check_metadata(data: dict[str, Any], phase: str) -> bool:
    return isinstance(_phase(data, phase).get("required_checks"), list)


def _changed_files(data: dict[str, Any]) -> list[str]:
    files = data.get("changed_files", [])
    if not isinstance(files, list):
        return []
    return [str(path) for path in files]


def _actor_type(data: dict[str, Any]) -> str:
    return str(data.get("actor", {}).get("type", data.get("author_type", "unknown")))


def _agent_id(data: dict[str, Any]) -> str:
    return str(data.get("actor", {}).get("id", data.get("agent", "unknown")))


def _is_high_risk_path(path: str) -> bool:
    return path in HIGH_RISK_FILES or any(path.startswith(prefix) for prefix in HIGH_RISK_PREFIXES)


def _high_risk_changed_files(data: dict[str, Any]) -> list[str]:
    return [path for path in _changed_files(data) if _is_high_risk_path(path)]


def find_self_protection_violations(data: dict[str, Any]) -> list[SelfProtectionViolation]:
    """Return concrete violations for the first OVK self-protection template."""
    violations: list[SelfProtectionViolation] = []
    actor_type = _actor_type(data)
    gate_name = str(data.get("ovk_gate_name", DEFAULT_GATE_NAME))
    before_required = _required_checks(data, "before")
    after_required = _required_checks(data, "after")
    changed_files = _changed_files(data)

    if actor_type != "ai_agent":
        return violations

    if gate_name in before_required and gate_name not in after_required:
        affected = next((path for path in changed_files if path.startswith(".github/")), None)
        violations.append(
            SelfProtectionViolation(
                failure_mode="required_check_removed",
                summary=f"Agent-authored change removed required verification gate {gate_name}.",
                affected_file=affected,
            )
        )

    for path in changed_files:
        if path.startswith(".verification/"):
            violations.append(
                SelfProtectionViolation(
                    failure_mode="verification_config_changed_by_agent",
                    summary="Agent-authored change modified OVK configuration or local verification memory.",
                    affected_file=path,
                )
            )

    permissions_after = _phase(data, "after").get("workflow_permissions", {})
    permissions_before = _phase(data, "before").get("workflow_permissions", {})
    if isinstance(permissions_after, dict):
        before_actions = (
            str(permissions_before.get("actions", "read")) if isinstance(permissions_before, dict) else "read"
        )
        after_actions = str(permissions_after.get("actions", "read"))
        if before_actions != "write" and after_actions == "write":
            violations.append(
                SelfProtectionViolation(
                    failure_mode="permissions_escalated",
                    summary="Agent-authored change escalated workflow actions permission to write.",
                    affected_file=next((p for p in changed_files if p.startswith(".github/")), None),
                )
            )

    return violations


def find_self_protection_unknowns(data: dict[str, Any]) -> list[SelfProtectionUnknown]:
    """Return reasons OVK cannot safely claim pass for a high-risk change."""
    if _actor_type(data) != "ai_agent":
        return []

    high_risk_files = _high_risk_changed_files(data)
    if not high_risk_files:
        return []

    unknowns: list[SelfProtectionUnknown] = []
    if not _has_required_check_metadata(data, "before"):
        unknowns.append(
            SelfProtectionUnknown(
                reason="Before-state required-check metadata is missing for an agent-authored high-risk change.",
                affected_file=high_risk_files[0],
            )
        )
    if not _has_required_check_metadata(data, "after"):
        unknowns.append(
            SelfProtectionUnknown(
                reason="After-state required-check metadata is missing for an agent-authored high-risk change.",
                affected_file=high_risk_files[0],
            )
        )
    return unknowns


def evaluate_self_protection(
    data: dict[str, Any],
    *,
    repo: str = "unknown/repo",
    pull_request: int | str | None = None,
    head_sha: str = "unknown",
    base_sha: str | None = None,
) -> VerificationEvidence:
    """Evaluate the self-protection policy and return OVK evidence."""
    violations = find_self_protection_violations(data)
    unknowns = find_self_protection_unknowns(data)

    if violations:
        status = VerificationStatus.FAIL
        merge_recommendation = "block"
        human_review_required = True
    elif unknowns:
        status = VerificationStatus.UNKNOWN
        merge_recommendation = "require_human_review"
        human_review_required = True
    else:
        status = VerificationStatus.PASS
        merge_recommendation = "allow"
        human_review_required = False

    subject: dict[str, Any] = {"repo": repo, "head_sha": head_sha}
    if pull_request is not None:
        subject["pull_request"] = pull_request
    if base_sha is not None:
        subject["base_sha"] = base_sha

    counterexamples = [violation.as_counterexample() for violation in violations]
    if not counterexamples:
        counterexamples = [unknown.as_counterexample() for unknown in unknowns]

    return VerificationEvidence(
        evidence_id="ev-agent-self-protection",
        schema_version="ovk.evidence.v1",
        subject=subject,
        change_origin={
            "author_type": _actor_type(data),
            "agent": _agent_id(data),
            "task": data.get("task", "unknown"),
        },
        intent={
            "intent_id": INTENT_ID,
            "title": INTENT_TITLE,
            "risk": {"severity": "critical"},
        },
        backend_claims=[
            BackendClaim(
                backend="opa",
                guarantee_type="policy_evaluation",
                status=status,
                assumptions=[
                    "Required-check metadata must be represented in the input object for pass claims.",
                    "Changed workflow and verification files are represented in changed_files.",
                    "This Python evaluator mirrors the first policy semantics for CI portability.",
                ],
                limits=[
                    "This check does not prove semantic correctness of workflow steps.",
                    "This check only covers the first self-protection template.",
                ],
                adapter_version="0.1.0",
            )
        ],
        counterexamples=counterexamples,
        generated_artifacts=[
            {
                "kind": "regression_policy_test",
                "path": ".verification/generated_tests/no_agent_self_disable_test.rego",
            }
        ]
        if violations
        else [],
        decision={
            "merge_recommendation": merge_recommendation,
            "human_review_required": human_review_required,
            "override_allowed": human_review_required,
            "override_requires": ["maintainer", "security-review"] if human_review_required else [],
        },
    )
