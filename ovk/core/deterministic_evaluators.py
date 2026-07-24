"""Pure deterministic evaluator functions executed in isolated workers."""

from __future__ import annotations

from typing import Any

from ovk.adapters.ci_secrets.exposure import find_ci_secrets_counterexamples
from ovk.adapters.deployment.state_machine import find_skipped_approval_paths
from ovk.adapters.infra.exposure import find_exposure_counterexamples
from ovk.adapters.infra.validation import validate_infra_input
from ovk.adapters.opa.self_protection import (
    find_self_protection_unknowns,
    find_self_protection_violations,
)
from ovk.adapters.z3.counterexample import counterexamples_from_obligation
from ovk.adapters.z3.executor import run_authorization_obligation_with_z3
from ovk.adapters.z3.obligation import build_authorization_obligation
from ovk.adapters.z3.validation import validate_authorization_input

EVALUATOR_IDS = frozenset(
    {
        "authorization-deterministic",
        "self-protection-deterministic",
        "infrastructure-deterministic",
        "ci-secrets-deterministic",
        "deployment-deterministic",
        "z3-authorization-native",
    }
)


def evaluate_deterministic(evaluator_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Run one registered evaluator and return a JSON-serializable result envelope."""
    if evaluator_id not in EVALUATOR_IDS:
        return {
            "termination": "tool_error",
            "exit_code": 1,
            "raw_result": {
                "status": "error",
                "reason": f"unknown evaluator_id: {evaluator_id}",
            },
        }
    dispatch = {
        "authorization-deterministic": _evaluate_authorization_deterministic,
        "self-protection-deterministic": _evaluate_self_protection_deterministic,
        "infrastructure-deterministic": _evaluate_infrastructure_deterministic,
        "ci-secrets-deterministic": _evaluate_ci_secrets_deterministic,
        "deployment-deterministic": _evaluate_deployment_deterministic,
        "z3-authorization-native": _evaluate_z3_authorization_native,
    }
    return dispatch[evaluator_id](payload)


def _evaluate_authorization_deterministic(payload: dict[str, Any]) -> dict[str, Any]:
    data = dict(payload.get("input") or {})
    issues = validate_authorization_input(data)
    if issues:
        return {
            "termination": "invalid_output",
            "exit_code": 1,
            "raw_result": {
                "status": "unknown",
                "reason": "malformed authorization input",
                "issues": issues,
                "models": [],
                "counterexamples": [],
            },
        }
    auth_obligation = build_authorization_obligation(data)
    counterexamples = counterexamples_from_obligation(auth_obligation)
    return {
        "termination": "completed",
        "exit_code": 0,
        "raw_result": {
            "status": "fail" if counterexamples else "pass",
            "reason": (
                "deterministic violation witness found"
                if counterexamples
                else "no deterministic violation witness found"
            ),
            "models": counterexamples,
            "counterexamples": counterexamples,
        },
    }


def _evaluate_self_protection_deterministic(payload: dict[str, Any]) -> dict[str, Any]:
    data = dict(payload.get("input") or {})
    violations = find_self_protection_violations(data)
    unknowns = find_self_protection_unknowns(data)
    if violations:
        status = "fail"
        counterexamples = [item.as_counterexample() for item in violations]
    elif unknowns:
        status = "unknown"
        counterexamples = [item.as_counterexample() for item in unknowns]
    else:
        status = "pass"
        counterexamples = []
    return {
        "termination": "completed",
        "exit_code": 0,
        "raw_result": {"status": status, "counterexamples": counterexamples},
    }


def _evaluate_infrastructure_deterministic(payload: dict[str, Any]) -> dict[str, Any]:
    data = dict(payload.get("input") or {})
    issues = validate_infra_input(data)
    if issues:
        return {
            "termination": "invalid_output",
            "exit_code": 1,
            "raw_result": {
                "status": "unknown",
                "counterexamples": [
                    {
                        "summary": issue.message,
                        "failure_mode": "infrastructure_abstraction_invalid",
                        "path": issue.path,
                    }
                    for issue in issues
                ],
            },
        }
    counterexamples = find_exposure_counterexamples(data)
    return {
        "termination": "completed",
        "exit_code": 0,
        "raw_result": {
            "status": "fail" if counterexamples else "pass",
            "counterexamples": counterexamples,
        },
    }


def _evaluate_ci_secrets_deterministic(payload: dict[str, Any]) -> dict[str, Any]:
    data = dict(payload.get("input") or {})
    workflows = data.get("workflows")
    if not isinstance(workflows, list) or not workflows:
        return {
            "termination": "invalid_output",
            "exit_code": 1,
            "raw_result": {
                "status": "unknown",
                "counterexamples": [
                    {
                        "summary": "Workflow abstraction is missing or empty.",
                        "failure_mode": "missing_workflow_abstraction",
                    }
                ],
            },
        }
    counterexamples = find_ci_secrets_counterexamples(data)
    return {
        "termination": "completed",
        "exit_code": 0,
        "raw_result": {
            "status": "fail" if counterexamples else "pass",
            "counterexamples": counterexamples,
        },
    }


def _evaluate_deployment_deterministic(payload: dict[str, Any]) -> dict[str, Any]:
    data = dict(payload.get("input") or {})
    if not data.get("states") or not data.get("transitions"):
        return {
            "termination": "invalid_output",
            "exit_code": 1,
            "raw_result": {
                "status": "unknown",
                "counterexamples": [
                    {
                        "summary": "State machine abstraction is missing states or transitions.",
                        "failure_mode": "missing_state_machine_abstraction",
                    }
                ],
            },
        }
    counterexamples = find_skipped_approval_paths(data)
    return {
        "termination": "completed",
        "exit_code": 0,
        "raw_result": {
            "status": "fail" if counterexamples else "pass",
            "counterexamples": counterexamples,
        },
    }


def _evaluate_z3_authorization_native(payload: dict[str, Any]) -> dict[str, Any]:
    data = dict(payload.get("input") or {})
    issues = validate_authorization_input(data)
    if issues:
        return {
            "termination": "invalid_output",
            "exit_code": 1,
            "native_execution": False,
            "raw_result": {
                "status": "unknown",
                "reason": "malformed input",
                "issues": issues,
                "models": [],
            },
        }
    auth_obligation = build_authorization_obligation(data)
    native_raw = run_authorization_obligation_with_z3(auth_obligation)
    from ovk.adapters.z3.result import normalize_z3_authorization_result

    normalized = normalize_z3_authorization_result(native_raw)
    native_execution = native_raw.get("reason") != "z3-solver is not installed"
    termination = "tool_unavailable" if native_raw.get("reason") == "z3-solver is not installed" else "completed"
    return {
        "termination": termination,
        "exit_code": 0 if termination == "completed" else 1,
        "native_execution": native_execution,
        "raw_result": {
            "status": normalized["status"],
            "reason": native_raw.get("reason"),
            "models": native_raw.get("models", []),
            "counterexamples": normalized.get("counterexamples", []),
        },
    }
