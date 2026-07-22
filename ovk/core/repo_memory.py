"""Repository memory for advisory router priors and lane history."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from ovk.core.bundle import content_digest


MEMORY_DIR = Path(".verification/memory")
REPOSITORY_MEMORY_ENV = "OVK_ENABLE_REPOSITORY_MEMORY"
CONCLUSIVE_STATUSES = frozenset({"pass", "fail"})


def _backend_outcomes(bundle_payload: dict[str, Any]) -> list[dict[str, str]]:
    """Extract backend execution outcomes from a bundle payload."""
    outcomes: list[dict[str, str]] = []
    for evidence in bundle_payload.get("evidence", []):
        for claim in evidence.get("backend_claims", []):
            backend = str(claim.get("backend", "unknown"))
            status = str(claim.get("status", "unknown"))
            outcomes.append({"backend": backend, "status": status})
    return outcomes


def record_run(bundle_payload: dict[str, Any], *, memory_dir: Path = MEMORY_DIR) -> Path:
    """Persist a compact run summary for future advisory routing analysis."""
    memory_dir.mkdir(parents=True, exist_ok=True)
    digest = content_digest(bundle_payload)[:16]
    path = memory_dir / f"run-{digest}.json"
    summary = {
        "bundle_id": bundle_payload.get("bundle_id"),
        "decision": bundle_payload.get("decision"),
        "evidence_count": len(bundle_payload.get("evidence", [])),
        "lanes": [
            str(item.get("intent", {}).get("intent_id", item.get("intent_id", "unknown")))
            for item in bundle_payload.get("evidence", [])
        ],
        "backend_outcomes": _backend_outcomes(bundle_payload),
    }
    path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return path


def backend_success_rates(*, memory_dir: Path = MEMORY_DIR) -> dict[str, float]:
    """Compute backend conclusiveness rates from stored run summaries.

    A verifier failure is a successful, conclusive execution. Reliability priors
    therefore count both pass and fail as successful outcomes; unknown, skipped,
    and error outcomes reduce the score.
    """
    if not memory_dir.exists():
        return {}
    counts: dict[str, list[str]] = {}
    for path in memory_dir.glob("run-*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for outcome in payload.get("backend_outcomes", []):
            backend = str(outcome.get("backend", "unknown"))
            counts.setdefault(backend, []).append(str(outcome.get("status", "unknown")))
    rates: dict[str, float] = {}
    for backend, statuses in counts.items():
        conclusive = sum(1 for status in statuses if status in CONCLUSIVE_STATUSES)
        rates[backend] = conclusive / len(statuses) if statuses else 0.0
    return rates


def repository_memory_enabled() -> bool:
    """Return whether untrusted workspace memory is explicitly enabled."""
    return os.environ.get(REPOSITORY_MEMORY_ENV, "").strip().lower() in {"1", "true", "yes"}


def router_historical_priors(
    *,
    memory_dir: Path = MEMORY_DIR,
    enabled: bool | None = None,
) -> dict[str, float]:
    """Return advisory backend reliability priors when explicitly enabled.

    Pull-request workspaces are attacker-controlled. Repository memory remains
    disabled by default until it can be loaded from a trusted base-branch or
    signed external store.
    """
    use_memory = repository_memory_enabled() if enabled is None else enabled
    if not use_memory:
        return {}
    rates = backend_success_rates(memory_dir=memory_dir)
    if rates:
        return rates

    lane_rates = lane_success_rates(memory_dir=memory_dir)
    lane_backend_defaults = {
        "agent-cannot-disable-own-ci-gate": "opa",
        "no-admin-route-bypass": "z3",
        "no-public-sensitive-resource": "opa",
        "no-secrets-in-untrusted-context": "opa",
        "no-skipped-approval-state": "opa",
        "compilation-incomplete": "ovk",
    }
    priors: dict[str, float] = {}
    for lane, rate in lane_rates.items():
        backend = lane_backend_defaults.get(lane, "deterministic")
        priors[backend] = max(priors.get(backend, 0.0), rate)
    return priors


def lane_success_rates(*, memory_dir: Path = MEMORY_DIR) -> dict[str, float]:
    """Compute coarse lane conclusiveness rates from stored runs."""
    if not memory_dir.exists():
        return {}
    counts: dict[str, list[str]] = {}
    for path in memory_dir.glob("run-*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        decision = str(payload.get("decision", {}).get("merge_recommendation", "unknown"))
        for lane in payload.get("lanes", []):
            counts.setdefault(str(lane), []).append(decision)
    rates: dict[str, float] = {}
    conclusive_decisions = {"allow", "allow_with_warning", "block"}
    for lane, decisions in counts.items():
        conclusive = sum(1 for item in decisions if item in conclusive_decisions)
        rates[lane] = conclusive / len(decisions) if decisions else 0.0
    return rates
