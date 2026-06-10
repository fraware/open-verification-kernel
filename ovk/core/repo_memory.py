"""Repository memory for router priors and lane history."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ovk.core.bundle import content_digest


MEMORY_DIR = Path(".verification/memory")


def _backend_outcomes(bundle_payload: dict[str, Any]) -> list[dict[str, str]]:
    """Extract backend pass/fail outcomes from a bundle payload."""
    outcomes: list[dict[str, str]] = []
    for evidence in bundle_payload.get("evidence", []):
        for claim in evidence.get("backend_claims", []):
            backend = str(claim.get("backend", "unknown"))
            status = str(claim.get("status", "unknown"))
            outcomes.append({"backend": backend, "status": status})
    return outcomes


def record_run(bundle_payload: dict[str, Any], *, memory_dir: Path = MEMORY_DIR) -> Path:
    """Persist a compact run summary for future routing."""
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
    """Compute backend success rates from stored run summaries."""
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
        passes = sum(1 for status in statuses if status == "pass")
        rates[backend] = passes / len(statuses) if statuses else 0.0
    return rates


def router_historical_priors(*, memory_dir: Path = MEMORY_DIR) -> dict[str, float]:
    """Map backend tool names to historical success priors from repository memory."""
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
    """Compute coarse lane success rates from stored runs."""
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
    for lane, decisions in counts.items():
        passes = sum(1 for item in decisions if item == "allow")
        rates[lane] = passes / len(decisions) if decisions else 0.0
    return rates
