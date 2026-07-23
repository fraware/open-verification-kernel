"""Template conformance matrix: honest production readiness for intent templates.

A template is ``catalog_only`` unless every required executable link exists.
Public executable claims that lack a compiler/adapter/example/test path are
downgraded honestly rather than advertised as strict-eligible.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from ovk.core.json_io import read_json_file

ProductionStatus = Literal[
    "catalog_only",
    "experimental",
    "advisory",
    "strict_eligible",
    "deprecated",
]

REQUIRED_ROW_FIELDS = (
    "intent_id",
    "path",
    "domain",
    "version",
    "production_status",
    "risk_severity",
    "property_kind",
    "acceptable_evidence_kinds",
    "claimed_backends",
    "executable_links",
    "missing_executable_links",
    "lane",
    "notes",
)

# Links that must all exist for a template to leave catalog_only.
REQUIRED_EXECUTABLE_LINKS = (
    "intent_file",
    "lane_evaluator",
    "neutral_compiler",
    "backend_registry",
    "pass_example",
    "fail_example",
    "enforcement_test",
)

# Intents with real enforced control-plane paths today.
EXECUTABLE_CATALOG: dict[str, dict[str, Any]] = {
    "no-admin-route-bypass": {
        "lane": "authorization",
        "claimed_backends": ["z3-native", "authorization-deterministic"],
        "links": {
            "lane_evaluator": "ovk/adapters/authorization/deterministic_adapter.py",
            "neutral_compiler": "ovk/core/authorization_compiler.py",
            "backend_registry": "ovk/adapters/authorization/__init__.py",
            "pass_example": "examples/auth_regression/input_admin_protected.json",
            "fail_example": "examples/auth_regression/input_admin_bypass.json",
            "enforcement_test": "tests/test_authorization_enforcement.py",
        },
        "max_status": "strict_eligible",
    },
    "agent-cannot-disable-own-ci-gate": {
        "lane": "self_protection",
        "claimed_backends": ["opa-native", "self-protection-deterministic"],
        "links": {
            "lane_evaluator": "ovk/adapters/self_protection/deterministic_adapter.py",
            "neutral_compiler": "ovk/core/self_protection_compiler.py",
            "backend_registry": "ovk/adapters/self_protection/__init__.py",
            "pass_example": "examples/no_agent_self_approval/input_gate_preserved.json",
            "fail_example": "examples/no_agent_self_approval/input_gate_removed.json",
            "enforcement_test": "tests/test_self_protection_enforcement.py",
        },
        "max_status": "strict_eligible",
    },
    "no-public-sensitive-resource": {
        "lane": "infrastructure",
        "claimed_backends": ["infrastructure-deterministic"],
        "links": {
            "lane_evaluator": "ovk/adapters/infrastructure/deterministic_adapter.py",
            "neutral_compiler": "ovk/core/infrastructure_compiler.py",
            "backend_registry": "ovk/adapters/infrastructure/__init__.py",
            "pass_example": "examples/infrastructure_exposure/input_private_sensitive_resource.json",
            "fail_example": "examples/infrastructure_exposure/input_public_sensitive_resource.json",
            "enforcement_test": "tests/test_remaining_lane_enforcement.py",
        },
        "max_status": "strict_eligible",
    },
    "no-secrets-in-untrusted-context": {
        "lane": "ci_secrets",
        "claimed_backends": ["ci-secrets-deterministic"],
        "links": {
            "lane_evaluator": "ovk/adapters/ci_secrets/deterministic_adapter.py",
            "neutral_compiler": "ovk/core/ci_secrets_compiler.py",
            "backend_registry": "ovk/adapters/ci_secrets/__init__.py",
            "pass_example": "examples/ci_secrets/input_secrets_safe.json",
            "fail_example": "examples/ci_secrets/input_secrets_exposed.json",
            "enforcement_test": "tests/test_remaining_lane_enforcement.py",
        },
        "max_status": "strict_eligible",
    },
    "no-skipped-approval-state": {
        "lane": "deployment",
        "claimed_backends": ["deployment-deterministic"],
        "links": {
            "lane_evaluator": "ovk/adapters/deployment/deterministic_adapter.py",
            "neutral_compiler": "ovk/core/deployment_compiler.py",
            "backend_registry": "ovk/adapters/deployment/__init__.py",
            "pass_example": "examples/deployment_state/input_valid_approval_path.json",
            "fail_example": "examples/deployment_state/input_skipped_approval.json",
            "enforcement_test": "tests/test_remaining_lane_enforcement.py",
        },
        "max_status": "strict_eligible",
    },
}

# Backend tokens that imply a public native/executable claim when present in
# intent_id or title. Without a matching executable catalog entry, status is
# forced down from any advertised executable readiness.
NATIVE_CLAIM_TOKENS = (
    "cbmc",
    "kani",
    "dafny",
    "verus",
    "lean",
    "alloy",
    "tla",
    "cedar",
    "z3",
    "opa",
)

STATUS_RANK = {
    "deprecated": 0,
    "catalog_only": 1,
    "experimental": 2,
    "advisory": 3,
    "strict_eligible": 4,
}


@dataclass(frozen=True)
class TemplateConformanceRow:
    intent_id: str
    path: str
    domain: str
    version: str
    production_status: ProductionStatus
    risk_severity: str
    property_kind: str
    acceptable_evidence_kinds: list[str]
    claimed_backends: list[str]
    executable_links: dict[str, bool]
    missing_executable_links: list[str]
    lane: str | None
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent_id": self.intent_id,
            "path": self.path,
            "domain": self.domain,
            "version": self.version,
            "production_status": self.production_status,
            "risk_severity": self.risk_severity,
            "property_kind": self.property_kind,
            "acceptable_evidence_kinds": list(self.acceptable_evidence_kinds),
            "claimed_backends": list(self.claimed_backends),
            "executable_links": dict(self.executable_links),
            "missing_executable_links": list(self.missing_executable_links),
            "lane": self.lane,
            "notes": list(self.notes),
        }


def _infer_claimed_backends(intent_id: str, title: str, catalog_entry: dict[str, Any] | None) -> list[str]:
    if catalog_entry and catalog_entry.get("claimed_backends"):
        return sorted(str(item) for item in catalog_entry["claimed_backends"])
    blob = f"{intent_id} {title}".lower().replace("_", "-")
    found = [token for token in NATIVE_CLAIM_TOKENS if token in blob]
    return found


def _link_presence(repo_root: Path, catalog_entry: dict[str, Any] | None, intent_path: Path) -> dict[str, bool]:
    links = {name: False for name in REQUIRED_EXECUTABLE_LINKS}
    links["intent_file"] = intent_path.is_file()
    if not catalog_entry:
        return links
    declared = catalog_entry.get("links") or {}
    for name in REQUIRED_EXECUTABLE_LINKS:
        if name == "intent_file":
            continue
        rel = declared.get(name)
        links[name] = bool(rel) and (repo_root / str(rel)).is_file()
    return links


def _min_status(current: ProductionStatus, ceiling: ProductionStatus) -> ProductionStatus:
    if STATUS_RANK[current] <= STATUS_RANK[ceiling]:
        return current
    return ceiling


def classify_template(
    *,
    repo_root: Path,
    intent_path: Path,
    template: dict[str, Any],
) -> TemplateConformanceRow:
    """Classify one template into an honest production status."""
    intent_id = str(template.get("intent_id") or intent_path.stem)
    catalog_entry = EXECUTABLE_CATALOG.get(intent_id)
    links = _link_presence(repo_root, catalog_entry, intent_path)
    missing = sorted(name for name, present in links.items() if not present)
    claimed = _infer_claimed_backends(
        intent_id,
        str(template.get("title") or ""),
        catalog_entry,
    )
    notes: list[str] = []
    lane = str(catalog_entry["lane"]) if catalog_entry else None

    if not missing:
        status: ProductionStatus = str(catalog_entry.get("max_status", "strict_eligible"))  # type: ignore[assignment]
        notes.append("all required executable links present")
    elif catalog_entry and links.get("neutral_compiler") and links.get("backend_registry"):
        status = "experimental"
        notes.append("partial executable path; missing: " + ", ".join(missing))
    elif catalog_entry:
        status = "advisory"
        notes.append("catalog entry exists but executable links incomplete")
    else:
        status = "catalog_only"
        notes.append("no enforced executable path registered")

    # Honest downgrade for native-named templates without executable catalog entry.
    if claimed and intent_id not in EXECUTABLE_CATALOG:
        status = _min_status(status, "catalog_only")
        notes.append(
            "downgraded unsupported public executable claim for backends: " + ", ".join(claimed)
        )

    if template.get("deprecated") is True:
        status = "deprecated"
        notes.append("template marked deprecated")

    relative = intent_path.relative_to(repo_root).as_posix() if intent_path.is_absolute() else intent_path.as_posix()
    evidence = template.get("acceptable_evidence") or []
    evidence_kinds = sorted(
        {
            str(item.get("kind"))
            for item in evidence
            if isinstance(item, dict) and item.get("kind")
        }
    )
    risk = template.get("risk") if isinstance(template.get("risk"), dict) else {}
    prop = template.get("property") if isinstance(template.get("property"), dict) else {}
    return TemplateConformanceRow(
        intent_id=intent_id,
        path=relative,
        domain=str(template.get("domain") or intent_path.parent.name),
        version=str(template.get("version") or ""),
        production_status=status,
        risk_severity=str(risk.get("severity") or "unknown"),
        property_kind=str(prop.get("kind") or "unknown"),
        acceptable_evidence_kinds=evidence_kinds,
        claimed_backends=claimed,
        executable_links=links,
        missing_executable_links=missing,
        lane=lane,
        notes=notes,
    )


def build_conformance_matrix(repo_root: Path, templates_dir: Path | None = None) -> dict[str, Any]:
    """Scan templates and build the conformance matrix document."""
    templates_dir = templates_dir or (repo_root / "templates")
    rows: list[TemplateConformanceRow] = []
    for path in sorted(templates_dir.rglob("*.intent.json")):
        template = read_json_file(path)
        rows.append(classify_template(repo_root=repo_root, intent_path=path, template=template))

    by_status = Counter(row.production_status for row in rows)
    by_domain = Counter(row.domain for row in rows)
    payload = {
        "schema_version": "ovk.template_conformance.v1",
        "template_count": len(rows),
        "required_row_fields": list(REQUIRED_ROW_FIELDS),
        "required_executable_links": list(REQUIRED_EXECUTABLE_LINKS),
        "production_statuses": list(STATUS_RANK.keys()),
        "counts_by_status": dict(sorted(by_status.items())),
        "counts_by_domain": dict(sorted(by_domain.items())),
        "templates": [row.to_dict() for row in rows],
    }
    return payload


def validate_matrix(matrix: dict[str, Any]) -> list[str]:
    """Return gate failures for a conformance matrix."""
    failures: list[str] = []
    if matrix.get("schema_version") != "ovk.template_conformance.v1":
        failures.append("schema_version must be ovk.template_conformance.v1")
    templates = matrix.get("templates")
    if not isinstance(templates, list) or not templates:
        failures.append("templates must be a non-empty list")
        return failures
    for index, row in enumerate(templates):
        if not isinstance(row, dict):
            failures.append(f"templates[{index}] must be an object")
            continue
        for field in REQUIRED_ROW_FIELDS:
            if field not in row:
                failures.append(f"templates[{index}] missing required field {field}")
        status = row.get("production_status")
        if status not in STATUS_RANK:
            failures.append(f"templates[{index}] invalid production_status {status!r}")
        missing = row.get("missing_executable_links") or []
        if status in {"strict_eligible", "advisory"} and missing and status == "strict_eligible":
            failures.append(
                f"{row.get('intent_id')}: strict_eligible requires empty missing_executable_links"
            )
        # catalog_only is mandatory when required links are incomplete and no
        # experimental/advisory catalog path was registered.
        if (
            status not in {"deprecated", "experimental", "advisory", "strict_eligible"}
            and status != "catalog_only"
            and missing
        ):
            failures.append(f"{row.get('intent_id')}: incomplete links must not claim {status}")
    return failures


def domain_counts_markdown(matrix: dict[str, Any]) -> str:
    """Render README-style domain count rows from the matrix."""
    counts = matrix.get("counts_by_domain") or {}
    lines = ["| Domain | Count |", "|---|---|"]
    for domain in sorted(counts):
        lines.append(f"| `{domain}/` | {counts[domain]} |")
    lines.append(f"| **total** | **{matrix.get('template_count', 0)}** |")
    return "\n".join(lines) + "\n"


def write_conformance_matrix(repo_root: Path, output: Path) -> dict[str, Any]:
    matrix = build_conformance_matrix(repo_root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return matrix
