"""Outcome-blind historical contract anchor extraction for RTK evaluation.

Inputs:
- a frozen transition census JSONL
- local Git checkouts of the frozen source repositories

Outputs:
- canonical JSONL HistoricalAnchor records
- a content-addressed manifest

This stage reads Git objects only. It does not execute source or target validators,
does not import RTK code, and does not read oracle labels.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any, Iterable


ABSENT = "ABSENT"
MALFORMED = "MALFORMED"
PENDING_SUBJECT = "PENDING_SOURCE_EVIDENCE"


def _git_bytes(repo: Path, *args: str, allow_failure: bool = False) -> bytes | None:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        if allow_failure:
            return None
        raise RuntimeError(
            f"git failed ({proc.returncode}): git -C {repo} {' '.join(args)}\n"
            + proc.stderr.decode("utf-8", errors="replace")
        )
    return proc.stdout


def _git_text(repo: Path, *args: str, allow_failure: bool = False) -> str | None:
    raw = _git_bytes(repo, *args, allow_failure=allow_failure)
    return None if raw is None else raw.decode("utf-8")


def _show(repo: Path, sha: str, path: str) -> bytes | None:
    return _git_bytes(repo, "show", f"{sha}:{path}", allow_failure=True)


def _list_paths(repo: Path, sha: str, prefix: str = "") -> list[str]:
    args = ["ls-tree", "-r", "--name-only", sha]
    if prefix:
        args.extend(["--", prefix])
    text = _git_text(repo, *args) or ""
    return sorted(line.strip() for line in text.splitlines() if line.strip())


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _typed_digest(tag: str, value: Any) -> str:
    return _sha256(tag.encode("utf-8") + b"\x00" + _canonical_bytes(value))


def _parse_json(raw: bytes | None) -> Any | None:
    if raw is None:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return MALFORMED


def _object(role: str, path: str, raw: bytes) -> dict[str, str]:
    return {"role": role, "path": path, "sha256": _sha256(raw)}


def _manifest_digest(objects: Iterable[dict[str, str]]) -> str:
    rows = sorted(
        (
            {"role": row["role"], "path": row["path"], "sha256": row["sha256"]}
            for row in objects
        ),
        key=lambda row: (row["role"], row["path"], row["sha256"]),
    )
    return _typed_digest("rtk-contract-manifest-v0", rows)


def _contract(status: str, objects: list[dict[str, str]]) -> dict[str, Any]:
    digest = _manifest_digest(objects) if objects else None
    return {"status": status, "digest": digest, "objects": sorted(objects, key=lambda x: (x["role"], x["path"]))}


def _path_digest(repo: Path, sha: str, path: str, tag: str) -> str:
    raw = _show(repo, sha, path)
    if raw is None:
        return f"{ABSENT}:{tag}"
    return _sha256(raw)


def _paths_digest(repo: Path, sha: str, paths: Iterable[str], tag: str) -> str:
    rows: list[dict[str, str]] = []
    for path in sorted(set(paths)):
        raw = _show(repo, sha, path)
        if raw is not None:
            rows.append({"path": path, "sha256": _sha256(raw)})
    if not rows:
        return f"{ABSENT}:{tag}"
    return _typed_digest(f"rtk-{tag}-manifest-v0", rows)


def _json_section_digest(value: Any, tag: str) -> str:
    if value is None:
        return f"{ABSENT}:{tag}"
    return _typed_digest(f"rtk-{tag}-v0", value)


def _contract_dimension(contract: dict[str, Any], tag: str) -> str:
    digest = contract.get("digest")
    if isinstance(digest, str):
        return digest
    return f"{contract.get('status', ABSENT)}:{tag}"


def _pair(source: str, target: str) -> dict[str, str]:
    return {"source": source, "target": target}


def _anchor_id(
    repository: str,
    source: str,
    target: str,
    family: str,
    claim_id: str,
    contract_locator: str,
) -> str:
    material = "\x00".join(
        ("rtk-anchor-v1", repository, source, target, family, claim_id, contract_locator)
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _require_fields(data: Any, fields: Iterable[str]) -> bool:
    return isinstance(data, dict) and all(field in data for field in fields)


def _schema_path_for_artifact(artifact: str) -> str:
    return f"schemas/{artifact}.schema.json"


def _certifyedge_schema_path_for_artifact(artifact: str) -> str:
    return f"schemas/pcs/{artifact}.schema.json"


def _certifyedge_contract(repo: Path, sha: str, profile_path: str) -> tuple[dict[str, Any], dict[str, Any] | str | None]:
    raw = _show(repo, sha, profile_path)
    parsed = _parse_json(raw)
    if raw is None:
        return _contract("ABSENT", []), None
    profile_obj = _object("profile", profile_path, raw)
    if parsed == MALFORMED:
        return _contract("MALFORMED", [profile_obj]), MALFORMED
    required = (
        "property_id",
        "template",
        "input_trace_artifact",
        "output_certificate_artifact",
        "valid_success_status",
        "valid_failure_status",
        "release_mode_required_fields",
        "formalization",
    )
    if not _require_fields(parsed, required):
        return _contract("MALFORMED", [profile_obj]), MALFORMED
    formalization = parsed.get("formalization")
    if not _require_fields(
        formalization,
        ("certificate_predicate", "required_fields", "admissible_status"),
    ):
        return _contract("MALFORMED", [profile_obj]), MALFORMED

    objects = [profile_obj]
    template_path = str(parsed["template"])
    template_raw = _show(repo, sha, template_path)
    if template_raw is not None:
        objects.append(_object("template", template_path, template_raw))

    artifact_names = [str(parsed["output_certificate_artifact"])]
    artifact_names.extend(str(x) for x in parsed.get("supporting_artifacts", []) if isinstance(x, str))
    for artifact in sorted(set(artifact_names)):
        schema_path = _certifyedge_schema_path_for_artifact(artifact)
        schema_raw = _show(repo, sha, schema_path)
        if schema_raw is not None:
            objects.append(_object(f"schema:{artifact}", schema_path, schema_raw))

    output_artifact = str(parsed["output_certificate_artifact"])
    registry_path = f"pcs_registry/{output_artifact}.registry.json"
    registry_raw = _show(repo, sha, registry_path)
    if registry_raw is not None:
        objects.append(_object("output_registry", registry_path, registry_raw))

    return _contract("PRESENT", objects), parsed


def _certifyedge_surface_paths(repo: Path, sha: str) -> tuple[list[str], list[str]]:
    evaluator = []
    for prefix in ("services/pcs-certificate", "cli"):
        for path in _list_paths(repo, sha, prefix):
            if path.endswith((".rs", ".py", ".json", ".stl")):
                evaluator.append(path)
    toolchain = [
        path
        for path in ("Cargo.lock", "Cargo.toml", "rust-toolchain.toml", "MODULE.bazel.lock")
        if _show(repo, sha, path) is not None
    ]
    return sorted(set(evaluator)), toolchain


def _certifyedge_anchors(repo: Path, transition: dict[str, Any]) -> list[dict[str, Any]]:
    source = str(transition["source_sha"])
    target = str(transition["target_sha"])
    source_profiles = [
        p for p in _list_paths(repo, source, "templates/profiles")
        if p.endswith(".json")
    ]
    evaluator_source, toolchain_source = _certifyedge_surface_paths(repo, source)
    evaluator_target, toolchain_target = _certifyedge_surface_paths(repo, target)

    rows: list[dict[str, Any]] = []
    for profile_path in source_profiles:
        source_contract, source_profile = _certifyedge_contract(repo, source, profile_path)
        if source_contract["status"] != "PRESENT" or not isinstance(source_profile, dict):
            continue
        target_contract, target_profile = _certifyedge_contract(repo, target, profile_path)
        claim_id = f"certifyedge-property:{source_profile['property_id']}"

        source_formal = source_profile.get("formalization", {})
        target_formal = target_profile.get("formalization", {}) if isinstance(target_profile, dict) else None

        source_output = str(source_profile["output_certificate_artifact"])
        target_output = str(target_profile["output_certificate_artifact"]) if isinstance(target_profile, dict) and "output_certificate_artifact" in target_profile else ""
        source_registry_path = f"pcs_registry/{source_output}.registry.json"
        target_registry_path = f"pcs_registry/{target_output}.registry.json" if target_output else ""

        dimensions = {
            "subject": _pair(PENDING_SUBJECT, PENDING_SUBJECT),
            "claim": _pair(
                _typed_digest("rtk-claim-id-v0", claim_id),
                _typed_digest("rtk-claim-id-v0", claim_id),
            ),
            "evaluator": _pair(
                _paths_digest(repo, source, evaluator_source, "certifyedge-evaluator"),
                _paths_digest(repo, target, evaluator_target, "certifyedge-evaluator"),
            ),
            "specification": _pair(
                _path_digest(repo, source, str(source_profile["template"]), "specification"),
                _path_digest(repo, target, str(target_profile["template"]) if isinstance(target_profile, dict) and "template" in target_profile else "__absent__", "specification"),
            ),
            "profile": _pair(
                _path_digest(repo, source, profile_path, "profile"),
                _path_digest(repo, target, profile_path, "profile"),
            ),
            "schema": _pair(
                _path_digest(repo, source, _certifyedge_schema_path_for_artifact(source_output), "schema"),
                _path_digest(repo, target, _certifyedge_schema_path_for_artifact(target_output) if target_output else "__absent__", "schema"),
            ),
            "policy": _pair(
                _json_section_digest(
                    {
                        "release_mode_required_fields": source_profile.get("release_mode_required_fields"),
                        "formalization": source_formal,
                    },
                    "certifyedge-policy",
                ),
                _json_section_digest(
                    {
                        "release_mode_required_fields": target_profile.get("release_mode_required_fields"),
                        "formalization": target_formal,
                    } if isinstance(target_profile, dict) else None,
                    "certifyedge-policy",
                ),
            ),
            "dependencies": _pair(
                _paths_digest(repo, source, toolchain_source, "dependencies"),
                _paths_digest(repo, target, toolchain_target, "dependencies"),
            ),
            "artifact_registry": _pair(
                _path_digest(repo, source, source_registry_path, "artifact-registry"),
                _path_digest(repo, target, target_registry_path if target_registry_path else "__absent__", "artifact-registry"),
            ),
            "toolchain": _pair(
                _paths_digest(repo, source, toolchain_source, "toolchain"),
                _paths_digest(repo, target, toolchain_target, "toolchain"),
            ),
            "protocol": _pair(
                _json_section_digest(
                    {
                        "input_trace_artifact": source_profile.get("input_trace_artifact"),
                        "output_certificate_artifact": source_profile.get("output_certificate_artifact"),
                        "valid_success_status": source_profile.get("valid_success_status"),
                        "valid_failure_status": source_profile.get("valid_failure_status"),
                        "certificate_predicate": source_formal.get("certificate_predicate") if isinstance(source_formal, dict) else None,
                    },
                    "certifyedge-protocol",
                ),
                _json_section_digest(
                    {
                        "input_trace_artifact": target_profile.get("input_trace_artifact"),
                        "output_certificate_artifact": target_profile.get("output_certificate_artifact"),
                        "valid_success_status": target_profile.get("valid_success_status"),
                        "valid_failure_status": target_profile.get("valid_failure_status"),
                        "certificate_predicate": target_formal.get("certificate_predicate") if isinstance(target_formal, dict) else None,
                    } if isinstance(target_profile, dict) else None,
                    "certifyedge-protocol",
                ),
            ),
        }
        rows.append(
            {
                "anchor_id": _anchor_id(
                    str(transition["repository"]), source, target,
                    "CERTIFYEDGE_PROPERTY_PROFILE", claim_id, profile_path,
                ),
                "transition_id": transition["transition_id"],
                "contract_locator": profile_path,
                "repository": transition["repository"],
                "source_sha": source,
                "target_sha": target,
                "family": "CERTIFYEDGE_PROPERTY_PROFILE",
                "claim_id": claim_id,
                "source_contract": source_contract,
                "target_contract": target_contract,
                "context_dimensions": dimensions,
                "materialization_status": "PENDING",
                "source_evidence_manifest_digest": None,
            }
        )
    return rows


def _pcs_workflow_contract(repo: Path, sha: str, profile_path: str) -> tuple[dict[str, Any], dict[str, Any] | str | None]:
    raw = _show(repo, sha, profile_path)
    parsed = _parse_json(raw)
    if raw is None:
        return _contract("ABSENT", []), None
    profile_obj = _object("workflow_profile", profile_path, raw)
    if parsed == MALFORMED:
        return _contract("MALFORMED", [profile_obj]), MALFORMED
    required = (
        "workflow_id",
        "runtime_artifacts",
        "certificate_artifacts",
        "required_registry_entries",
        "required_admission_profile",
        "status_policy",
    )
    if not _require_fields(parsed, required):
        return _contract("MALFORMED", [profile_obj]), MALFORMED

    objects = [profile_obj]
    workflow_schema = "schemas/WorkflowProfile.v0.schema.json"
    schema_raw = _show(repo, sha, workflow_schema)
    if schema_raw is not None:
        objects.append(_object("workflow_schema", workflow_schema, schema_raw))

    artifact_names: set[str] = set()
    for key in ("runtime_artifacts", "certificate_artifacts", "required_registry_entries"):
        for artifact in parsed.get(key, []):
            if isinstance(artifact, str):
                artifact_names.add(artifact)
    for artifact in sorted(artifact_names):
        schema_path = _schema_path_for_artifact(artifact)
        schema_raw = _show(repo, sha, schema_path)
        if schema_raw is not None:
            objects.append(_object(f"schema:{artifact}", schema_path, schema_raw))

    catalog_path = "catalog/pf_core.catalog.json"
    catalog_raw = _show(repo, sha, catalog_path)
    catalog = _parse_json(catalog_raw)
    if isinstance(catalog, dict):
        modes = catalog.get("workflow_certificate_modes", [])
        if any(
            isinstance(row, dict) and row.get("workflow_id") == parsed.get("workflow_id")
            for row in modes
        ):
            objects.append(_object("pf_core_catalog", catalog_path, catalog_raw))

    return _contract("PRESENT", objects), parsed


def _pcs_evaluator_paths(repo: Path, sha: str) -> tuple[list[str], list[str]]:
    evaluator = []
    for path in _list_paths(repo, sha, "python/pcs_core"):
        name = path.lower()
        if path.endswith(".py") and any(
            token in name
            for token in ("valid", "release", "registry", "profile", "conformance", "hash", "proof", "pf_core")
        ):
            evaluator.append(path)
    toolchain = [
        path
        for path in (
            "python/pyproject.toml",
            "python/requirements.txt",
            "rust-toolchain.toml",
            "VERSION",
        )
        if _show(repo, sha, path) is not None
    ]
    return sorted(set(evaluator)), toolchain


def _pcs_workflow_anchors(repo: Path, transition: dict[str, Any]) -> list[dict[str, Any]]:
    source = str(transition["source_sha"])
    target = str(transition["target_sha"])
    profile_paths = [
        p for p in _list_paths(repo, source, "examples/workflow_profiles")
        if p.endswith(".json")
    ]
    evaluator_source, toolchain_source = _pcs_evaluator_paths(repo, source)
    evaluator_target, toolchain_target = _pcs_evaluator_paths(repo, target)

    rows: list[dict[str, Any]] = []
    for profile_path in profile_paths:
        source_contract, source_profile = _pcs_workflow_contract(repo, source, profile_path)
        if source_contract["status"] != "PRESENT" or not isinstance(source_profile, dict):
            continue
        target_contract, target_profile = _pcs_workflow_contract(repo, target, profile_path)
        claim_id = f"pcs-workflow:{source_profile['workflow_id']}"
        dimensions = {
            "subject": _pair(PENDING_SUBJECT, PENDING_SUBJECT),
            "claim": _pair(
                _typed_digest("rtk-claim-id-v0", claim_id),
                _typed_digest("rtk-claim-id-v0", claim_id),
            ),
            "evaluator": _pair(
                _paths_digest(repo, source, evaluator_source, "pcs-evaluator"),
                _paths_digest(repo, target, evaluator_target, "pcs-evaluator"),
            ),
            "specification": _pair(
                _path_digest(repo, source, profile_path, "specification"),
                _path_digest(repo, target, profile_path, "specification"),
            ),
            "profile": _pair(
                _path_digest(repo, source, profile_path, "profile"),
                _path_digest(repo, target, profile_path, "profile"),
            ),
            "schema": _pair(
                _path_digest(repo, source, "schemas/WorkflowProfile.v0.schema.json", "schema"),
                _path_digest(repo, target, "schemas/WorkflowProfile.v0.schema.json", "schema"),
            ),
            "policy": _pair(
                _json_section_digest(
                    {
                        "required_admission_profile": source_profile.get("required_admission_profile"),
                        "status_policy": source_profile.get("status_policy"),
                        "formalization": source_profile.get("formalization"),
                    },
                    "pcs-workflow-policy",
                ),
                _json_section_digest(
                    {
                        "required_admission_profile": target_profile.get("required_admission_profile"),
                        "status_policy": target_profile.get("status_policy"),
                        "formalization": target_profile.get("formalization"),
                    } if isinstance(target_profile, dict) else None,
                    "pcs-workflow-policy",
                ),
            ),
            "dependencies": _pair(
                _paths_digest(repo, source, toolchain_source, "dependencies"),
                _paths_digest(repo, target, toolchain_target, "dependencies"),
            ),
            "artifact_registry": _pair(
                _path_digest(repo, source, "examples/artifact_registry.valid.json", "artifact-registry"),
                _path_digest(repo, target, "examples/artifact_registry.valid.json", "artifact-registry"),
            ),
            "toolchain": _pair(
                _paths_digest(repo, source, toolchain_source, "toolchain"),
                _paths_digest(repo, target, toolchain_target, "toolchain"),
            ),
            "protocol": _pair(
                _json_section_digest(
                    {
                        "runtime_artifacts": source_profile.get("runtime_artifacts"),
                        "certificate_artifacts": source_profile.get("certificate_artifacts"),
                        "handoff_sequence": source_profile.get("handoff_sequence"),
                    },
                    "pcs-workflow-protocol",
                ),
                _json_section_digest(
                    {
                        "runtime_artifacts": target_profile.get("runtime_artifacts"),
                        "certificate_artifacts": target_profile.get("certificate_artifacts"),
                        "handoff_sequence": target_profile.get("handoff_sequence"),
                    } if isinstance(target_profile, dict) else None,
                    "pcs-workflow-protocol",
                ),
            ),
        }
        rows.append(
            {
                "anchor_id": _anchor_id(
                    str(transition["repository"]), source, target,
                    "PCS_WORKFLOW_PROFILE", claim_id, profile_path,
                ),
                "transition_id": transition["transition_id"],
                "contract_locator": profile_path,
                "repository": transition["repository"],
                "source_sha": source,
                "target_sha": target,
                "family": "PCS_WORKFLOW_PROFILE",
                "claim_id": claim_id,
                "source_contract": source_contract,
                "target_contract": target_contract,
                "context_dimensions": dimensions,
                "materialization_status": "PENDING",
                "source_evidence_manifest_digest": None,
            }
        )
    return rows


def _pcs_verifier_profile_anchors(repo: Path, transition: dict[str, Any]) -> list[dict[str, Any]]:
    source = str(transition["source_sha"])
    target = str(transition["target_sha"])
    candidates = [
        p for p in _list_paths(repo, source, "examples/verifier_assurance")
        if p.endswith(".json")
    ]
    rows: list[dict[str, Any]] = []
    for profile_path in candidates:
        source_raw = _show(repo, source, profile_path)
        source_profile = _parse_json(source_raw)
        if not isinstance(source_profile, dict) or source_profile.get("artifact_type") != "VerifierProfile.v1":
            continue
        claim_surface = source_profile.get("claim_surface")
        if not isinstance(claim_surface, dict):
            continue
        claim_ids = sorted(
            set(
                str(x)
                for x in claim_surface.get("supported_claim_ids", [])
                if isinstance(x, str) and x
            )
        )
        if not claim_ids:
            continue

        target_raw = _show(repo, target, profile_path)
        target_profile = _parse_json(target_raw)
        source_objects = [_object("verifier_profile", profile_path, source_raw)]
        target_objects: list[dict[str, str]] = []
        status = "ABSENT" if target_raw is None else "MALFORMED"
        if target_raw is not None:
            target_objects.append(_object("verifier_profile", profile_path, target_raw))
            if isinstance(target_profile, dict) and target_profile.get("artifact_type") == "VerifierProfile.v1":
                status = "PRESENT"

        schema_path = "schemas/VerifierProfile.v1.schema.json"
        for sha, objects in ((source, source_objects), (target, target_objects)):
            raw = _show(repo, sha, schema_path)
            if raw is not None:
                objects.append(_object("verifier_profile_schema", schema_path, raw))

        source_contract = _contract("PRESENT", source_objects)
        target_contract = _contract(status, target_objects)

        for native_claim in claim_ids:
            claim_id = f"pcs-verifier-claim:{native_claim}"
            target_dict = target_profile if isinstance(target_profile, dict) else None
            dimensions = {
                "subject": _pair(PENDING_SUBJECT, PENDING_SUBJECT),
                "claim": _pair(
                    _typed_digest("rtk-claim-id-v0", claim_id),
                    _typed_digest("rtk-claim-id-v0", claim_id),
                ),
                "evaluator": _pair(
                    _json_section_digest(
                        {
                            "implementation": source_profile.get("implementation"),
                            "configuration": source_profile.get("configuration"),
                            "producer": source_profile.get("producer"),
                            "producer_version": source_profile.get("producer_version"),
                        },
                        "pcs-verifier-evaluator",
                    ),
                    _json_section_digest(
                        {
                            "implementation": target_dict.get("implementation"),
                            "configuration": target_dict.get("configuration"),
                            "producer": target_dict.get("producer"),
                            "producer_version": target_dict.get("producer_version"),
                        } if target_dict else None,
                        "pcs-verifier-evaluator",
                    ),
                ),
                "specification": _pair(
                    _json_section_digest(source_profile.get("claim_surface"), "pcs-verifier-claim-surface"),
                    _json_section_digest(target_dict.get("claim_surface") if target_dict else None, "pcs-verifier-claim-surface"),
                ),
                "profile": _pair(
                    _path_digest(repo, source, profile_path, "profile"),
                    _path_digest(repo, target, profile_path, "profile"),
                ),
                "schema": _pair(
                    _path_digest(repo, source, schema_path, "schema"),
                    _path_digest(repo, target, schema_path, "schema"),
                ),
                "policy": _pair(
                    _json_section_digest(
                        {
                            "applicability": source_profile.get("applicability"),
                            "assumptions": source_profile.get("assumptions"),
                            "known_blind_spots": source_profile.get("known_blind_spots"),
                        },
                        "pcs-verifier-policy",
                    ),
                    _json_section_digest(
                        {
                            "applicability": target_dict.get("applicability"),
                            "assumptions": target_dict.get("assumptions"),
                            "known_blind_spots": target_dict.get("known_blind_spots"),
                        } if target_dict else None,
                        "pcs-verifier-policy",
                    ),
                ),
                "dependencies": _pair(
                    _json_section_digest(source_profile.get("external_dependencies"), "pcs-verifier-dependencies"),
                    _json_section_digest(target_dict.get("external_dependencies") if target_dict else None, "pcs-verifier-dependencies"),
                ),
                "artifact_registry": _pair(f"{ABSENT}:artifact-registry", f"{ABSENT}:artifact-registry"),
                "toolchain": _pair(
                    _json_section_digest(source_profile.get("execution_controls"), "pcs-verifier-toolchain"),
                    _json_section_digest(target_dict.get("execution_controls") if target_dict else None, "pcs-verifier-toolchain"),
                ),
                "protocol": _pair(
                    _json_section_digest(
                        {
                            "mechanism": source_profile.get("mechanism"),
                            "decision_space": claim_surface.get("decision_space"),
                        },
                        "pcs-verifier-protocol",
                    ),
                    _json_section_digest(
                        {
                            "mechanism": target_dict.get("mechanism"),
                            "decision_space": (target_dict.get("claim_surface") or {}).get("decision_space") if isinstance(target_dict.get("claim_surface"), dict) else None,
                        } if target_dict else None,
                        "pcs-verifier-protocol",
                    ),
                ),
            }
            rows.append(
                {
                    "anchor_id": _anchor_id(
                        str(transition["repository"]), source, target,
                        "PCS_VERIFIER_PROFILE_V1", claim_id, profile_path,
                    ),
                    "transition_id": transition["transition_id"],
                    "contract_locator": profile_path,
                    "repository": transition["repository"],
                    "source_sha": source,
                    "target_sha": target,
                    "family": "PCS_VERIFIER_PROFILE_V1",
                    "claim_id": claim_id,
                    "source_contract": source_contract,
                    "target_contract": target_contract,
                    "context_dimensions": dimensions,
                    "materialization_status": "PENDING",
                    "source_evidence_manifest_digest": None,
                }
            )
    return rows


def _load_census(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("eligibility") != "ELIGIBLE":
            continue
        rows.append(row)
    return rows


def _parse_repo(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("--repo must use repository=local_path")
    name, raw_path = value.split("=", 1)
    if not name.strip() or not raw_path.strip():
        raise argparse.ArgumentTypeError(f"invalid repository specification: {value}")
    return name.strip(), Path(raw_path).resolve()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--census", type=Path, required=True)
    parser.add_argument("--repo", action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()

    repos = dict(_parse_repo(value) for value in args.repo)
    census = _load_census(args.census)
    anchors: list[dict[str, Any]] = []

    for transition in census:
        repository = str(transition["repository"])
        repo = repos.get(repository)
        if repo is None:
            raise SystemExit(f"missing --repo checkout for {repository}")
        if repository == "fraware/CertifyEdge":
            anchors.extend(_certifyedge_anchors(repo, transition))
        elif repository == "SentinelOps-CI/pcs-core":
            anchors.extend(_pcs_workflow_anchors(repo, transition))
            anchors.extend(_pcs_verifier_profile_anchors(repo, transition))
        else:
            raise SystemExit(f"unsupported frozen repository: {repository}")

    anchors.sort(
        key=lambda row: (
            str(row["repository"]),
            str(row["target_sha"]),
            str(row["family"]),
            str(row["claim_id"]),
            str(row["contract_locator"]),
            str(row["anchor_id"]),
        )
    )
    ids = [str(row["anchor_id"]) for row in anchors]
    if len(ids) != len(set(ids)):
        raise SystemExit("anchor_id collision detected")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="\n") as handle:
        for row in anchors:
            handle.write(_canonical_bytes(row).decode("utf-8") + "\n")

    payload = args.out.read_bytes()
    by_family: dict[str, int] = {}
    by_repo: dict[str, int] = {}
    for row in anchors:
        family = str(row["family"])
        repository = str(row["repository"])
        by_family[family] = by_family.get(family, 0) + 1
        by_repo[repository] = by_repo.get(repository, 0) + 1

    manifest = {
        "schema_version": "rtk.historical_anchor_manifest.v0",
        "anchor_count": len(anchors),
        "anchors_by_family": dict(sorted(by_family.items())),
        "anchors_by_repository": dict(sorted(by_repo.items())),
        "anchor_jsonl_sha256": _sha256(payload),
        "source_native_validators_executed": False,
        "target_native_validators_executed": False,
        "rtk_executed": False,
        "oracle_labels_consulted": False,
        "selection_rule": "all mechanically eligible native contract anchors at source revision",
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_bytes(_canonical_bytes(manifest) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
