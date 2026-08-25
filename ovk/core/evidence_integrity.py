"""Evidence integrity envelope: digests, sealing, verification, path redaction.

Integrity helper fields live on ``ovk.evidence.v3`` (optional in the JSON schema;
required once an evidence record is sealed). The ``evidence_digest`` is a
canonical JSON SHA-256 over all fields except itself and optional ``signature``.
"""

from __future__ import annotations

import hmac
import re
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from ovk import __version__ as OVK_VERSION
from ovk.core.attestation_signing import SIGNATURE_ALG, sign_payload, signing_key_from_environment
from ovk.core.bundle import content_digest
from ovk.core.materials import compute_material_set_digest
from ovk.core.models import VerificationEvidence

SUPPORTED_EVIDENCE_SCHEMA_VERSIONS: frozenset[str] = frozenset(
    {
        "ovk.evidence.v1",
        "ovk.evidence.v2",
        "ovk.evidence.v3",
    }
)

# Fields excluded from the canonical digest payload.
DIGEST_EXCLUDED_FIELDS: frozenset[str] = frozenset({"evidence_digest", "signature"})

# Presence of any of these (except evidence_digest itself when checking partial writes)
# indicates an integrity envelope was started.
INTEGRITY_FIELD_NAMES: tuple[str, ...] = (
    "ovk_version",
    "checker_id",
    "checker_version",
    "input_digest",
    "relevant_file_digests",
    "configuration_digest",
    "policy_digest",
    "started_at",
    "completed_at",
    "assumptions",
    "unknowns",
    "stderr",
    "exit_status",
    "evidence_digest",
    "signature",
)

# Required once sealing begins or for sealed v3 evidence.
REQUIRED_INTEGRITY_FIELDS: tuple[str, ...] = (
    "ovk_version",
    "checker_id",
    "checker_version",
    "input_digest",
    "relevant_file_digests",
    "configuration_digest",
    "policy_digest",
    "started_at",
    "completed_at",
    "assumptions",
    "unknowns",
    "stderr",
    "exit_status",
    "evidence_digest",
)

_HOME_PREFIX = re.compile(
    r"^(?:"
    r"(?:/home|/Users)/[^/]+|"
    r"(?i:[a-z]:)\\Users\\[^\\]+|"
    r"~"
    r")"
)


def utc_now_iso() -> str:
    """Return a stable ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def redact_path(path: str) -> str:
    """Redact user/home prefixes from a filesystem path.

    Absolute home directories collapse to ``<home>/...`` so evidence can cite
    relative structure without leaking account names. Basename-only collapse is
    intentionally avoided except when no directory structure remains.
    """
    raw = str(path).strip()
    if not raw:
        return raw
    normalized = raw.replace("\\", "/")
    if normalized.startswith("//"):
        # UNC-style; keep host redacted.
        parts = [part for part in normalized.split("/") if part]
        if len(parts) >= 2:
            return "<unc>/" + "/".join(parts[1:])
        return "<unc>"
    match = _HOME_PREFIX.match(normalized)
    if match:
        rest = normalized[match.end() :].lstrip("/")
        return f"<home>/{rest}" if rest else "<home>"
    # Windows drive without Users
    drive = re.match(r"^(?i:[a-z]:)(/.*)?$", normalized)
    if drive:
        rest = (drive.group(1) or "").lstrip("/")
        return f"<drive>/{rest}" if rest else "<drive>"
    return normalized


def detect_path_redaction_collisions(paths: Sequence[str]) -> list[dict[str, Any]]:
    """Return collision groups where distinct paths share one redacted form."""
    groups: dict[str, list[str]] = {}
    for path in paths:
        redacted = redact_path(path)
        groups.setdefault(redacted, []).append(str(path))
    collisions: list[dict[str, Any]] = []
    for redacted, originals in sorted(groups.items()):
        unique = sorted(set(originals))
        if len(unique) > 1:
            collisions.append({"redacted": redacted, "paths": unique})
    return collisions


def _evidence_as_dict(evidence: VerificationEvidence | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(evidence, VerificationEvidence):
        return evidence.model_dump(mode="json")
    return dict(evidence)


def evidence_digest_payload(evidence: VerificationEvidence | Mapping[str, Any]) -> dict[str, Any]:
    """Return the canonical payload hashed into ``evidence_digest``."""
    payload = _evidence_as_dict(evidence)
    return {key: value for key, value in payload.items() if key not in DIGEST_EXCLUDED_FIELDS}


def compute_evidence_digest(evidence: VerificationEvidence | Mapping[str, Any]) -> str:
    """Compute the SHA-256 evidence digest over the canonical payload."""
    return content_digest(evidence_digest_payload(evidence))


def verify_evidence_digest(evidence: VerificationEvidence | Mapping[str, Any]) -> bool:
    """Return True when stated ``evidence_digest`` matches the recomputed digest."""
    payload = _evidence_as_dict(evidence)
    stated = payload.get("evidence_digest")
    if not isinstance(stated, str) or not stated:
        return False
    return hmac.compare_digest(stated, compute_evidence_digest(payload))


def sign_evidence(
    evidence: VerificationEvidence | Mapping[str, Any],
    *,
    key: bytes | None = None,
) -> dict[str, str] | None:
    """Optionally sign the digest payload (excludes evidence_digest and signature)."""
    selected = key if key is not None else signing_key_from_environment()
    if selected is None:
        return None
    return sign_payload(evidence_digest_payload(evidence), selected)


def verify_evidence_signature(
    evidence: VerificationEvidence | Mapping[str, Any],
    *,
    key: bytes | None = None,
) -> bool:
    """Verify optional signature when present; missing signature is allowed."""
    payload = _evidence_as_dict(evidence)
    signature = payload.get("signature")
    if signature is None:
        return True
    if not isinstance(signature, dict):
        return False
    selected = key if key is not None else signing_key_from_environment()
    if selected is None:
        return False
    expected = sign_payload(evidence_digest_payload(payload), selected)
    return (
        str(signature.get("algorithm", "")) == SIGNATURE_ALG
        and hmac.compare_digest(str(signature.get("digest", "")), expected["digest"])
    )


def recompute_input_digest(evidence: VerificationEvidence | Mapping[str, Any]) -> str:
    """Recompute the input digest bound into the integrity envelope."""
    payload = _evidence_as_dict(evidence)
    materials = payload.get("materials")
    if materials:
        return compute_material_set_digest(materials)
    return content_digest(
        {
            "subject": payload.get("subject"),
            "intent": payload.get("intent"),
            "change_origin": payload.get("change_origin") or {},
        }
    )


def integrity_fields_present(evidence: VerificationEvidence | Mapping[str, Any]) -> list[str]:
    """Return integrity field names that are explicitly set (not None)."""
    payload = _evidence_as_dict(evidence)
    present: list[str] = []
    for name in INTEGRITY_FIELD_NAMES:
        if name not in payload:
            continue
        value = payload[name]
        if value is None:
            continue
        present.append(name)
    return present


def integrity_envelope_complete(evidence: VerificationEvidence | Mapping[str, Any]) -> bool:
    """Return True when every required integrity field is present and non-empty where required."""
    payload = _evidence_as_dict(evidence)
    for name in REQUIRED_INTEGRITY_FIELDS:
        if name not in payload:
            return False
        value = payload[name]
        if name in {"stderr", "exit_status", "assumptions", "unknowns", "relevant_file_digests"}:
            # Explicit null / empty containers are allowed; key must exist.
            if value is None and name in {"stderr", "exit_status"}:
                continue
            if value is None:
                return False
            continue
        if value is None or value == "":
            return False
    return True


def missing_integrity_fields(evidence: VerificationEvidence | Mapping[str, Any]) -> list[str]:
    """Return required integrity fields that are missing or empty."""
    payload = _evidence_as_dict(evidence)
    missing: list[str] = []
    for name in REQUIRED_INTEGRITY_FIELDS:
        if name not in payload:
            missing.append(name)
            continue
        value = payload[name]
        if name in {"stderr", "exit_status"}:
            continue
        if name in {"assumptions", "unknowns", "relevant_file_digests"}:
            if value is None:
                missing.append(name)
            continue
        if value is None or value == "":
            missing.append(name)
    return missing


def _paths_from_materials(materials: list[Any] | None) -> list[str]:
    paths: list[str] = []
    for item in materials or []:
        if not isinstance(item, dict):
            continue
        for key in ("path", "uri", "source_path"):
            value = item.get(key)
            if isinstance(value, str) and value.strip():
                # Strip ovk-material: scheme for redaction of filesystem URIs.
                if value.startswith("ovk-material:"):
                    continue
                paths.append(value)
    return paths


def build_relevant_file_digests(
    materials: list[Any] | None,
    *,
    redact: bool = True,
) -> list[dict[str, str]]:
    """Build ``relevant_file_digests`` entries from materials, with optional path redaction."""
    entries: list[dict[str, str]] = []
    raw_paths: list[str] = []
    for item in materials or []:
        if not isinstance(item, dict):
            continue
        digest = str(item.get("sha256") or item.get("digest") or "")
        if not digest:
            continue
        path = str(item.get("path") or item.get("uri") or item.get("material_id") or "")
        raw_paths.append(path)
        display = redact_path(path) if redact and path else path
        entries.append({"path": display, "sha256": digest})
    entries.sort(key=lambda row: (row["path"], row["sha256"]))
    return entries


def collect_assumptions(evidence: VerificationEvidence | Mapping[str, Any]) -> list[str]:
    """Aggregate claim assumptions into a top-level list."""
    payload = _evidence_as_dict(evidence)
    collected: list[str] = []
    seen: set[str] = set()
    for claim in payload.get("backend_claims") or []:
        if not isinstance(claim, dict):
            continue
        for item in claim.get("assumptions") or []:
            text = str(item)
            if text not in seen:
                seen.add(text)
                collected.append(text)
    return collected


def collect_unknowns(evidence: VerificationEvidence | Mapping[str, Any]) -> list[str]:
    """Collect unknowns from coverage and non-pass claims."""
    payload = _evidence_as_dict(evidence)
    unknowns: list[str] = []
    seen: set[str] = set()
    coverage = payload.get("coverage") or {}
    if isinstance(coverage, dict):
        for item in coverage.get("unknowns") or []:
            text = str(item)
            if text not in seen:
                seen.add(text)
                unknowns.append(text)
        status = str(coverage.get("status") or "")
        if status in {"unknown", "partial"}:
            note = f"coverage status is {status}"
            if note not in seen:
                seen.add(note)
                unknowns.append(note)
    for claim in payload.get("backend_claims") or []:
        if not isinstance(claim, dict):
            continue
        status = str(claim.get("status") or "")
        if status in {"unknown", "error", "skipped"}:
            note = f"claim {claim.get('backend')}: {status}"
            if note not in seen:
                seen.add(note)
                unknowns.append(note)
    return unknowns


def _timestamps_from_attempts(attempts: list[Any] | None) -> tuple[str | None, str | None]:
    started: list[str] = []
    finished: list[str] = []
    for attempt in attempts or []:
        if not isinstance(attempt, dict):
            continue
        if attempt.get("started_at"):
            started.append(str(attempt["started_at"]))
        if attempt.get("finished_at"):
            finished.append(str(attempt["finished_at"]))
    return (min(started) if started else None, max(finished) if finished else None)


def _stderr_and_exit(attempts: list[Any] | None) -> tuple[str | None, int | None]:
    """Pick representative stderr digest / exit status from attempts."""
    stderr: str | None = None
    exit_status: int | None = None
    for attempt in attempts or []:
        if not isinstance(attempt, dict):
            continue
        if stderr is None and attempt.get("stderr_digest"):
            stderr = str(attempt["stderr_digest"])
        if exit_status is None and attempt.get("exit_code") is not None:
            exit_status = int(attempt["exit_code"])
    return stderr, exit_status


def resolve_checker_identity(
    evidence: VerificationEvidence | Mapping[str, Any],
    *,
    registry: Any | None = None,
) -> tuple[str, str | None]:
    """Resolve the versioned producer identity from backend or compiler evidence."""
    payload = _evidence_as_dict(evidence)
    claims = payload.get("backend_claims") or []
    primary = claims[0] if claims and isinstance(claims[0], dict) else {}
    primary_backend = str(primary.get("backend") or "")

    # ``backend=none`` is a synthetic conservative claim emitted only when no
    # backend produced a result. Do not invent a tool/adapter version for that
    # sentinel. The bound compiler is the versioned component that produced the
    # obligation and zero-result evidence projection, so use its exact identity.
    if primary_backend == "none" and not primary.get("adapter_version") and not primary.get("tool_version"):
        compiler = payload.get("compiler")
        if isinstance(compiler, dict):
            compiler_id = str(compiler.get("compiler_id") or "")
            compiler_version = str(compiler.get("compiler_version") or "")
            if compiler_id and compiler_version:
                return compiler_id, compiler_version

    checker_id = str(primary_backend or payload.get("checker_id") or "unknown")
    checker_version: str | None = None
    if registry is not None:
        manifest = None
        by_id = getattr(registry, "by_checker_id", None)
        by_tool = getattr(registry, "by_tool", None)
        if callable(by_id):
            manifest = by_id(checker_id)
        if manifest is None and callable(by_tool):
            manifest = by_tool(checker_id)
        if isinstance(manifest, dict):
            checker_id = str(manifest.get("checker_id") or checker_id)
            checker_version = (
                str(manifest.get("version") or "")
                or str((manifest.get("tool") or {}).get("adapter_version") or "")
                or None
            )
            if checker_version == "":
                checker_version = None
    if not checker_version:
        adapter = primary.get("adapter_version")
        tool = primary.get("tool_version")
        if adapter:
            checker_version = str(adapter)
        elif tool:
            checker_version = str(tool)
    existing = payload.get("checker_version")
    if not checker_version and existing:
        checker_version = str(existing)
    return checker_id, checker_version


def reconstruct_controlling_decision(
    evidence: VerificationEvidence | Mapping[str, Any],
) -> dict[str, Any]:
    """Reconstruct the controlling decision bound by the evidence digest.

    Returns decision_state, original_decision_state, controlling_finding_ids,
    and finding_contributions from the sealed decision object. Callers should
    verify ``evidence_digest`` before trusting this reconstruction.
    """
    payload = _evidence_as_dict(evidence)
    decision = payload.get("decision") or {}
    if not isinstance(decision, dict):
        decision = {}
    return {
        "decision_state": decision.get("decision_state"),
        "original_decision_state": decision.get("original_decision_state"),
        "controlling_finding_ids": list(decision.get("controlling_finding_ids") or []),
        "finding_contributions": list(decision.get("finding_contributions") or []),
        "merge_recommendation": decision.get("merge_recommendation"),
        "evidence_digest": payload.get("evidence_digest"),
        "digest_valid": verify_evidence_digest(payload),
    }


def finding_id_duplicates(evidence: VerificationEvidence | Mapping[str, Any]) -> list[str]:
    """Return finding IDs duplicated within controlling lists or contributions."""
    payload = _evidence_as_dict(evidence)
    decision = payload.get("decision") or {}
    if not isinstance(decision, dict):
        return []
    # An id listed once in controlling_finding_ids and once in finding_contributions is normal.
    # Duplicates mean the same id appears twice within either collection.
    controlling = [str(x) for x in (decision.get("controlling_finding_ids") or [])]
    contrib_ids = [
        str(item.get("finding_id"))
        for item in (decision.get("finding_contributions") or [])
        if isinstance(item, dict) and item.get("finding_id")
    ]
    dupes: set[str] = set()
    for collection in (controlling, contrib_ids):
        seen: set[str] = set()
        for item in collection:
            if item in seen:
                dupes.add(item)
            seen.add(item)
    return sorted(dupes)


def seal_evidence(
    evidence: VerificationEvidence,
    *,
    registry: Any | None = None,
    key: bytes | None = None,
    ovk_version: str | None = None,
    configuration_digest: str | None = None,
    policy_digest: str | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
    stderr: str | None = None,
    exit_status: int | None = None,
    relevant_file_digests: list[dict[str, str]] | None = None,
) -> VerificationEvidence:
    """Attach a complete integrity envelope and ``evidence_digest``.

    Raises ``ValueError`` when path redaction would collide or checker version
    cannot be resolved.
    """
    checker_id, checker_version = resolve_checker_identity(evidence, registry=registry)
    if not checker_version:
        raise ValueError("cannot seal evidence without checker_version (OVK-INV-023)")

    materials = evidence.materials
    file_digests = relevant_file_digests
    if file_digests is None:
        file_digests = build_relevant_file_digests(materials, redact=True)
    # Distinct originals that redact to the same form:
    material_paths = _paths_from_materials(materials)
    if material_paths:
        collisions = detect_path_redaction_collisions(material_paths)
        if collisions:
            raise ValueError(
                "path redaction collisions in relevant_file_digests (OVK-INV-030): "
                + "; ".join(f"{c['redacted']}<-{c['paths']}" for c in collisions)
            )
    # Two different digests claiming the same redacted path is also a collision.
    by_path: dict[str, set[str]] = {}
    for item in file_digests:
        by_path.setdefault(item["path"], set()).add(item["sha256"])
    ambiguous = {path: digests for path, digests in by_path.items() if len(digests) > 1}
    if ambiguous:
        raise ValueError(
            "path redaction collisions in relevant_file_digests (OVK-INV-030): "
            + "; ".join(f"{path}:{sorted(digests)}" for path, digests in sorted(ambiguous.items()))
        )

    attempt_start, attempt_end = _timestamps_from_attempts(evidence.execution_attempts)
    attempt_stderr, attempt_exit = _stderr_and_exit(evidence.execution_attempts)

    compiler = evidence.compiler or {}
    config_digest = configuration_digest or content_digest(
        {
            "compiler": compiler,
            "aggregation_policy": evidence.aggregation_policy,
            "coverage": evidence.coverage,
        }
    )
    pol_digest = policy_digest
    if pol_digest is None:
        # Prefer obligation policy digest from attempts / routing artifacts when present.
        for artifact in evidence.generated_artifacts:
            if artifact.get("kind") == "control_plane_trace" and artifact.get("policy_digest"):
                pol_digest = str(artifact["policy_digest"])
                break
        if pol_digest is None:
            pol_digest = content_digest({"intent": evidence.intent, "decision_policy": True})

    started = started_at or attempt_start or utc_now_iso()
    completed = completed_at or attempt_end or utc_now_iso()

    # Clear digest/signature before computing so payload is clean.
    provisional = evidence.model_copy(
        update={
            "ovk_version": ovk_version or OVK_VERSION,
            "checker_id": checker_id,
            "checker_version": checker_version,
            "input_digest": recompute_input_digest(evidence),
            "relevant_file_digests": file_digests,
            "configuration_digest": config_digest,
            "policy_digest": pol_digest,
            "started_at": started,
            "completed_at": completed,
            "assumptions": collect_assumptions(evidence),
            "unknowns": collect_unknowns(evidence),
            "stderr": stderr if stderr is not None else attempt_stderr,
            "exit_status": exit_status if exit_status is not None else attempt_exit,
            "evidence_digest": None,
            "signature": None,
        }
    )
    digest = compute_evidence_digest(provisional)
    signed = sign_evidence({**provisional.model_dump(mode="json"), "evidence_digest": digest}, key=key)
    return provisional.model_copy(
        update={
            "evidence_digest": digest,
            "signature": signed,
        }
    )


def is_supported_schema_version(schema_version: str) -> bool:
    """Return True when the evidence schema version is known to OVK."""
    return str(schema_version) in SUPPORTED_EVIDENCE_SCHEMA_VERSIONS
