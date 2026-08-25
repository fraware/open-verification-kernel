"""Typed and authenticated acquisition provenance for critical repository metadata.

Production collectors bind a ``ProtectedMetadataArtifact`` to an exact subject
and canonical payload, then sign those same canonical bytes. HMAC remains valid
for tests and local development. Consumer jobs verify with a public key or an
explicit test key and must not require a shared collector secret.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any, Literal

from pydantic import BaseModel, Field

from ovk.core.bundle import content_digest

PROVENANCE_SCHEMA_VERSION = "ovk.metadata_acquisition.v1"
ARTIFACT_SCHEMA_VERSION = "ovk.metadata.acquisition.v1"
SIGNATURE_ALGORITHM = "hmac-sha256"
ED25519_ALGORITHM = "ed25519"
OIDC_ATTESTATION_ALGORITHM = "oidc-attestation"
TRUSTED_PROVENANCE_KINDS: frozenset[str] = frozenset(
    {"protected_base_workflow", "signed_service", "maintainer_supplied"}
)
TRUSTED_OIDC_ISSUERS: frozenset[str] = frozenset({"https://token.actions.githubusercontent.com"})
HMAC_LOCAL_METHODS: frozenset[str] = frozenset({"protected_hmac_key", "hmac_local"})
PRODUCTION_METHODS: frozenset[str] = frozenset({"ed25519", "oidc_github_actions"})
METADATA_SIGNING_KEY_ENV = "OVK_METADATA_SIGNING_KEY"
METADATA_SIGNING_PRIVATE_KEY_ENV = "OVK_METADATA_SIGNING_PRIVATE_KEY"
METADATA_VERIFY_PUBKEY_ENV = "OVK_METADATA_VERIFY_PUBKEY"
PR_COLLECTOR_EVENTS = frozenset({"pull_request", "pull_request_target"})

PROTECTED_METADATA_FIELDS: frozenset[str] = frozenset(
    {
        "_ovk_acquisition",
        "_ovk_protected_artifact",
        "_ovk_provenance_conflicts",
        "before",
        "after",
        "before_required_checks",
        "after_required_checks",
        "before_branch_protection",
        "after_branch_protection",
        "repository",
        "branch",
        "base_sha",
        "head_sha",
        "source_endpoint",
        "payload_digest",
        "kind",
        "subject",
        "payload",
        "collector_id",
        "collector_version",
        "acquisition_method",
        "collected_at",
        "signature",
        "attestation_ref",
        "oidc",
        "schema_version",
    }
)

CALLER_CONTEXT_FIELDS: frozenset[str] = frozenset(
    {
        "actor_type",
        "author_type",
        "agent_id",
        "agent",
        "task",
        "changed_files",
        "ovk_gate_name",
        "before_workflow_permissions",
        "after_workflow_permissions",
        "github_repository",
        "github_head_sha",
        "github_base_sha",
        "github_pull_request_number",
    }
)


class AcquisitionSignature(BaseModel):
    algorithm: Literal["hmac-sha256", "ed25519", "oidc-attestation"] = SIGNATURE_ALGORITHM
    key_id: str
    digest: str
    public_key: str | None = None


class OidcCollectorClaims(BaseModel):
    issuer: str
    subject: str
    audience: str | None = None
    workflow_ref: str | None = None
    run_id: str | None = None


class ProtectedSubject(BaseModel):
    repository: str
    branch: str
    head_sha: str
    base_sha: str | None = None


class ProvenanceConflict(BaseModel):
    field: str
    reason: str


class MetadataAcquisitionRecord(BaseModel):
    """Digest-bound record describing how control-plane metadata was acquired."""

    schema_version: Literal["ovk.metadata_acquisition.v1"] = PROVENANCE_SCHEMA_VERSION
    collector_id: str
    collector_version: str
    source_type: Literal["branch_protection", "protected_environment"]
    repository: str
    branch: str
    base_sha: str | None = None
    head_sha: str | None = None
    collected_at: str
    payload_digest: str
    authentication_method: str
    provenance_kind: str
    source_endpoint: str | None = None
    signature: AcquisitionSignature | None = None
    attestation_ref: str | None = None
    oidc: OidcCollectorClaims | None = None
    extensions: dict[str, Any] = Field(default_factory=dict)


class ProtectedMetadataArtifact(BaseModel):
    """Canonical v1 protected metadata artifact.

    The signature covers the canonical unsigned artifact, including the already
    normalized payload and its digest. Verifiers recompute the same bytes.
    """

    schema_version: Literal["ovk.metadata.acquisition.v1"] = ARTIFACT_SCHEMA_VERSION
    kind: Literal["branch_protection", "protected_environment"]
    subject: ProtectedSubject
    payload: dict[str, Any]
    collector_id: str
    collector_version: str
    acquisition_method: str
    collected_at: str
    payload_digest: str
    source_endpoint: str | None = None
    signature: AcquisitionSignature | None = None
    attestation_ref: str | None = None
    oidc: OidcCollectorClaims | None = None
    extensions: dict[str, Any] = Field(default_factory=dict)

    def to_acquisition_record(self, *, provenance_kind: str = "protected_base_workflow") -> MetadataAcquisitionRecord:
        return MetadataAcquisitionRecord(
            collector_id=self.collector_id,
            collector_version=self.collector_version,
            source_type=self.kind,
            repository=self.subject.repository,
            branch=self.subject.branch,
            base_sha=self.subject.base_sha,
            head_sha=self.subject.head_sha,
            collected_at=self.collected_at,
            payload_digest=self.payload_digest,
            authentication_method=self.acquisition_method,
            provenance_kind=provenance_kind,
            source_endpoint=self.source_endpoint,
            signature=self.signature,
            attestation_ref=self.attestation_ref,
            oidc=self.oidc,
            extensions=dict(self.extensions),
        )


def branch_metadata_payload(data: dict[str, Any]) -> dict[str, Any]:
    before = data.get("before") if isinstance(data.get("before"), dict) else {}
    after = data.get("after") if isinstance(data.get("after"), dict) else {}
    return {"before": before, "after": after}


def expected_branch_metadata_digest(data: dict[str, Any]) -> str:
    return content_digest(branch_metadata_payload(data))


def canonical_protected_payload(payload: dict[str, Any], *, kind: str) -> dict[str, Any]:
    """Normalize once. This is the exact object whose digest is signed."""
    if kind == "protected_environment":
        names = payload.get("protected_environments")
        if not isinstance(names, list):
            names = payload.get("environments")
        normalized_names = [str(item) for item in names] if isinstance(names, list) else []
        return {"protected_environments": normalized_names}
    before = payload.get("before") if isinstance(payload.get("before"), dict) else {}
    after = payload.get("after") if isinstance(payload.get("after"), dict) else {}
    return {"before": before, "after": after}


def expected_artifact_payload_digest(payload: dict[str, Any], *, kind: str) -> str:
    return content_digest(canonical_protected_payload(payload, kind=kind))


def _unsigned_record_payload(record: MetadataAcquisitionRecord | dict[str, Any]) -> dict[str, Any]:
    payload = record.model_dump(mode="json") if isinstance(record, MetadataAcquisitionRecord) else dict(record)
    payload.pop("signature", None)
    return payload


def _unsigned_artifact_payload(artifact: ProtectedMetadataArtifact | dict[str, Any]) -> dict[str, Any]:
    payload = artifact.model_dump(mode="json") if isinstance(artifact, ProtectedMetadataArtifact) else dict(artifact)
    payload.pop("signature", None)
    return payload


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def collector_signing_forbidden(*, event_name: str | None = None) -> bool:
    """Signing credentials must never be used in PR jobs, workers, bench, or holdout."""
    event = event_name if event_name is not None else os.environ.get("GITHUB_EVENT_NAME", "")
    if event in PR_COLLECTOR_EVENTS:
        return True
    role = os.environ.get("OVK_COLLECTOR_CONTEXT", "").strip().lower()
    if role in {"pr", "backend_worker", "bench", "holdout"}:
        return True
    return False


def _hmac_digest(unsigned: dict[str, Any], key: str) -> str:
    return hmac.new(key.encode("utf-8"), _canonical_bytes(unsigned), hashlib.sha256).hexdigest()


def _parse_ed25519_private_key(raw: str) -> Any:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    text = raw.strip()
    if text.startswith("-----BEGIN"):
        return load_pem_private_key(text.encode("utf-8"), password=None)
    key_bytes = bytes.fromhex(text)
    return Ed25519PrivateKey.from_private_bytes(key_bytes)


def _parse_ed25519_public_key(raw: str) -> Any:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    text = raw.strip()
    if text.startswith("-----BEGIN"):
        return load_pem_public_key(text.encode("utf-8"))
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(text))


def _ed25519_sign(unsigned: dict[str, Any], private_key_raw: str) -> tuple[str, str]:
    key = _parse_ed25519_private_key(private_key_raw)
    signature = key.sign(_canonical_bytes(unsigned)).hex()
    public_bytes = key.public_key().public_bytes_raw()
    return signature, public_bytes.hex()


def _ed25519_verify(unsigned: dict[str, Any], signature_hex: str, public_key_raw: str) -> bool:
    try:
        key = _parse_ed25519_public_key(public_key_raw)
        key.verify(bytes.fromhex(signature_hex), _canonical_bytes(unsigned))
        return True
    except Exception:
        return False


def sign_acquisition_record(
    record: MetadataAcquisitionRecord | dict[str, Any],
    *,
    key: str,
    key_id: str = "ovk-metadata-v1",
) -> MetadataAcquisitionRecord:
    """Authenticate an acquisition record using a protected collector HMAC key.

    HMAC is the local/test algorithm. Production collectors should prefer
    ``sign_protected_artifact`` with Ed25519.
    """
    if not key:
        raise ValueError("metadata signing key must be non-empty")

    normalized = MetadataAcquisitionRecord.model_validate(
        {**_unsigned_record_payload(record), "signature": None}
    )
    unsigned = _unsigned_record_payload(normalized)
    digest = _hmac_digest(unsigned, key)
    unsigned["signature"] = {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "digest": digest,
    }
    return MetadataAcquisitionRecord.model_validate(unsigned)


def sign_protected_artifact(
    artifact: ProtectedMetadataArtifact | dict[str, Any],
    *,
    hmac_key: str | None = None,
    ed25519_private_key: str | None = None,
    key_id: str = "ovk-metadata-v1",
) -> ProtectedMetadataArtifact:
    """Sign a protected artifact after normalizing payload and digest."""
    raw = artifact.model_dump(mode="json") if isinstance(artifact, ProtectedMetadataArtifact) else dict(artifact)
    kind = str(raw.get("kind") or "branch_protection")
    payload = canonical_protected_payload(raw.get("payload") if isinstance(raw.get("payload"), dict) else {}, kind=kind)
    raw["payload"] = payload
    raw["payload_digest"] = content_digest(payload)
    raw.pop("signature", None)
    normalized = ProtectedMetadataArtifact.model_validate(raw)
    unsigned = _unsigned_artifact_payload(normalized)

    if ed25519_private_key:
        digest, public_key = _ed25519_sign(unsigned, ed25519_private_key)
        unsigned["signature"] = {
            "algorithm": ED25519_ALGORITHM,
            "key_id": key_id,
            "digest": digest,
            "public_key": public_key,
        }
        unsigned["acquisition_method"] = "ed25519"
    elif hmac_key:
        unsigned["signature"] = {
            "algorithm": SIGNATURE_ALGORITHM,
            "key_id": key_id,
            "digest": _hmac_digest(unsigned, hmac_key),
        }
        if unsigned.get("acquisition_method") not in HMAC_LOCAL_METHODS:
            unsigned["acquisition_method"] = "hmac_local"
    else:
        raise ValueError("protected metadata signing requires an Ed25519 private key or local HMAC key")
    return ProtectedMetadataArtifact.model_validate(unsigned)


def verify_acquisition_signature(
    record: MetadataAcquisitionRecord,
    *,
    key: str | None,
    public_key: str | None = None,
) -> bool:
    if record.signature is None:
        return False
    unsigned = _unsigned_record_payload(record)
    algorithm = record.signature.algorithm
    if algorithm == SIGNATURE_ALGORITHM:
        if not key:
            return False
        expected = _hmac_digest(unsigned, key)
        return hmac.compare_digest(expected, record.signature.digest)
    if algorithm == ED25519_ALGORITHM:
        verify_key = public_key or record.signature.public_key or os.environ.get(METADATA_VERIFY_PUBKEY_ENV)
        if not verify_key:
            return False
        return _ed25519_verify(unsigned, record.signature.digest, verify_key)
    if algorithm == OIDC_ATTESTATION_ALGORITHM:
        return False
    return False


def verify_artifact_signature(
    artifact: ProtectedMetadataArtifact,
    *,
    hmac_key: str | None = None,
    public_key: str | None = None,
) -> bool:
    if artifact.signature is None:
        return False
    unsigned = _unsigned_artifact_payload(artifact)
    algorithm = artifact.signature.algorithm
    if algorithm == SIGNATURE_ALGORITHM:
        if not hmac_key:
            return False
        expected = _hmac_digest(unsigned, hmac_key)
        return hmac.compare_digest(expected, artifact.signature.digest)
    if algorithm == ED25519_ALGORITHM:
        verify_key = public_key or artifact.signature.public_key or os.environ.get(METADATA_VERIFY_PUBKEY_ENV)
        if not verify_key:
            return False
        return _ed25519_verify(unsigned, artifact.signature.digest, verify_key)
    return False


def parse_acquisition_record(data: dict[str, Any]) -> MetadataAcquisitionRecord | None:
    artifact = parse_protected_artifact(data)
    if artifact is not None:
        return artifact.to_acquisition_record(
            provenance_kind=str((artifact.extensions or {}).get("provenance_kind") or "protected_base_workflow")
        )
    raw = data.get("_ovk_acquisition")
    if not isinstance(raw, dict):
        return None
    try:
        return MetadataAcquisitionRecord.model_validate(raw)
    except Exception:
        return None


def parse_protected_artifact(data: dict[str, Any]) -> ProtectedMetadataArtifact | None:
    raw = data.get("_ovk_protected_artifact")
    if not isinstance(raw, dict):
        if data.get("schema_version") == ARTIFACT_SCHEMA_VERSION and isinstance(data.get("subject"), dict):
            raw = data
        else:
            return None
    try:
        artifact = ProtectedMetadataArtifact.model_validate(raw)
    except Exception:
        return None
    return artifact


def _oidc_claims_trusted(claims: OidcCollectorClaims | None) -> bool:
    if claims is None:
        return False
    if claims.issuer not in TRUSTED_OIDC_ISSUERS:
        return False
    if not claims.subject.strip():
        return False
    return True


def acquisition_is_trusted(
    data: dict[str, Any],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None,
    verification_key: str | None,
    allowed_provenance_kinds: set[str] | frozenset[str] | None = None,
    public_key: str | None = None,
) -> tuple[bool, list[str], MetadataAcquisitionRecord | None]:
    """Validate provenance, content binding and authentication against material."""
    if data.get("_ovk_provenance_conflicts"):
        conflicts = data.get("_ovk_provenance_conflicts")
        detail = conflicts if isinstance(conflicts, list) else ["protected metadata conflict"]
        return False, [f"protected metadata conflict: {detail}"], parse_acquisition_record(data)

    record = parse_acquisition_record(data)
    reasons: list[str] = []
    if record is None:
        return False, ["typed metadata acquisition record missing or invalid"], None

    allowed = frozenset(allowed_provenance_kinds or TRUSTED_PROVENANCE_KINDS)
    if record.provenance_kind not in TRUSTED_PROVENANCE_KINDS:
        reasons.append(f"untrusted provenance kind: {record.provenance_kind}")
    if record.provenance_kind not in allowed:
        reasons.append(f"provenance kind not allowed by policy: {record.provenance_kind}")
    if record.repository != repo:
        reasons.append(f"repository mismatch: {record.repository} != {repo}")
    if record.head_sha and record.head_sha != head_sha:
        reasons.append(f"head revision mismatch: {record.head_sha} != {head_sha}")
    if base_sha is not None and record.base_sha != base_sha:
        reasons.append(f"base revision mismatch: {record.base_sha} != {base_sha}")

    artifact = parse_protected_artifact(data)
    if artifact is not None:
        expected_digest = expected_artifact_payload_digest(artifact.payload, kind=artifact.kind)
        if artifact.payload_digest != expected_digest or record.payload_digest != expected_digest:
            reasons.append("metadata payload digest mismatch")
        if artifact.kind == "branch_protection" and record.payload_digest != expected_branch_metadata_digest(data):
            reasons.append("flattened branch-protection payload digest mismatch")
        if artifact.kind == "protected_environment":
            observed = canonical_protected_payload(data, kind="protected_environment")
            if observed != canonical_protected_payload(artifact.payload, kind="protected_environment"):
                reasons.append("protected-environment payload does not match signed artifact")
        if artifact.subject.repository != repo or artifact.subject.head_sha != head_sha:
            reasons.append("protected artifact subject mismatch")
        if base_sha is not None and artifact.subject.base_sha != base_sha:
            reasons.append("protected artifact base revision mismatch")
    elif record.payload_digest != expected_branch_metadata_digest(data):
        reasons.append("metadata payload digest mismatch")

    if not record.collector_id.strip() or not record.collector_version.strip():
        reasons.append("collector identity incomplete")
    if not record.authentication_method.strip():
        reasons.append("authentication method missing")

    method = record.authentication_method
    signature_ok = False
    if method in HMAC_LOCAL_METHODS or (record.signature and record.signature.algorithm == SIGNATURE_ALGORITHM):
        signature_ok = verify_acquisition_signature(record, key=verification_key, public_key=public_key)
        if artifact is not None and not signature_ok:
            signature_ok = verify_artifact_signature(artifact, hmac_key=verification_key, public_key=public_key)
    elif method == "ed25519" or (record.signature and record.signature.algorithm == ED25519_ALGORITHM):
        signature_ok = verify_acquisition_signature(record, key=None, public_key=public_key)
        if artifact is not None and not signature_ok:
            signature_ok = verify_artifact_signature(artifact, public_key=public_key)
    elif method == "oidc_github_actions":
        if not _oidc_claims_trusted(record.oidc):
            reasons.append("OIDC collector identity missing or untrusted")
        signature_ok = verify_acquisition_signature(record, key=verification_key, public_key=public_key)
        if not signature_ok and artifact is not None:
            signature_ok = verify_artifact_signature(
                artifact, hmac_key=verification_key, public_key=public_key
            )
        if not signature_ok:
            reasons.append("OIDC-attested collector still requires a verifiable artifact signature")
    else:
        reasons.append(f"unsupported authentication method: {method}")

    if not signature_ok and "OIDC-attested collector still requires a verifiable artifact signature" not in reasons:
        reasons.append("metadata acquisition signature missing or invalid")

    return not reasons, reasons, record


def allowed_provenance_kinds_from_policy(policy: dict[str, Any] | None) -> frozenset[str]:
    """Read an allowlist only; no policy field can directly assert trust."""
    if not isinstance(policy, dict):
        return TRUSTED_PROVENANCE_KINDS
    trust = policy.get("trust")
    if not isinstance(trust, dict):
        return TRUSTED_PROVENANCE_KINDS
    raw = trust.get("allowed_metadata_provenance_kinds")
    if raw is None:
        return TRUSTED_PROVENANCE_KINDS
    if not isinstance(raw, list):
        return frozenset()
    return frozenset(str(item) for item in raw if str(item) in TRUSTED_PROVENANCE_KINDS)


def _values_conflict(left: Any, right: Any) -> bool:
    if left is None or right is None:
        return False
    return left != right


def merge_loaded_protected_metadata(
    caller: dict[str, Any],
    loaded: dict[str, Any],
) -> tuple[dict[str, Any], list[ProvenanceConflict]]:
    """Loaded artifact owns protected fields. Caller may add non-protected context only.

    Conflicting protected, subject, or acquisition fields become typed conflicts.
    Caller ``_ovk_acquisition`` is never restored over a loaded artifact.
    """
    conflicts: list[ProvenanceConflict] = []
    merged = dict(loaded)

    for key, value in caller.items():
        if key in PROTECTED_METADATA_FIELDS:
            loaded_value = loaded.get(key)
            if key in loaded and _values_conflict(loaded_value, value):
                conflicts.append(
                    ProvenanceConflict(
                        field=key,
                        reason="caller attempted to override loaded protected metadata",
                    )
                )
            continue
        if key not in merged:
            merged[key] = value

    if "_ovk_acquisition" in caller and "_ovk_acquisition" not in loaded:
        conflicts.append(
            ProvenanceConflict(
                field="_ovk_acquisition",
                reason="caller-forged acquisition cannot become authoritative",
            )
        )

    subject_pairs = (
        ("github_repository", "repository"),
        ("github_head_sha", "head_sha"),
        ("github_base_sha", "base_sha"),
    )
    for caller_key, loaded_key in subject_pairs:
        if caller_key in caller and loaded_key in loaded and _values_conflict(caller.get(caller_key), loaded.get(loaded_key)):
            conflicts.append(
                ProvenanceConflict(
                    field=caller_key,
                    reason="caller subject does not match loaded protected subject",
                )
            )

    if conflicts:
        merged["_ovk_provenance_conflicts"] = [item.model_dump(mode="json") for item in conflicts]
    return merged, conflicts


def flatten_protected_artifact_for_loader(data: dict[str, Any]) -> dict[str, Any]:
    """Project a protected artifact into the compiler/loader dictionary shape."""
    artifact = parse_protected_artifact(data)
    if artifact is None:
        return dict(data)
    flattened = dict(data)
    payload = canonical_protected_payload(artifact.payload, kind=artifact.kind)
    if artifact.kind == "branch_protection":
        flattened["before"] = payload.get("before") or {}
        flattened["after"] = payload.get("after") or {}
        before_checks = flattened["before"].get("required_checks")
        after_checks = flattened["after"].get("required_checks")
        if isinstance(before_checks, list):
            flattened["before_required_checks"] = [str(item) for item in before_checks]
        if isinstance(after_checks, list):
            flattened["after_required_checks"] = [str(item) for item in after_checks]
    elif artifact.kind == "protected_environment":
        flattened["protected_environments"] = payload.get("protected_environments") or []
    flattened["_ovk_protected_artifact"] = artifact.model_dump(mode="json")
    provenance_kind = str((artifact.extensions or {}).get("provenance_kind") or "protected_base_workflow")
    flattened["_ovk_acquisition"] = artifact.to_acquisition_record(provenance_kind=provenance_kind).model_dump(
        mode="json"
    )
    flattened["repository"] = artifact.subject.repository
    flattened["branch"] = artifact.subject.branch
    flattened["base_sha"] = artifact.subject.base_sha
    flattened["head_sha"] = artifact.subject.head_sha
    return flattened


def trusted_protected_environment_names(
    data: dict[str, Any],
    *,
    repo: str,
    head_sha: str,
    base_sha: str | None,
    verification_key: str | None,
    public_key: str | None = None,
) -> frozenset[str]:
    """Return protected-environment names only from a trusted acquisition artifact."""
    trusted, _reasons, record = acquisition_is_trusted(
        data,
        repo=repo,
        head_sha=head_sha,
        base_sha=base_sha,
        verification_key=verification_key,
        public_key=public_key,
    )
    if not trusted or record is None or record.source_type != "protected_environment":
        return frozenset()
    artifact = parse_protected_artifact(data)
    payload = artifact.payload if artifact is not None else data
    names = canonical_protected_payload(payload, kind="protected_environment").get("protected_environments") or []
    return frozenset(str(item) for item in names)
