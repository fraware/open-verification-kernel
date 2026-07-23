"""Keyless Sigstore (cosign) signing helpers for protected OVK releases.

Signs release artifacts with ``cosign sign-blob``, verifies with an exact
certificate identity + OIDC issuer, and runs a tamper test that must fail
verification. Intended for GitHub Actions with ``id-token: write``.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


DEFAULT_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
WORKFLOW_FILE = ".github/workflows/publish.yml"
REPO_SLUG = "fraware/open-verification-kernel"


@dataclass(frozen=True)
class SignedArtifact:
    """One artifact and its retained cosign bundle."""

    artifact: str
    bundle: str
    sha256: str


def github_certificate_identity(*, workflow_ref: str | None = None) -> str:
    """Return the Fulcio subject URI for a GitHub Actions workflow ref.

    ``workflow_ref`` is the Actions ``github.workflow_ref`` value, e.g.
    ``fraware/open-verification-kernel/.github/workflows/publish.yml@refs/tags/v1.2.0``.
    """
    ref = (workflow_ref or os.environ.get("GITHUB_WORKFLOW_REF") or "").strip()
    if not ref:
        raise ValueError("workflow_ref / GITHUB_WORKFLOW_REF is required")
    if not ref.startswith(f"{REPO_SLUG}/"):
        raise ValueError(f"refusing unexpected workflow_ref repository: {ref}")
    return f"https://github.com/{ref}"


def production_tag_identity(tag: str) -> str:
    """Exact identity consumers should pin for an immutable release tag."""
    normalized = tag if tag.startswith("refs/tags/") else f"refs/tags/{tag}"
    return f"https://github.com/{REPO_SLUG}/{WORKFLOW_FILE}@{normalized}"


def require_immutable_tag_ref(git_ref: str) -> None:
    """Refuse signing claims that are not bound to an immutable tag ref."""
    if not git_ref.startswith("refs/tags/"):
        raise ValueError(f"protected release signing requires an immutable tag ref, got {git_ref!r}")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _cosign_bin() -> str:
    path = shutil.which("cosign")
    if not path:
        raise RuntimeError("cosign is not available on PATH")
    return path


def discover_release_artifacts(dist_dir: Path, extra: Sequence[Path] | None = None) -> list[Path]:
    """Return wheel/sdist paths plus any explicit extras that exist."""
    artifacts: list[Path] = []
    if dist_dir.is_dir():
        for pattern in ("*.whl", "*.tar.gz"):
            artifacts.extend(sorted(dist_dir.glob(pattern)))
    for path in extra or ():
        resolved = path.resolve()
        if not resolved.is_file():
            raise FileNotFoundError(f"extra artifact missing: {resolved}")
        artifacts.append(resolved)
    if not artifacts:
        raise FileNotFoundError(f"no release artifacts found under {dist_dir}")
    return artifacts


def sign_blob(artifact: Path, bundle_path: Path) -> None:
    """Keyless ``cosign sign-blob`` for one file; retains the cosign bundle."""
    cosign = _cosign_bin()
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        [cosign, "sign-blob", "--yes", "--bundle", str(bundle_path), str(artifact)],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(f"cosign sign-blob failed for {artifact.name}: {detail}")
    if not bundle_path.is_file() or bundle_path.stat().st_size == 0:
        raise RuntimeError(f"cosign did not write bundle: {bundle_path}")


def verify_blob(
    artifact: Path,
    bundle_path: Path,
    *,
    certificate_identity: str,
    certificate_oidc_issuer: str,
) -> None:
    """Verify a blob against a retained bundle and exact identity policy."""
    cosign = _cosign_bin()
    if not certificate_identity or not certificate_oidc_issuer:
        raise ValueError("certificate_identity and certificate_oidc_issuer are required")
    completed = subprocess.run(
        [
            cosign,
            "verify-blob",
            "--bundle",
            str(bundle_path),
            "--certificate-identity",
            certificate_identity,
            "--certificate-oidc-issuer",
            certificate_oidc_issuer,
            str(artifact),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip()
        raise RuntimeError(f"cosign verify-blob failed for {artifact.name}: {detail}")


def tamper_test(
    artifact: Path,
    bundle_path: Path,
    *,
    certificate_identity: str,
    certificate_oidc_issuer: str,
) -> None:
    """Mutate a copy of the artifact and require verification to fail."""
    with tempfile.TemporaryDirectory(prefix="ovk-sigstore-tamper-") as tmp:
        tampered = Path(tmp) / f"{artifact.name}.tampered"
        shutil.copy2(artifact, tampered)
        with tampered.open("ab") as handle:
            handle.write(b"\nOVK-SIGSTORE-TAMPER\n")
        try:
            verify_blob(
                tampered,
                bundle_path,
                certificate_identity=certificate_identity,
                certificate_oidc_issuer=certificate_oidc_issuer,
            )
        except RuntimeError:
            return
        raise RuntimeError(
            f"tamper test failed open: mutated {artifact.name} still verified against {bundle_path.name}"
        )


def sign_and_verify_release(
    artifacts: Iterable[Path],
    *,
    bundles_dir: Path,
    certificate_identity: str,
    certificate_oidc_issuer: str = DEFAULT_OIDC_ISSUER,
    require_tag: bool = False,
    git_ref: str | None = None,
) -> list[SignedArtifact]:
    """Sign, same-workflow verify, and tamper-test each artifact."""
    if require_tag:
        require_immutable_tag_ref(git_ref or "")

    bundles_dir.mkdir(parents=True, exist_ok=True)
    signed: list[SignedArtifact] = []
    for artifact in artifacts:
        artifact = artifact.resolve()
        bundle_path = bundles_dir / f"{artifact.name}.cosign.bundle.json"
        sign_blob(artifact, bundle_path)
        verify_blob(
            artifact,
            bundle_path,
            certificate_identity=certificate_identity,
            certificate_oidc_issuer=certificate_oidc_issuer,
        )
        tamper_test(
            artifact,
            bundle_path,
            certificate_identity=certificate_identity,
            certificate_oidc_issuer=certificate_oidc_issuer,
        )
        signed.append(
            SignedArtifact(
                artifact=str(artifact),
                bundle=str(bundle_path),
                sha256=_sha256_file(artifact),
            )
        )
    return signed


def write_summary(
    path: Path,
    *,
    identity: str,
    issuer: str,
    signed: Sequence[SignedArtifact],
) -> dict[str, Any]:
    """Write a machine-readable signing summary for artifact retention."""
    payload = {
        "schema_version": "ovk.sigstore_release_summary.v1",
        "certificate_identity": identity,
        "certificate_oidc_issuer": issuer,
        "artifacts": [asdict(item) for item in signed],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload
