#!/usr/bin/env python
"""Collect protected repository metadata for OVK.

Runs only as a protected-base collector. Signing credentials are refused in PR
jobs, backend workers, bench, and holdout eval. A single GitHub branch-protection
response is recorded as head/current state and is never duplicated as both
before and after unless the caller supplies a distinct base snapshot.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from ovk import __version__ as OVK_VERSION
from ovk.core.github_api_metadata import (
    config_from_environment,
    fetch_branch_protection,
    fetch_environments,
    protected_environment_names_from_api,
    required_checks_from_branch_protection,
)
from ovk.core.github_event import load_github_event_metadata
from ovk.core.metadata_provenance import (
    METADATA_SIGNING_KEY_ENV,
    METADATA_SIGNING_PRIVATE_KEY_ENV,
    OidcCollectorClaims,
    ProtectedMetadataArtifact,
    ProtectedSubject,
    collector_signing_forbidden,
    expected_artifact_payload_digest,
    sign_protected_artifact,
)

COLLECTOR_ID = "ovk.collect_branch_metadata"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect OVK protected repository metadata")
    parser.add_argument("--repository", default=None)
    parser.add_argument("--branch", default=None)
    parser.add_argument("--base-sha", default=None)
    parser.add_argument("--head-sha", default=None)
    parser.add_argument(
        "--kind",
        choices=("branch_protection", "protected_environment"),
        default="branch_protection",
    )
    parser.add_argument("--event", type=Path, default=None, help="GitHub event payload JSON")
    parser.add_argument("--output", type=Path, default=Path("ovk-required-checks.json"))
    return parser.parse_args()


def _branch_from_event(event_path: Path | None) -> str | None:
    if event_path is None:
        return None
    metadata = load_github_event_metadata(event_path)
    if metadata.base_sha:
        return None
    pull_request = json.loads(event_path.read_text(encoding="utf-8")).get("pull_request")
    if isinstance(pull_request, dict):
        base = pull_request.get("base", {})
        if isinstance(base, dict) and base.get("ref"):
            return str(base["ref"])
    return None


def _subject_from_args(args: argparse.Namespace, repository: str, branch: str) -> ProtectedSubject | None:
    head_sha = args.head_sha or os.environ.get("GITHUB_SHA")
    if args.event is not None:
        event_metadata = load_github_event_metadata(args.event)
        if not head_sha or head_sha == "unknown":
            head_sha = event_metadata.head_sha
        base_sha = args.base_sha or event_metadata.base_sha
        repository = repository or event_metadata.repository
    else:
        base_sha = args.base_sha
    if not repository or not branch or not head_sha:
        return None
    return ProtectedSubject(
        repository=repository,
        branch=branch,
        base_sha=base_sha,
        head_sha=str(head_sha),
    )


def _maybe_sign(artifact: ProtectedMetadataArtifact) -> ProtectedMetadataArtifact:
    if collector_signing_forbidden():
        return artifact
    private_key = os.environ.get(METADATA_SIGNING_PRIVATE_KEY_ENV)
    hmac_key = os.environ.get(METADATA_SIGNING_KEY_ENV)
    if not private_key and not hmac_key:
        return artifact
    try:
        return sign_protected_artifact(
            artifact,
            hmac_key=None if private_key else hmac_key,
            ed25519_private_key=private_key,
        )
    except Exception:
        return artifact


def _oidc_claims() -> OidcCollectorClaims | None:
    issuer = os.environ.get("OVK_OIDC_ISSUER") or "https://token.actions.githubusercontent.com"
    subject = os.environ.get("OVK_OIDC_SUBJECT")
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if not subject and workflow_ref:
        repository = os.environ.get("GITHUB_REPOSITORY", "")
        subject = f"repo:{repository}:ref:{os.environ.get('GITHUB_REF', '')}"
    if not subject:
        return None
    return OidcCollectorClaims(
        issuer=issuer,
        subject=subject,
        audience=os.environ.get("OVK_OIDC_AUDIENCE"),
        workflow_ref=workflow_ref,
        run_id=run_id,
    )


def main() -> int:
    args = parse_args()
    repository = args.repository
    branch = args.branch

    if args.event is not None:
        event_metadata = load_github_event_metadata(args.event)
        if repository is None and event_metadata.repository != "unknown/repo":
            repository = event_metadata.repository
        if branch is None:
            branch = _branch_from_event(args.event)

    config = config_from_environment(repository=repository, branch=branch)
    output_payload: dict[str, object] = {}

    if config is not None:
        subject = _subject_from_args(args, config.repository, config.branch)
        collected_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        oidc = _oidc_claims()
        if args.kind == "protected_environment":
            environments = fetch_environments(config)
            names = protected_environment_names_from_api(environments)
            if names and subject is not None:
                payload = {"protected_environments": names}
                artifact = ProtectedMetadataArtifact(
                    kind="protected_environment",
                    subject=subject,
                    payload=payload,
                    collector_id=COLLECTOR_ID,
                    collector_version=OVK_VERSION,
                    acquisition_method="oidc_github_actions" if oidc else "hmac_local",
                    collected_at=collected_at,
                    payload_digest=expected_artifact_payload_digest(payload, kind="protected_environment"),
                    source_endpoint=f"{config.api_base.rstrip('/')}/repos/{config.repository}/environments",
                    oidc=oidc,
                    extensions={"provenance_kind": "protected_base_workflow"},
                )
                output_payload = _maybe_sign(artifact).model_dump(mode="json")
        else:
            branch_protection = fetch_branch_protection(config)
            required_checks = required_checks_from_branch_protection(branch_protection)
            if required_checks is not None and subject is not None:
                # Current API snapshot is head/current state only. Do not invent a
                # matching before snapshot from the same response.
                payload = {
                    "before": {},
                    "after": {"required_checks": required_checks},
                    "head_state": {
                        "kind": "current_branch_protection",
                        "source": "github_branch_protection_api",
                    },
                }

                artifact = ProtectedMetadataArtifact(
                    kind="branch_protection",
                    subject=subject,
                    payload={"before": {}, "after": {"required_checks": required_checks}},
                    collector_id=COLLECTOR_ID,
                    collector_version=OVK_VERSION,
                    acquisition_method="oidc_github_actions" if oidc else "hmac_local",
                    collected_at=collected_at,
                    payload_digest=expected_artifact_payload_digest(
                        {"before": {}, "after": {"required_checks": required_checks}},
                        kind="branch_protection",
                    ),
                    source_endpoint=f"{config.api_base.rstrip('/')}/repos/{config.repository}/branches/{config.branch}/protection",
                    oidc=oidc,
                    extensions={
                        "provenance_kind": "protected_base_workflow",
                        "head_state": payload["head_state"],
                    },
                )
                output_payload = _maybe_sign(artifact).model_dump(mode="json")

    args.output.write_text(json.dumps(output_payload, indent=2) + "\n", encoding="utf-8")
    if output_payload:
        print("OVK protected metadata collected.")
    else:
        print("OVK branch metadata unavailable; wrote empty metadata.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
