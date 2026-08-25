#!/usr/bin/env python
"""Emit a GitHub check run from an OVK evidence bundle.

Fail-closed on stale head-SHA mismatch. Idempotent updates use a stable
``external_id`` (``ovk:{repo}:{head_sha}``): existing check runs with that
external_id are PATCHed; otherwise a new check run is created.
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from ovk.core.github_check import (
    StaleCheckRunError,
    build_check_run_payload,
    check_run_external_id,
)
from ovk.core.json_io import read_json_file
from ovk.core.models import EvidenceBundle


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Emit a GitHub check run for OVK results")
    parser.add_argument("--evidence", type=Path, default=Path("ovk-evidence.json"))
    parser.add_argument("--markdown", type=Path, default=Path("ovk-pr-comment.md"))
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--head-sha", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--api-base", default="https://api.github.com")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def _request(
    url: str,
    *,
    token: str,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any] | list[Any] | None]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read().decode("utf-8")
            parsed: dict[str, Any] | list[Any] | None = json.loads(raw) if raw else None
            return int(response.status), parsed
    except urllib.error.HTTPError as exc:
        return int(exc.code), None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return 0, None


def _find_check_run_id(
    api_base: str,
    repo: str,
    token: str,
    *,
    head_sha: str,
    external_id: str,
) -> int | None:
    """Return an existing check-run id for this external_id on the commit, if any."""
    encoded_sha = urllib.parse.quote(head_sha, safe="")
    url = (
        f"{api_base.rstrip('/')}/repos/{repo}/commits/{encoded_sha}/check-runs"
        f"?per_page=100"
    )
    status, payload = _request(url, token=token)
    if status < 200 or status >= 300 or not isinstance(payload, dict):
        return None
    check_runs = payload.get("check_runs")
    if not isinstance(check_runs, list):
        return None
    for item in check_runs:
        if not isinstance(item, dict):
            continue
        if str(item.get("external_id", "")) == external_id:
            check_id = item.get("id")
            if isinstance(check_id, int):
                return check_id
            if isinstance(check_id, str) and check_id.isdigit():
                return int(check_id)
    return None


def _post_check_run(api_base: str, repo: str, token: str, payload: dict[str, Any]) -> bool:
    url = f"{api_base.rstrip('/')}/repos/{repo}/check-runs"
    status, _ = _request(url, token=token, method="POST", payload=payload)
    return 200 <= status < 300


def _patch_check_run(
    api_base: str,
    repo: str,
    token: str,
    check_run_id: int,
    payload: dict[str, Any],
) -> bool:
    url = f"{api_base.rstrip('/')}/repos/{repo}/check-runs/{check_run_id}"
    # PATCH body must not include head_sha / name / external_id on update.
    update = {
        "status": payload.get("status", "completed"),
        "conclusion": payload.get("conclusion"),
        "output": payload.get("output"),
    }
    status, _ = _request(url, token=token, method="PATCH", payload=update)
    return 200 <= status < 300


def emit_or_update_check_run(
    api_base: str,
    repo: str,
    token: str,
    payload: dict[str, Any],
) -> bool:
    """Create or idempotently update a check run keyed by external_id."""
    head_sha = str(payload.get("head_sha", ""))
    external_id = str(payload.get("external_id", "") or "")
    if not external_id and head_sha:
        external_id = check_run_external_id(repo=repo, head_sha=head_sha)
        payload = {**payload, "external_id": external_id}
    if head_sha and external_id:
        existing_id = _find_check_run_id(
            api_base,
            repo,
            token,
            head_sha=head_sha,
            external_id=external_id,
        )
        if existing_id is not None:
            return _patch_check_run(api_base, repo, token, existing_id, payload)
    return _post_check_run(api_base, repo, token, payload)


def main() -> int:
    args = parse_args()
    if not args.evidence.exists():
        print(f"evidence bundle not found: {args.evidence}")
        return 0

    bundle = EvidenceBundle.model_validate(read_json_file(args.evidence))
    markdown_summary = args.markdown.read_text(encoding="utf-8") if args.markdown.exists() else None
    head_sha = args.head_sha or str(bundle.subject.get("head_sha", ""))
    if not head_sha:
        print("missing head SHA; skipping GitHub check emission")
        return 0

    try:
        payload = build_check_run_payload(
            bundle,
            head_sha=head_sha,
            markdown_summary=markdown_summary,
            validate_sha=True,
        )
    except StaleCheckRunError as exc:
        print(f"refusing stale/mismatched check-run emission: {exc}")
        return 1

    if args.dry_run:
        print(json.dumps(payload, indent=2))
        return 0

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token or not args.repo:
        print("missing GITHUB_TOKEN or repo; skipping GitHub check emission")
        return 0

    if emit_or_update_check_run(args.api_base, args.repo, token, payload):
        print(
            f"emitted GitHub check run with conclusion {payload['conclusion']} "
            f"external_id={payload.get('external_id')}"
        )
        return 0
    print("failed to emit GitHub check run")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
